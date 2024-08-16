use {
  super::*,
  anyhow::ensure,
  brotli::enc::{writer::CompressorWriter, BrotliEncoderParams},
  http::header::HeaderValue,
  io::Write,
  std::str,
};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Eq, Default)]
pub struct Inscription {
  pub body: Option<Vec<u8>>,
  pub content_encoding: Option<Vec<u8>>,
  pub content_type: Option<Vec<u8>>,
  pub delegate: Option<Vec<u8>>,
  pub duplicate_field: bool,
  pub incomplete_field: bool,
  pub metadata: Option<Vec<u8>>,
  pub metaprotocol: Option<Vec<u8>>,
  pub parents: Vec<Vec<u8>>,
  pub pointer: Option<Vec<u8>>,
  pub rune: Option<Vec<u8>>,
  pub unrecognized_even_field: bool,
}

impl Inscription {
  pub fn new(
    chain: Chain,
    compress: bool,
    delegate: Option<InscriptionId>,
    metadata: Option<Vec<u8>>,
    metaprotocol: Option<String>,
    parents: Vec<InscriptionId>,
    path: Option<PathBuf>,
    pointer: Option<u64>,
    rune: Option<Rune>,
  ) -> Result<Self, Error> {
    let path = path.as_ref();

    let (body, content_type, content_encoding) = if let Some(path) = path {
      let body = fs::read(path).with_context(|| format!("io error reading {}", path.display()))?;

      let content_type = Media::content_type_for_path(path)?.0;

      let (body, content_encoding) = if compress {
        let compression_mode = Media::content_type_for_path(path)?.1;
        let mut compressed = Vec::new();

        {
          CompressorWriter::with_params(
            &mut compressed,
            body.len(),
            &BrotliEncoderParams {
              lgblock: 24,
              lgwin: 24,
              mode: compression_mode,
              quality: 11,
              size_hint: body.len(),
              ..default()
            },
          )
          .write_all(&body)?;

          let mut decompressor = brotli::Decompressor::new(compressed.as_slice(), compressed.len());

          let mut decompressed = Vec::new();

          decompressor.read_to_end(&mut decompressed)?;

          ensure!(decompressed == body, "decompression roundtrip failed");
        }

        if compressed.len() < body.len() {
          (compressed, Some("br".as_bytes().to_vec()))
        } else {
          (body, None)
        }
      } else {
        (body, None)
      };

      if let Some(limit) = chain.inscription_content_size_limit() {
        let len = body.len();
        if len > limit {
          bail!("content size of {len} bytes exceeds {limit} byte limit for {chain} inscriptions");
        }
      }

      (Some(body), Some(content_type), content_encoding)
    } else {
      (None, None, None)
    };

    Ok(Self {
      body,
      content_encoding,
      content_type: content_type.map(|content_type| content_type.into()),
      delegate: delegate.map(|delegate| delegate.value()),
      metadata,
      metaprotocol: metaprotocol.map(|metaprotocol| metaprotocol.into_bytes()),
      parents: parents.iter().map(|parent| parent.value()).collect(),
      pointer: pointer.map(Self::pointer_value),
      rune: rune.map(|rune| rune.commitment()),
      ..default()
    })
  }

  pub fn pointer_value(pointer: u64) -> Vec<u8> {
    let mut bytes = pointer.to_le_bytes().to_vec();

    while bytes.last().copied() == Some(0) {
      bytes.pop();
    }

    bytes
  }

  fn inscription_id_field(field: Option<&[u8]>) -> Option<InscriptionId> {
    let value = field.as_ref()?;

    if value.len() < Txid::LEN {
      return None;
    }

    if value.len() > Txid::LEN + 4 {
      return None;
    }

    let (txid, index) = value.split_at(Txid::LEN);

    if let Some(last) = index.last() {
      // Accept fixed length encoding with 4 bytes (with potential trailing zeroes)
      // or variable length (no trailing zeroes)
      if index.len() != 4 && *last == 0 {
        return None;
      }
    }

    let txid = Txid::from_slice(txid).unwrap();

    let index = [
      index.first().copied().unwrap_or(0),
      index.get(1).copied().unwrap_or(0),
      index.get(2).copied().unwrap_or(0),
      index.get(3).copied().unwrap_or(0),
    ];

    let index = u32::from_le_bytes(index);

    Some(InscriptionId { txid, index })
  }

  pub fn media(&self) -> Media {
    if self.body.is_none() {
      return Media::Unknown;
    }

    let Some(content_type) = self.content_type() else {
      return Media::Unknown;
    };

    content_type.parse().unwrap_or(Media::Unknown)
  }

  pub fn body(&self) -> Option<&[u8]> {
    Some(self.body.as_ref()?)
  }

  pub fn into_body(self) -> Option<Vec<u8>> {
    self.body
  }

  pub fn content_length(&self) -> Option<usize> {
    Some(self.body()?.len())
  }

  pub fn content_type(&self) -> Option<&str> {
    str::from_utf8(self.content_type.as_ref()?).ok()
  }

  pub fn content_encoding(&self) -> Option<HeaderValue> {
    HeaderValue::from_str(str::from_utf8(self.content_encoding.as_ref()?).unwrap_or_default()).ok()
  }

  pub fn delegate(&self) -> Option<InscriptionId> {
    Self::inscription_id_field(self.delegate.as_deref())
  }

  pub fn metadata(&self) -> Option<Value> {
    ciborium::from_reader(Cursor::new(self.metadata.as_ref()?)).ok()
  }

  pub fn metaprotocol(&self) -> Option<&str> {
    str::from_utf8(self.metaprotocol.as_ref()?).ok()
  }

  pub fn parents(&self) -> Vec<InscriptionId> {
    self
      .parents
      .iter()
      .filter_map(|parent| Self::inscription_id_field(Some(parent)))
      .collect()
  }

  pub fn pointer(&self) -> Option<u64> {
    let value = self.pointer.as_ref()?;

    if value.iter().skip(8).copied().any(|byte| byte != 0) {
      return None;
    }

    let pointer = [
      value.first().copied().unwrap_or(0),
      value.get(1).copied().unwrap_or(0),
      value.get(2).copied().unwrap_or(0),
      value.get(3).copied().unwrap_or(0),
      value.get(4).copied().unwrap_or(0),
      value.get(5).copied().unwrap_or(0),
      value.get(6).copied().unwrap_or(0),
      value.get(7).copied().unwrap_or(0),
    ];

    Some(u64::from_le_bytes(pointer))
  }

  pub fn hidden(&self) -> bool {
    use regex::bytes::Regex;

    const BVM_NETWORK: &[u8] = b"<body style=\"background:#F61;color:#fff;\">\
                        <h1 style=\"height:100%\">bvm.network</h1></body>";

    lazy_static! {
      static ref BRC_420: Regex = Regex::new(r"^\s*/content/[[:xdigit:]]{64}i\d+\s*$").unwrap();
    }

    self
      .body()
      .map(|body| BRC_420.is_match(body) || body.starts_with(BVM_NETWORK))
      .unwrap_or_default()
      || self.metaprotocol.is_some()
      || matches!(self.media(), Media::Code(_) | Media::Text | Media::Unknown)
  }
}
