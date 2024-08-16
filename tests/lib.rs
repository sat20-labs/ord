#![allow(clippy::type_complexity)]

use {
  self::{command_builder::CommandBuilder, expected::Expected, test_server::TestServer},
  bitcoin::{
    address::{Address, NetworkUnchecked},
    blockdata::constants::COIN_VALUE,
    Network, OutPoint, Sequence, Txid, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::ListDescriptorsResult,
  chrono::{DateTime, Utc},
  executable_path::executable_path,
  mockcore::TransactionTemplate,
  ord::{
    api, chain::Chain, decimal::Decimal, outgoing::Outgoing, subcommand::runes::RuneInfo,
    InscriptionId, RuneEntry,
  },
  ordinals::{
    Artifact, Charm, Edict, Pile, Rarity, Rune, RuneId, Runestone, Sat, SatPoint, SpacedRune,
  },
  pretty_assertions::assert_eq as pretty_assert_eq,
  regex::Regex,
  reqwest::{StatusCode, Url},
  serde::de::DeserializeOwned,
  std::sync::Arc,
  std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::{self, FromStr},
    thread,
    time::Duration,
  },
  tempfile::TempDir,
};

macro_rules! assert_regex_match {
  ($value:expr, $pattern:expr $(,)?) => {
    let regex = Regex::new(&format!("^(?s){}$", $pattern)).unwrap();
    let string = $value.to_string();

    if !regex.is_match(string.as_ref()) {
      eprintln!("Regex did not match:");
      pretty_assert_eq!(regex.as_str(), string);
    }
  };
}

mod command_builder;
mod expected;
mod test_server;

mod balances;
mod decode;
mod epochs;
mod find;
mod index;
mod info;
mod json_api;
mod list;
mod parse;
mod runes;
mod server;
mod settings;
mod subsidy;
mod supply;
mod traits;
mod version;

const RUNE: u128 = 99246114928149462;

type Supply = ord::subcommand::supply::Output;

fn create_wallet(core: &mockcore::Handle, ord: &TestServer) {
  CommandBuilder::new(format!("--chain {} wallet create", core.network()))
    .core(core)
    .ord(ord)
    .stdout_regex(".*")
    .run_and_extract_stdout();
}

fn envelope(payload: &[&[u8]]) -> Witness {
  let mut builder = bitcoin::script::Builder::new()
    .push_opcode(bitcoin::opcodes::OP_FALSE)
    .push_opcode(bitcoin::opcodes::all::OP_IF);

  for data in payload {
    let mut buf = bitcoin::script::PushBytesBuf::new();
    buf.extend_from_slice(data).unwrap();
    builder = builder.push_slice(buf);
  }

  let script = builder
    .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
    .into_script();

  Witness::from_slice(&[script.into_bytes(), Vec::new()])
}

fn default<T: Default>() -> T {
  Default::default()
}
