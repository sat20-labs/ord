use super::*;

#[derive(Boilerplate, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionHtml {
  pub chain: Chain,
  pub etching: Option<SpacedRune>,
  pub inscription_count: u32,
  pub transaction: Transaction,
  pub txid: Txid,
}

impl PageContent for TransactionHtml {
  fn title(&self) -> String {
    format!("Transaction {}", self.txid)
  }
}
