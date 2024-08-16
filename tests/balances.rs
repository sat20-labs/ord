use {super::*, ord::subcommand::balances::Output};

#[test]
fn flag_is_required() {
  let core = mockcore::builder().network(Network::Regtest).build();

  CommandBuilder::new("--regtest balances")
    .core(&core)
    .expected_exit_code(1)
    .expected_stderr("error: `ord balances` requires index created with `--index-runes` flag\n")
    .run_and_extract_stdout();
}

#[test]
fn no_runes() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let output = CommandBuilder::new("--regtest --index-runes balances")
    .core(&core)
    .run_and_deserialize_output::<Output>();

  assert_eq!(
    output,
    Output {
      runes: BTreeMap::new()
    }
  );
}
