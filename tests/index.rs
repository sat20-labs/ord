use super::*;

#[test]
fn run_is_an_alias_for_update() {
  let core = mockcore::spawn();
  core.mine_blocks(1);

  let tempdir = TempDir::new().unwrap();

  let index_path = tempdir.path().join("foo.redb");

  CommandBuilder::new(format!("--index {} index run", index_path.display()))
    .core(&core)
    .run_and_extract_stdout();

  assert!(index_path.is_file())
}

#[test]
fn custom_index_path() {
  let core = mockcore::spawn();
  core.mine_blocks(1);

  let tempdir = TempDir::new().unwrap();

  let index_path = tempdir.path().join("foo.redb");

  CommandBuilder::new(format!("--index {} index update", index_path.display()))
    .core(&core)
    .run_and_extract_stdout();

  assert!(index_path.is_file())
}

#[test]
fn re_opening_database_does_not_trigger_schema_check() {
  let core = mockcore::spawn();
  core.mine_blocks(1);

  let tempdir = TempDir::new().unwrap();

  let index_path = tempdir.path().join("foo.redb");

  CommandBuilder::new(format!("--index {} index update", index_path.display()))
    .core(&core)
    .run_and_extract_stdout();

  assert!(index_path.is_file());

  CommandBuilder::new(format!("--index {} index update", index_path.display()))
    .core(&core)
    .run_and_extract_stdout();
}
