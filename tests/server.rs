use {super::*, ciborium::value::Integer};

#[test]
fn run() {
  let core = mockcore::spawn();

  let port = TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
    .port();

  let builder =
    CommandBuilder::new(format!("server --address 127.0.0.1 --http-port {port}")).core(&core);

  let mut command = builder.command();

  let mut child = command.spawn().unwrap();

  for attempt in 0.. {
    if let Ok(response) = reqwest::blocking::get(format!("http://localhost:{port}/status")) {
      if response.status() == 200 {
        break;
      }
    }

    if attempt == 100 {
      panic!("Server did not respond to status check",);
    }

    thread::sleep(Duration::from_millis(50));
  }

  child.kill().unwrap();
}

#[test]
fn expected_sat_time_is_rounded() {
  let core = mockcore::spawn();

  TestServer::spawn_with_args(&core, &[]).assert_response_regex(
    "/sat/2099999997689999",
    r".*<dt>timestamp</dt><dd><time>.* \d+:\d+:\d+ UTC</time> \(expected\)</dd>.*",
  );
}

#[test]
fn missing_credentials() {
  let core = mockcore::spawn();

  CommandBuilder::new("--bitcoin-rpc-username foo server")
    .core(&core)
    .expected_exit_code(1)
    .expected_stderr("error: no bitcoin RPC password specified\n")
    .run_and_extract_stdout();

  CommandBuilder::new("--bitcoin-rpc-password bar server")
    .core(&core)
    .expected_exit_code(1)
    .expected_stderr("error: no bitcoin RPC username specified\n")
    .run_and_extract_stdout();
}

#[test]
fn ctrl_c() {
  use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
  };

  let core = mockcore::spawn();

  let port = TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
    .port();

  let tempdir = Arc::new(TempDir::new().unwrap());

  core.mine_blocks(3);

  let mut spawn = CommandBuilder::new(format!("server --address 127.0.0.1 --http-port {port}"))
    .temp_dir(tempdir.clone())
    .core(&core)
    .spawn();

  for attempt in 0.. {
    if let Ok(response) = reqwest::blocking::get(format!("http://localhost:{port}/blockcount")) {
      if response.status() == 200 || response.text().unwrap() == *"3" {
        break;
      }
    }

    if attempt == 100 {
      panic!("Server did not respond to status check",);
    }

    thread::sleep(Duration::from_millis(50));
  }

  signal::kill(
    Pid::from_raw(spawn.child.id().try_into().unwrap()),
    Signal::SIGINT,
  )
  .unwrap();

  let mut buffer = String::new();
  BufReader::new(spawn.child.stderr.as_mut().unwrap())
    .read_line(&mut buffer)
    .unwrap();

  assert_eq!(
    buffer,
    "Shutting down gracefully. Press <CTRL-C> again to shutdown immediately.\n"
  );

  spawn.child.wait().unwrap();

  CommandBuilder::new(format!(
    "server --no-sync --address 127.0.0.1 --http-port {port}"
  ))
  .temp_dir(tempdir)
  .core(&core)
  .spawn();

  for attempt in 0.. {
    if let Ok(response) = reqwest::blocking::get(format!("http://localhost:{port}/blockcount")) {
      if response.status() == 200 || response.text().unwrap() == *"3" {
        break;
      }
    }

    if attempt == 100 {
      panic!("Server did not respond to status check",);
    }

    thread::sleep(Duration::from_millis(50));
  }
}
