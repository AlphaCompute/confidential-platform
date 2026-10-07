//! The built binary's `healthcheck` subcommand with a cleared environment: it must answer
//! from `ALPHACOMPUTE_SECRETS` alone and never reach the runtime's configuration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::process::Command;
use std::time::Duration;

fn healthcheck(secrets: Option<&str>) -> i32 {
    let mut command = Command::new(env!("CARGO_BIN_EXE_alpha-runtime"));
    command.arg("healthcheck").env_clear();
    if let Some(secrets) = secrets {
        command.env("ALPHACOMPUTE_SECRETS", secrets);
    }
    let mut child = command.spawn().unwrap();
    for _ in 0..50 {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    panic!("healthcheck {secrets:?} did not exit within 5 s");
}

#[test]
fn healthcheck_answers_from_the_secrets_variable_alone() {
    // The server path would exit 1 here, refusing the missing KMS variables.
    assert_eq!(healthcheck(None), 0);
    assert_eq!(healthcheck(Some(r#"{"web":["x"]}"#)), 1);
    assert_eq!(healthcheck(Some("not json")), 1);
}
