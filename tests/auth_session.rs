use assert_cmd::prelude::*;
use serde_json::Value;
use std::process::Command;
use tempfile::TempDir;

fn bin_cmd() -> Command {
    Command::cargo_bin("tsupasswd").expect("binary 'tsupasswd' not found")
}

fn temp_home() -> TempDir {
    tempfile::Builder::new()
        .prefix("tsupasswd_test_")
        .tempdir()
        .expect("failed to create tempdir")
}

#[test]
fn auth_logout_status_flow() {
    let home_dir = temp_home();
    let home = home_dir.path();

    let mut status0 = bin_cmd();
    status0
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["status", "--json"]);
    status0.assert().failure();

    let mut auth = bin_cmd();
    auth.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["auth", "test-secret", "--ttl", "5"]);
    auth.assert().success();

    let mut status1 = bin_cmd();
    status1
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["status", "--json"]);
    let out = status1.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("invalid json");
    assert_eq!(v["authenticated"], true);

    let mut logout = bin_cmd();
    logout
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .arg("logout");
    logout.assert().success();

    let mut status2 = bin_cmd();
    status2
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["status", "--json"]);
    status2.assert().failure();
}
