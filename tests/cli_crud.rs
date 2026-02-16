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

fn auth(home: &std::path::Path) {
    let mut cmd = bin_cmd();
    cmd.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .arg("auth")
        .arg("test-secret")
        .arg("--ttl")
        .arg("5");
    cmd.assert().success();
}

#[test]
fn cli_crud_flow() {
    let home_dir = temp_home();
    let home = home_dir.path();

    auth(home);

    let url = "https://example.com";
    let username = "alice";
    let password1 = "pw-1";
    let password2 = "pw-2";

    let mut add = bin_cmd();
    add.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["add", url, username, password1, "--title", "t1", "--note", "n1"]);
    add.assert().success();

    let mut get = bin_cmd();
    get.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["get", url, "--json"]);
    let out = get.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("invalid json");
    let arr = v.as_array().expect("expected array");
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["username"], username);
    assert_eq!(arr[0]["password"], password1);
    assert_eq!(arr[0]["title"], "t1");
    assert_eq!(arr[0]["note"], "n1");

    let mut search = bin_cmd();
    search
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["search", "example.com", "--json"]);
    let out = search.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("invalid json");
    let arr = v.as_array().expect("expected array");
    assert!(!arr.is_empty());
    let id = arr[0]["id"].as_str().expect("id must be string");

    let mut update = bin_cmd();
    update
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["update", id, "--password", password2, "--title", "t2"]);
    update.assert().success();

    let mut get2 = bin_cmd();
    get2.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["get", url, "--json"]);
    let out = get2.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("invalid json");
    let arr = v.as_array().expect("expected array");
    assert_eq!(arr[0]["password"], password2);
    assert_eq!(arr[0]["title"], "t2");

    let mut delete = bin_cmd();
    delete
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["delete", id]);
    delete.assert().success();

    let mut get3 = bin_cmd();
    get3.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["get", url]);
    get3.assert().failure();
}
