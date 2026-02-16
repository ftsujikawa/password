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
fn csv_export_import_roundtrip() {
    let src_home_dir = temp_home();
    let src_home = src_home_dir.path();
    auth(src_home);

    let mut add1 = bin_cmd();
    add1
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", src_home)
        .env("USERPROFILE", src_home)
        .env("LOCALAPPDATA", src_home)
        .args([
            "add",
            "https://a.example",
            "u1",
            "p1",
            "--title",
            "t1",
            "--note",
            "n1",
        ]);
    add1.assert().success();

    let mut add2 = bin_cmd();
    add2
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", src_home)
        .env("USERPROFILE", src_home)
        .env("LOCALAPPDATA", src_home)
        .args(["add", "https://b.example", "u2", "p2"]);
    add2.assert().success();

    let csv_dir = tempfile::Builder::new()
        .prefix("tsupasswd_csv_")
        .tempdir()
        .expect("failed to create tempdir");
    let csv_path = csv_dir.path().join("export.csv");

    let mut export = bin_cmd();
    export
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", src_home)
        .env("USERPROFILE", src_home)
        .env("LOCALAPPDATA", src_home)
        .args(["export", csv_path.to_str().unwrap()]);
    export.assert().success();

    let dst_home_dir = temp_home();
    let dst_home = dst_home_dir.path();
    auth(dst_home);

    let mut import = bin_cmd();
    import
        .env("AUTH_SECRET", "test-secret")
        .env("HOME", dst_home)
        .env("USERPROFILE", dst_home)
        .env("LOCALAPPDATA", dst_home)
        .args(["import", csv_path.to_str().unwrap()]);
    import.assert().success();

    let mut get = bin_cmd();
    get.env("AUTH_SECRET", "test-secret")
        .env("HOME", dst_home)
        .env("USERPROFILE", dst_home)
        .env("LOCALAPPDATA", dst_home)
        .args(["get", "https://a.example", "--json"]);
    let out = get.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("invalid json");
    let arr = v.as_array().expect("expected array");
    assert_eq!(arr[0]["username"], "u1");
    assert_eq!(arr[0]["password"], "p1");
}
