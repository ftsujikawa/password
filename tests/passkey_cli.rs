use assert_cmd::prelude::*;
use std::process::Command;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn bin_cmd() -> Command {
    Command::cargo_bin("password").expect("binary 'password' not found")
}

fn temp_home() -> TempDir {
    tempfile::Builder::new()
        .prefix("password_cli_test_")
        .tempdir()
        .expect("failed to create tempdir")
}

fn auth(home: &PathBuf) {
    let mut cmd = bin_cmd();
    cmd.env("AUTH_SECRET", "test-secret-123")
        .env("HOME", home)
        .arg("auth")
        .arg("test-secret-123")
        .arg("--ttl")
        .arg("5");
    cmd.assert().success();
}

#[test]
fn passkey_add_get_search_export_delete_flow() {
    let home_dir = temp_home();
    let home = home_dir.path().to_path_buf();

    // 認証
    auth(&home);

    // add
    let mut add = bin_cmd();
    add.env("AUTH_SECRET", "test-secret-123")
        .env("HOME", &home)
        .args([
            "passkey", "add", "example.com", "cred-123", "user-abc", "pubkey-xyz",
        ])
        .args(["--sign-count", "42"]) 
        .args(["--transports", "usb,nfc"]);
    let add_out = add.assert().success().get_output().stdout.clone();
    let add_out = String::from_utf8_lossy(&add_out);
    assert!(add_out.contains("保存しました:"));

    // get
    let mut get = bin_cmd();
    get.env("AUTH_SECRET", "test-secret-123")
        .env("HOME", &home)
        .args(["passkey", "get", "example.com", "user-abc"]);
    let get_out = get.assert().success().get_output().stdout.clone();
    let get_out = String::from_utf8_lossy(&get_out);
    assert!(get_out.contains("rp_id=\"example.com\""));
    assert!(get_out.contains("credential_id=\"cred-123\""));
    assert!(get_out.contains("user_handle=\"user-abc\""));

    // search（ID取得）
    let mut search = bin_cmd();
    search
        .env("AUTH_SECRET", "test-secret-123")
        .env("HOME", &home)
        .args(["passkey", "search", "example.com"]);
    let search_out = search.assert().success().get_output().stdout.clone();
    let search_out = String::from_utf8_lossy(&search_out);
    assert!(search_out.contains("id="));
    // 先頭トークンの id=... を抽出
    let first_line = search_out.lines().next().unwrap_or("");
    let id = first_line
        .split_whitespace()
        .find(|tok| tok.starts_with("id="))
        .and_then(|tok| tok.strip_prefix("id="))
        .expect("id not found in search output");

    // export
    let csv_path = home.join("passkeys.csv");
    let mut export_cmd = bin_cmd();
    export_cmd
        .env("AUTH_SECRET", "test-secret-123")
        .env("HOME", &home)
        .args(["passkey", "export", csv_path.to_string_lossy().as_ref()]);
    export_cmd.assert().success();
    assert!(fs::metadata(&csv_path).is_ok(), "CSV not created: {}", csv_path.display());

    // delete
    let mut delete_cmd = bin_cmd();
    delete_cmd
        .env("AUTH_SECRET", "test-secret-123")
        .env("HOME", &home)
        .args(["passkey", "delete", id]);
    delete_cmd.assert().success();

    // delete 後 get は失敗（非0）
    let mut get2 = bin_cmd();
    get2.env("AUTH_SECRET", "test-secret-123")
        .env("HOME", &home)
        .args(["passkey", "get", "example.com", "user-abc"]);
    get2.assert().failure();
}
