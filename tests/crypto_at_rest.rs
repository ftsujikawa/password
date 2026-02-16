use assert_cmd::prelude::*;
use rusqlite::{params, Connection};
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
fn password_is_not_stored_in_plaintext_in_db() {
    let home_dir = temp_home();
    let home = home_dir.path();
    auth(home);

    let url = "https://secret.example";
    let username = "bob";
    let plaintext = "super-secret-plaintext";

    let mut add = bin_cmd();
    add.env("AUTH_SECRET", "test-secret")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home)
        .args(["add", url, username, plaintext]);
    add.assert().success();

    let db_path = home.join(".tsupasswd_db").join("passwords.db");
    assert!(db_path.exists());

    let conn = Connection::open(db_path).expect("failed to open db");
    let enc_pw: String = conn
        .query_row(
            "SELECT password FROM passwords WHERE url = ?1 LIMIT 1",
            params![url],
            |row| row.get(0),
        )
        .expect("row not found");

    assert_ne!(enc_pw, plaintext);
    assert!(!enc_pw.contains(plaintext));
}
