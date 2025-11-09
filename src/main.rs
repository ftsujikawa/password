use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use csv::{ReaderBuilder, WriterBuilder};

// WindowsのみShift-JISで出力するためにprintln!/eprintln!をローカルでラップ
#[derive(Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum OutEnc { Utf8, Sjis }

#[allow(dead_code)]
fn decide_encoding() -> OutEnc {
    if let Ok(v) = std::env::var("TSUPASSWD_ENCODING") {
        match v.to_ascii_lowercase().as_str() {
            "sjis" | "shift_jis" | "shift-jis" | "cp932" | "932" => return OutEnc::Sjis,
            "utf8" | "utf-8" | "65001" => return OutEnc::Utf8,
            _ => {}
        }
    }
    #[cfg(windows)]
    {
        if std::env::var("WT_SESSION").is_ok() { return OutEnc::Utf8; }
        if let Ok(tp) = std::env::var("TERM_PROGRAM") {
            let tp = tp.to_ascii_lowercase();
            if tp == "vscode" || tp == "windows_terminal" || tp == "windows terminal" { return OutEnc::Utf8; }
        }
        let cp = unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() };
        if cp == 932 { OutEnc::Sjis } else { OutEnc::Utf8 }
    }
    #[cfg(not(windows))]
    { OutEnc::Utf8 }
}
#[cfg(windows)]
fn print_encoded(line: String, is_err: bool) {
    use std::io::{self, Write};
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, WriteConsoleW, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    unsafe {
        let handle = if is_err { GetStdHandle(STD_ERROR_HANDLE) } else { GetStdHandle(STD_OUTPUT_HANDLE) };
        let mut mode: u32 = 0;
        // コンソールに直結している場合は UTF-16 で直接出力
        if handle != std::ptr::null_mut() && GetConsoleMode(handle, &mut mode) != 0 {
            let mut wide: Vec<u16> = line.encode_utf16().collect();
            // 行末にCRLF追加
            wide.push('\r' as u16);
            wide.push('\n' as u16);
            let mut written: u32 = 0;
            let _ = WriteConsoleW(handle, wide.as_ptr() as *const _, wide.len() as u32, &mut written as *mut u32, std::ptr::null());
            return;
        }
    }
    // リダイレクト・パイプ時はバイト列で出力（環境変数で選択）
    match decide_encoding() {
        OutEnc::Sjis => {
            let (bytes, _, _) = encoding_rs::SHIFT_JIS.encode(&line);
            if is_err {
                let _ = io::stderr().write_all(&bytes);
                let _ = io::stderr().write_all(b"\r\n");
                let _ = io::stderr().flush();
            } else {
                let _ = io::stdout().write_all(&bytes);
                let _ = io::stdout().write_all(b"\r\n");
                let _ = io::stdout().flush();
            }
        }
        OutEnc::Utf8 => {
            if is_err { let _ = writeln!(io::stderr(), "{}", line); }
            else { let _ = writeln!(io::stdout(), "{}", line); }
        }
    }
}

#[cfg(not(windows))]
fn print_encoded(line: String, is_err: bool) {
    use std::io::{self, Write};
    if is_err {
        let _ = writeln!(io::stderr(), "{}", line);
    } else {
        let _ = writeln!(io::stdout(), "{}", line);
    }
}

macro_rules! println {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        crate::print_encoded(s, false);
    }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        crate::print_encoded(s, true);
    }};
}

fn print_usage() {
    println!("使い方:");
    println!("  tsupasswd [長さ]");
    println!("  tsupasswd add <url> <username> [password|length] [--title <title>] [--note <note>]");
    println!("  tsupasswd get <url> [--json]");
    println!("  tsupasswd search <keyword> [--json]");
    println!("  tsupasswd update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]");
    println!("  tsupasswd delete <id>");
    println!("  tsupasswd export <csv_path>");
    println!("  tsupasswd import <csv_path>");
    println!("  tsupasswd auth <secret> [--ttl MINUTES]");
    println!("  tsupasswd logout");
    println!("  tsupasswd status [--json]");
    println!("  tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV] [--title T]");
    println!("  tsupasswd passkey get <rp_id> <user_handle> [--json]");
    println!("  tsupasswd passkey search <keyword> [--json]");
    println!("  tsupasswd passkey delete <id>");
    println!("  tsupasswd passkey export <csv_path>");
    println!("  tsupasswd passkey import <csv_path>");
    println!("");
    println!("共通オプション:");
    println!("  -h, --help    このヘルプを表示");
    println!("");
    println!("コマンド詳細:");
    println!("  tsupasswd [長さ]");
    println!("    引数:");
    println!("      長さ              生成するパスワードの文字数（省略時 16）");
    println!("");
    println!("  tsupasswd add <url> <username> [password|length] [--title <title>] [--note <note>]");
    println!("    引数:");
    println!("      url               サイトURL等の識別子");
    println!("      username          ユーザ名");
    println!("      password|length   文字列を指定するとそのまま保存、数値を指定するとその長さで生成");
    println!("    オプション:");
    println!("      --title <title>   タイトル");
    println!("      --note <note>     備考");
    println!("");
    println!("  tsupasswd get <url> [--json]");
    println!("    オプション:");
    println!("      --json            JSON形式で出力");
    println!("");
    println!("  tsupasswd search <keyword> [--json]");
    println!("    オプション:");
    println!("      --json            JSON形式で出力");
    println!("");
    println!("  tsupasswd update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]");
    println!("    オプション:");
    println!("      --url U           URL を更新");
    println!("      --user NAME       ユーザ名を更新");
    println!("      --password PASS   パスワードをこの文字列に更新");
    println!("      --length N        ランダムに N 文字のパスワードを生成して更新");
    println!("      --title T         タイトルを更新");
    println!("      --note N          備考を更新");
    println!("");
    println!("  tsupasswd delete <id>");
    println!("");
    println!("  tsupasswd export <csv_path>");
    println!("");
    println!("  tsupasswd import <csv_path>");
    println!("");
    println!("  tsupasswd auth <secret> [--ttl MINUTES]");
    println!("    オプション:");
    println!("      --ttl MINUTES     セッション有効期限（分） デフォルト 30");
    println!("");
    println!("  tsupasswd logout");
    println!("  tsupasswd status");
    println!("");
    println!("  tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV] [--title T]");
    println!("    オプション:");
    println!("      --sign-count N    認証器のサインカウント");
    println!("      --transports CSV  transports をカンマ区切りで指定");
    println!("      --title T         タイトル");
    println!("");
    println!("  tsupasswd passkey get <rp_id> <user_handle> [--json]");
    println!("    オプション:");
    println!("      --json            JSON形式で出力");
    println!("");
    println!("  tsupasswd passkey search <keyword> [--json]");
    println!("    オプション:");
    println!("      --json            JSON形式で出力");
    println!("");
    println!("  tsupasswd passkey delete <id>");
    println!("  tsupasswd passkey export <csv_path>");
    println!("  tsupasswd passkey import <csv_path>");
    println!("");
    println!("環境変数:");
    println!("  AUTH_SECRET           認証用シークレット（tsupasswd auth で使用）");
    println!("  TSUPASSWD_ENCODING    出力エンコーディングを指定（utf8 / sjis）。Windowsでのリダイレクト時に有効");
}
#[tokio::main]
async fn main() {
    // 端末のコードページは実行時に検出して出力側で切替
    // パニック時のメッセージもエンコードして出力
    std::panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "panic occurred".to_string()
        };
        #[cfg(windows)]
        {
            crate::print_encoded(format!("panic: {}", msg), true);
        }
        #[cfg(not(windows))]
        {
            eprintln!("panic: {}", msg);
        }
    }));
    // CLI:
    // - `tsupasswd` -> デフォルト16文字のパスワードを出力
    // - `tsupasswd 24` -> 指定長のパスワードを出力
    // - `tsupasswd add <url> <username> [password|length] [--title <title>] [--note <note>]` -> DBに保存
    // - `tsupasswd get <url>` -> URLで検索してユーザID/パスワード/タイトル/備考を取得
    // - `tsupasswd search <keyword>` -> 部分一致で検索（url/username/title/note）しID付きで一覧
    // - `tsupasswd update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]` -> レコード更新（idはFirestoreのドキュメントID）
    // - `tsupasswd delete <id>` -> レコード削除（idはFirestoreのドキュメントID）
    // Rustls 0.23+: 明示的に CryptoProvider をインストール（結果は無視）
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 引数を収集してログに追記
    let all_args: Vec<String> = env::args().collect();
    let mut args = all_args.clone().into_iter();
    let _prog = args.next();
    let first = args.next();
    if matches!(first.as_deref(), Some("--help") | Some("-h") | Some("help")) {
        print_usage();
        return;
    }
    match first.as_deref() {
        Some("passkey") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            match args.next().as_deref() {
                Some("add") => {
                    let rp_id = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV] [--title T]"); std::process::exit(1);} };
                    let credential_id = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV] [--title T]"); std::process::exit(1);} };
                    let user_handle = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV] [--title T]"); std::process::exit(1);} };
                    let public_key = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV] [--title T]"); std::process::exit(1);} };
                    let mut sign_count: i64 = 0;
                    let mut title: Option<String> = None;
                    let mut transports: Option<String> = None;
                    while let Some(flag) = args.next() {
                        match flag.as_str() {
                            "--sign-count" => { if let Some(n) = args.next().and_then(|s| s.parse::<i64>().ok()) { sign_count = n.max(0); } }
                            "--title" => { title = args.next(); }
                            "--transports" => { transports = args.next(); }
                            _ => {}
                        }
                    }
                    let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
                    match insert_passkey(&db, &rp_id, &credential_id, &user_handle, &public_key, sign_count, title.as_deref(), transports.as_deref()).await {
                        Ok(rec) => {
                            match rec.title.as_deref() {
                                Some(ttl) => println!("保存しました: id={} rp_id=\"{}\" user_handle=\"{}\" title=\"{}\"", rec.id, rec.rp_id, rec.user_handle, ttl),
                                None => println!("保存しました: id={} rp_id=\"{}\" user_handle=\"{}\"", rec.id, rec.rp_id, rec.user_handle),
                            }
                        }
                        Err(e) => { eprintln!("保存に失敗しました: {}", e); std::process::exit(1); }
                    }
                }
                Some("get") => {
                    let rp_id = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey get <rp_id> <user_handle>"); std::process::exit(1);} };
                    let user_handle = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey get <rp_id> <user_handle>"); std::process::exit(1);} };
                    let mut json_out = false;
                    while let Some(flag) = args.next() { if flag == "--json" { json_out = true; } }
                    let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
                    match get_passkeys_by_user(&db, &rp_id, &user_handle).await {
                        Ok(list) => {
                            if list.is_empty() { eprintln!("見つかりませんでした: rp_id={} user_handle={} ", rp_id, user_handle); std::process::exit(1); }
                            if json_out {
                                let data: Vec<_> = list.into_iter().map(|r| {
                                    serde_json::json!({
                                        "id": r.id,
                                        "rp_id": r.rp_id,
                                        "credential_id": r.credential_id,
                                        "user_handle": r.user_handle,
                                        "public_key": r.public_key,
                                        "sign_count": r.sign_count,
                                        "title": r.title,
                                        "transports": r.transports,
                                        "created_at": r.created_at,
                                    })
                                }).collect();
                                match serde_json::to_string_pretty(&data) { Ok(s) => println!("{}", s), Err(e) => { eprintln!("JSONエンコードに失敗しました: {}", e); std::process::exit(1); } }
                            } else {
                                for r in list {
                                    match (r.title.as_deref(), r.transports.as_deref()) {
                                        (Some(ttl), Some(t)) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={} title=\"{}\" transports=\"{}\"", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count, ttl, t),
                                        (Some(ttl), None) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={} title=\"{}\"", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count, ttl),
                                        (None, Some(t)) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={} transports=\"{}\"", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count, t),
                                        (None, None) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={}", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count),
                                    }
                                }
                            }
                        }
                        Err(e) => { eprintln!("取得に失敗しました: {}", e); std::process::exit(1); }
                    }
                }
                Some("search") => {
                    let keyword = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey search <keyword>"); std::process::exit(1);} };
                    let mut json_out = false;
                    while let Some(flag) = args.next() { if flag == "--json" { json_out = true; } }
                    let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
                    match search_passkeys(&db, &keyword).await {
                        Ok(list) => {
                            if list.is_empty() { eprintln!("見つかりませんでした: keyword={}", keyword); std::process::exit(1); }
                            if json_out {
                                let data: Vec<_> = list.into_iter().map(|r| {
                                    serde_json::json!({
                                        "id": r.id,
                                        "rp_id": r.rp_id,
                                        "credential_id": r.credential_id,
                                        "user_handle": r.user_handle,
                                        "public_key": r.public_key,
                                        "sign_count": r.sign_count,
                                        "title": r.title,
                                        "transports": r.transports,
                                        "created_at": r.created_at,
                                    })
                                }).collect();
                                match serde_json::to_string_pretty(&data) { Ok(s) => println!("{}", s), Err(e) => { eprintln!("JSONエンコードに失敗しました: {}", e); std::process::exit(1); } }
                            } else {
                                for r in list {
                                    match (r.title.as_deref(), r.transports.as_deref()) {
                                        (Some(ttl), Some(t)) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={} title=\"{}\" transports=\"{}\"", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count, ttl, t),
                                        (Some(ttl), None) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={} title=\"{}\"", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count, ttl),
                                        (None, Some(t)) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={} transports=\"{}\"", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count, t),
                                        (None, None) => println!("id={} rp_id=\"{}\" credential_id=\"{}\" user_handle=\"{}\" sign_count={}", r.id, r.rp_id, r.credential_id, r.user_handle, r.sign_count),
                                    }
                                }
                            }
                        }
                        Err(e) => { eprintln!("検索に失敗しました: {}", e); std::process::exit(1); }
                    }
                }
                Some("delete") => {
                    let id = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey delete <id>"); std::process::exit(1);} };
                    let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
                    if let Err(e) = delete_passkey(&db, &id).await { eprintln!("削除に失敗しました: {}", e); std::process::exit(1); } else { println!("削除しました: id={}", id); }
                }
                Some("export") => {
                    let path = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey export <csv_path>"); std::process::exit(1);} };
                    let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
                    if let Err(e) = export_passkeys_csv(&db, &path) { eprintln!("エクスポートに失敗しました: {}", e); std::process::exit(1); } else { println!("エクスポート完了: {}", path); }
                }
                Some("import") => {
                    let path = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd passkey import <csv_path>"); std::process::exit(1);} };
                    let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
                    if let Err(e) = import_passkeys_csv(&db, &path).await { eprintln!("インポートに失敗しました: {}", e); std::process::exit(1); } else { println!("インポート完了: {}", path); }
                }
                _ => {
                    eprintln!("使い方: tsupasswd passkey <add|get|search|delete|export|import> ...");
                    std::process::exit(1);
                }
            }
        }
        Some("export") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let path = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd export <csv_path>"); std::process::exit(1);} };
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            if let Err(e) = export_csv(&db, &path) {
                eprintln!("エクスポートに失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("エクスポート完了: {}", path);
            }
        }
        Some("import") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let path = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd import <csv_path>"); std::process::exit(1);} };
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            if let Err(e) = import_csv(&db, &path).await {
                eprintln!("インポートに失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("インポート完了: {}", path);
            }
        }
        Some("auth") => {
            let secret = match args.next() { Some(v) => v, None => { eprintln!("使い方: tsupasswd auth <secret> [--ttl MINUTES]"); std::process::exit(1);} };
            let mut ttl: i64 = 30;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--ttl" => {
                        if let Some(n) = args.next().and_then(|s| s.parse::<i64>().ok()) { ttl = n.max(1); }
                    }
                    _ => {}
                }
            }
            let expected = match env::var("AUTH_SECRET") { Ok(v) => v, Err(_) => { eprintln!("環境変数 AUTH_SECRET が未設定です"); std::process::exit(1)} };
            if secret != expected { eprintln!("認証に失敗しました"); std::process::exit(1); }
            if let Err(e) = start_session(ttl) {
                eprintln!("セッション開始に失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("認証しました: 有効期限 {} 分", ttl);
            }
        }
        Some("logout") => {
            if let Err(e) = end_session() {
                eprintln!("ログアウトに失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("ログアウトしました");
            }
        }
        Some("status") => {
            let mut json_out = false;
            while let Some(flag) = args.next() { if flag == "--json" { json_out = true; } }
            match session_status() {
                Ok(Some(rem)) => {
                    if json_out {
                        let obj = serde_json::json!({
                            "authenticated": true,
                            "remaining_seconds": rem,
                        });
                        match serde_json::to_string_pretty(&obj) { Ok(s) => println!("{}", s), Err(e) => { eprintln!("JSONエンコードに失敗しました: {}", e); std::process::exit(1); } }
                    } else {
                        println!("認証済み: 残り {} 秒", rem)
                    }
                }
                Ok(None) => {
                    if json_out {
                        let obj = serde_json::json!({
                            "authenticated": false
                        });
                        match serde_json::to_string_pretty(&obj) { Ok(s) => println!("{}", s), Err(e) => { eprintln!("JSONエンコードに失敗しました: {}", e); std::process::exit(1); } }
                    } else {
                        eprintln!("未認証です");
                    }
                    std::process::exit(1);
                }
                Err(e) => { eprintln!("状態取得に失敗しました: {}", e); std::process::exit(1); }
            }
        }
        Some("add") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let url = match args.next() { Some(v) => v, None => return print_add_usage_and_exit() };
            let username = match args.next() { Some(v) => v, None => return print_add_usage_and_exit() };
            let maybe_pw_or_len = args.next();

            let password = match maybe_pw_or_len {
                None => generate_password(16),
                Some(s) => match s.parse::<usize>() {
                    Ok(n) => generate_password(n.max(1)),
                    Err(_) => s, // 文字列が数値でなければ、そのままパスワードとして扱う
                },
            };

            // 追加オプションの解析: --title <title> --note <note>
            let mut title: Option<String> = None;
            let mut note: Option<String> = None;
            loop {
                match args.next() {
                    Some(flag) if flag == "--title" => {
                        title = args.next();
                    }
                    Some(flag) if flag == "--note" => {
                        note = args.next();
                    }
                    Some(_) => {
                        // 未知の引数は無視（簡易実装）
                        continue;
                    }
                    None => break,
                }
            }

            let db = match init_db().await {
                Ok(db) => db,
                Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1); }
            };
            if let Err(e) = insert_password(&db, &url, &username, &password, title.as_deref(), note.as_deref()).await {
                eprintln!("保存に失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("保存しました: url={} username={}", url, username);
            }
        }
        Some("get") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let url = match args.next() { Some(v) => v, None => {
                eprintln!("使い方: tsupasswd get <url>");
                std::process::exit(1);
            }};
            let mut json_out = false;
            while let Some(flag) = args.next() { if flag == "--json" { json_out = true; } }
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            match fetch_by_url(&db, &url).await {
                Ok(entries) => {
                        if entries.is_empty() {
                            eprintln!("見つかりませんでした: url={}", url);
                            std::process::exit(1);
                        } else {
                            if json_out {
                                let data: Vec<_> = entries.into_iter().map(|(username, password, title, note)| {
                                    serde_json::json!({
                                        "username": username,
                                        "password": password,
                                        "title": title,
                                        "note": note,
                                    })
                                }).collect();
                                match serde_json::to_string_pretty(&data) { Ok(s) => println!("{}", s), Err(e) => { eprintln!("JSONエンコードに失敗しました: {}", e); std::process::exit(1); } }
                            } else {
                                for (username, password, title, note) in entries {
                                    match (title.as_deref(), note.as_deref()) {
                                        (Some(t), Some(n)) => println!("username=\"{}\" password=\"{}\" title=\"{}\" note=\"{}\"", username, password, t, n),
                                        (Some(t), None) => println!("username=\"{}\" password=\"{}\" title=\"{}\"", username, password, t),
                                        (None, Some(n)) => println!("username=\"{}\" password=\"{}\" note=\"{}\"", username, password, n),
                                        (None, None) => println!("username=\"{}\" password=\"{}\"", username, password),
                                    }
                                }
                            }
                        }
                }
                Err(e) => { eprintln!("検索に失敗しました: {}", e); std::process::exit(1); }
            }
        }
        Some("search") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let keyword = match args.next() { Some(v) => v, None => {
                eprintln!("使い方: tsupasswd search <keyword>");
                std::process::exit(1);
            }};
            let mut json_out = false;
            while let Some(flag) = args.next() { if flag == "--json" { json_out = true; } }
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            match search_entries(&db, &keyword).await {
                Ok(entries) => {
                        if entries.is_empty() {
                            eprintln!("見つかりませんでした: keyword={}", keyword);
                            std::process::exit(1);
                        } else {
                            if json_out {
                                let data: Vec<_> = entries.into_iter().map(|(id, url, username, password, title, note)| {
                                    serde_json::json!({
                                        "id": id,
                                        "url": url,
                                        "username": username,
                                        "password": password,
                                        "title": title,
                                        "note": note,
                                    })
                                }).collect();
                                match serde_json::to_string_pretty(&data) { Ok(s) => println!("{}", s), Err(e) => { eprintln!("JSONエンコードに失敗しました: {}", e); std::process::exit(1); } }
                            } else {
                                for (id, url, username, password, title, note) in entries {
                                    match (title.as_deref(), note.as_deref()) {
                                        (Some(t), Some(n)) => println!("id={} url=\"{}\" username=\"{}\" password=\"{}\" title=\"{}\" note=\"{}\"", id, url, username, password, t, n),
                                        (Some(t), None) => println!("id={} url=\"{}\" username=\"{}\" password=\"{}\" title=\"{}\"", id, url, username, password, t),
                                        (None, Some(n)) => println!("id={} url=\"{}\" username=\"{}\" password=\"{}\" note=\"{}\"", id, url, username, password, n),
                                        (None, None) => println!("id={} url=\"{}\" username=\"{}\" password=\"{}\"", id, url, username, password),
                                    }
                                }
                            }
                        }
                }
                Err(e) => { eprintln!("検索に失敗しました: {}", e); std::process::exit(1); }
            }
        }
        Some("update") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let id: String = match args.next() { Some(v) => v, None => { eprintln!("使い方: password update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]"); std::process::exit(1);} };
            let mut new_url: Option<String> = None;
            let mut new_user: Option<String> = None;
            let mut new_password: Option<String> = None;
            let mut title: Option<String> = None;
            let mut note: Option<String> = None;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--url" => new_url = args.next(),
                    "--user" => new_user = args.next(),
                    "--password" => new_password = args.next(),
                    "--length" => {
                        if let Some(n) = args.next().and_then(|s| s.parse::<usize>().ok()) {
                            new_password = Some(generate_password(n.max(1)));
                        }
                    }
                    "--title" => title = args.next(),
                    "--note" => note = args.next(),
                    _ => {}
                }
            }
            if new_url.is_none() && new_user.is_none() && new_password.is_none() && title.is_none() && note.is_none() {
                eprintln!("更新内容が指定されていません");
                std::process::exit(1);
            }
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            if let Err(e) = update_entry(&db, &id, new_url.as_deref(), new_user.as_deref(), new_password.as_deref(), title.as_deref(), note.as_deref()).await {
                eprintln!("更新に失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("更新しました: id={}", id);
            }
        }
        Some("delete") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let id: String = match args.next() { Some(v) => v, None => { eprintln!("使い方: password delete <id>"); std::process::exit(1);} };
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            if let Err(e) = delete_entry(&db, &id).await {
                eprintln!("削除に失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("削除しました: id={}", id);
            }
        }
        Some(s) => {
            // 数値なら長さとして解釈。それ以外はヘルプ代わりに16文字生成。
            let len = s.parse::<usize>().unwrap_or(16);
            println!("{}", generate_password(len));
        }
        None => {
            println!("{}", generate_password(16));
        }
    }
}

// 記号を含む安全な文字集合
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT: &[u8] = b"0123456789";
#[allow(dead_code)]
const SYMBOL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/"; // スペースやバックスラッシュ、`'"` は除外

fn generate_password(len: usize) -> String {
    // 総合アルファベット
    let mut alphabet: Vec<u8> = Vec::with_capacity(UPPER.len() + LOWER.len() + DIGIT.len());
    alphabet.extend_from_slice(UPPER);
    alphabet.extend_from_slice(LOWER);
    alphabet.extend_from_slice(DIGIT);

    if len == 0 {
        return String::new();
    }

    // 少なくとも各カテゴリから1文字ずつ確保（ただし必要な長さを超えない）
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    for cat in [UPPER, LOWER, DIGIT] {
        if bytes.len() >= len { break; }
        let idx = rand_index(cat.len());
        bytes.push(cat[idx]);
    }

    // 残りは全アルファベットからランダムに
    while bytes.len() < len {
        let idx = rand_index(alphabet.len());
        bytes.push(alphabet[idx]);
    }

    // シャッフルして先頭にカテゴリ固定が来ないようにする
    fisher_yates_shuffle(&mut bytes);

    String::from_utf8(bytes).unwrap_or_default()
}

fn rand_index(len: usize) -> usize {
    // OsRngからu64を取り出し、範囲に収まるようにリジェクションサンプリング
    if len <= 1 { return 0; }
    let bound = len as u64;
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let v = OsRng.next_u64();
        if v < zone {
            return (v % bound) as usize;
        }
    }
}

fn fisher_yates_shuffle(data: &mut [u8]) {
    if data.len() <= 1 { return; }
    for i in (1..data.len()).rev() {
        let j = rand_index(i + 1);
        data.swap(i, j);
    }
}

const COLLECTION: &str = "passwords"; // SQLiteのテーブル名としても使用

fn session_file_path() -> PathBuf {
    if cfg!(windows) {
        if let Ok(dir) = env::var("LOCALAPPDATA") {
            return PathBuf::from(dir).join("tsupasswd").join("session");
        }
        if let Ok(up) = env::var("USERPROFILE") {
            return PathBuf::from(up).join("AppData").join("Local").join("tsupasswd").join("session");
        }
    }
    let home = env::var("HOME").or_else(|_| env::var("USERPROFILE")).unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".password_cli").join("session")
}

// 引数や標準出力をファイルへ記録する機能は削除済み

fn ensure_authenticated() -> Result<(), String> {
    match session_status() {
        Ok(Some(rem)) => {
            if rem <= 0 { Err("セッションが期限切れです。`tsupasswd auth <secret>` を実行してください".to_string()) } else { Ok(()) }
        }
        Ok(None) => Err("未認証です。`tsupasswd auth <secret>` を実行してください".to_string()),
        Err(e) => Err(format!("認証状態の確認に失敗しました: {}", e)),
    }
}

fn start_session(ttl_minutes: i64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = session_file_path();
    if let Some(dir) = path.parent() { fs::create_dir_all(dir)?; }
    let expiry = Utc::now().timestamp() + ttl_minutes * 60;
    let mut f = fs::File::create(path)?;
    write!(f, "{}", expiry)?;
    Ok(())
}

fn end_session() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = session_file_path();
    if path.exists() { fs::remove_file(path)?; }
    Ok(())
}

fn session_status() -> Result<Option<i64>, Box<dyn std::error::Error + Send + Sync>> {
    let path = session_file_path();
    if !path.exists() { return Ok(None); }
    let s = fs::read_to_string(path)?;
    let expiry: i64 = s.trim().parse()?;
    let now = Utc::now().timestamp();
    Ok(Some(expiry - now))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordRecord {
    id: String,
    url: String,
    username: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    created_at: String,
}

async fn init_db() -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
    let path = db_file_path();
    if let Some(dir) = path.parent() { fs::create_dir_all(dir)?; }
    let conn = Connection::open(path)?;
    conn.execute(
        &format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                title TEXT,
                note TEXT,
                created_at TEXT NOT NULL
            )",
            COLLECTION
        ),
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passkeys (
            id TEXT PRIMARY KEY,
            rp_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            user_handle TEXT NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL,
            title TEXT,
            transports TEXT,
            created_at TEXT NOT NULL
        )",
        [],
    )?;
    // 既存DBへの後方互換: title列が無い場合に追加
    let _ = conn.execute("ALTER TABLE passkeys ADD COLUMN title TEXT", []);
    // 既存DBへの後方互換: transports列が無い場合に追加
    let _ = conn.execute("ALTER TABLE passkeys ADD COLUMN transports TEXT", []);
    Ok(conn)
}

async fn insert_password(
    db: &Connection,
    url: &str,
    username: &str,
    password: &str,
    title: Option<&str>,
    note: Option<&str>,
) -> Result<PasswordRecord, Box<dyn std::error::Error + Send + Sync>> {
    // 既存URLの有無を確認（最新の1件）
    if let Some((existing_id, existing_title, existing_note, created_at)) = {
        let mut stmt = db.prepare(&format!(
            "SELECT id, title, note, created_at FROM {} WHERE url = ?1 ORDER BY created_at DESC LIMIT 1",
            COLLECTION
        ))?;
        stmt
            .query_row(params![url], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .optional()?
    } {
        // 更新：username/passwordは上書き、title/noteは新規指定があれば上書き、未指定は既存維持
        let new_title = title.map(|s| s.to_string()).or(existing_title);
        let new_note = note.map(|s| s.to_string()).or(existing_note);
        let enc_pw = encrypt_for_id(&existing_id, password)?;
        db.execute(
            &format!("UPDATE {} SET username=?1, password=?2, title=?3, note=?4 WHERE id=?5", COLLECTION),
            params![username, enc_pw, new_title, new_note, existing_id],
        )?;
        return Ok(PasswordRecord {
            id: existing_id,
            url: url.to_string(),
            username: username.to_string(),
            password: enc_pw,
            title: new_title,
            note: new_note,
            created_at,
        });
    }

    // 新規挿入
    let id = uuid::Uuid::new_v4().to_string();
    let rec = PasswordRecord {
        id: id.clone(),
        url: url.to_string(),
        username: username.to_string(),
        password: encrypt_for_id(&id, password)?,
        title: title.map(|s| s.to_string()),
        note: note.map(|s| s.to_string()),
        created_at: Utc::now().to_rfc3339(),
    };
    db.execute(
        &format!(
            "INSERT INTO {} (id, url, username, password, title, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            COLLECTION
        ),
        params![rec.id, rec.url, rec.username, rec.password, rec.title, rec.note, rec.created_at],
    )?;
    Ok(rec)
}

async fn fetch_by_url(db: &Connection, url: &str) -> Result<Vec<(String, String, Option<String>, Option<String>)>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = db.prepare(&format!("SELECT id, username, password, title, note FROM {} WHERE url = ?1", COLLECTION))?;
    let rows = stmt.query_map(params![url], |row| {
        let id: String = row.get(0)?;
        let username: String = row.get(1)?;
        let enc_pw: String = row.get(2)?;
        let title: Option<String> = row.get(3)?;
        let note: Option<String> = row.get(4)?;
        let pw = decrypt_for_id(&id, &enc_pw).unwrap_or(enc_pw);
        Ok((username, pw, title, note))
    })?;
    let mut out = Vec::new();
    for r in rows { out.push(r?); }
    Ok(out)
}

async fn search_entries(db: &Connection, keyword: &str) -> Result<Vec<(String, String, String, String, Option<String>, Option<String>)>, Box<dyn std::error::Error + Send + Sync>> {
    let like = format!("%{}%", keyword);
    let mut stmt = db.prepare(&format!(
        "SELECT id, url, username, password, title, note FROM {} WHERE 
            id LIKE ?1 OR url LIKE ?1 OR username LIKE ?1 OR IFNULL(title,'') LIKE ?1 OR IFNULL(note,'') LIKE ?1 ",
        COLLECTION
    ))?;
    let rows = stmt.query_map(params![like], |row| {
        let id: String = row.get(0)?;
        let url: String = row.get(1)?;
        let username: String = row.get(2)?;
        let enc_pw: String = row.get(3)?;
        let title: Option<String> = row.get(4)?;
        let note: Option<String> = row.get(5)?;
        let pw = decrypt_for_id(&id, &enc_pw).unwrap_or(enc_pw);
        Ok((id, url, username, pw, title, note))
    })?;
    let mut out: Vec<(String, String, String, String, Option<String>, Option<String>)> = Vec::new();
    for r in rows { out.push(r?); }
    // created_at降順の代わりに id 降順で簡易並び替え
    out.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(out)
}

async fn update_entry(
    db: &Connection,
    id: &str,
    url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    title: Option<&str>,
    note: Option<&str>,
) -> Result<PasswordRecord, Box<dyn std::error::Error + Send + Sync>> {
    // 現在のレコードを取得
    let mut stmt = db.prepare(&format!("SELECT id, url, username, password, title, note, created_at FROM {} WHERE id = ?1", COLLECTION))?;
    let mut current: PasswordRecord = stmt
        .query_row(params![id], |row| {
            Ok(PasswordRecord {
                id: row.get(0)?,
                url: row.get(1)?,
                username: row.get(2)?,
                password: row.get(3)?,
                title: row.get(4)?,
                note: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .optional()? // Option<PasswordRecord>
        .ok_or_else(|| format!("id={} が見つかりません", id))?;
    if let Some(v) = url { current.url = v.to_string(); }
    if let Some(v) = username { current.username = v.to_string(); }
    if let Some(v) = password { current.password = encrypt_for_id(&current.id, v)?; }
    if let Some(v) = title { current.title = Some(v.to_string()); }
    if let Some(v) = note { current.note = Some(v.to_string()); }

    db.execute(
        &format!(
            "UPDATE {} SET url=?1, username=?2, password=?3, title=?4, note=?5 WHERE id=?6",
            COLLECTION
        ),
        params![current.url, current.username, current.password, current.title, current.note, id],
    )?;
    Ok(current)
}

async fn delete_entry(db: &Connection, id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    db.execute(&format!("DELETE FROM {} WHERE id = ?1", COLLECTION), params![id])?;
    Ok(())
}

fn print_add_usage_and_exit() {
    eprintln!(
        "使い方: tsupasswd add <url> <username> [password|length] [--title <title>] [--note <note>]"
    );
    std::process::exit(1);
}

fn db_file_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".tsupasswd_db").join("passwords.db")
}

fn export_csv(db: &Connection, path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut wtr = WriterBuilder::new().from_path(path)?;
    // ヘッダー: id,url,username,password,title,note,created_at（passwordは平文で出力）
    wtr.write_record(["id", "url", "username", "password", "title", "note", "created_at"])?;
    let mut stmt = db.prepare(&format!(
        "SELECT id, url, username, password, title, note, created_at FROM {} ORDER BY created_at DESC",
        COLLECTION
    ))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for r in rows {
        let (id, url, username, enc_pw, title, note, created_at) = r?;
        let pw = decrypt_for_id(&id, &enc_pw).unwrap_or(enc_pw);
        wtr.write_record([
            id,
            url,
            username,
            pw,
            title.unwrap_or_default(),
            note.unwrap_or_default(),
            created_at,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

async fn import_csv(db: &Connection, path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut rdr = ReaderBuilder::new().has_headers(true).from_path(path)?;
    let headers = rdr.headers()?.clone();
    for result in rdr.records() {
        let rec = result?; // CSVレコード
        // ヘッダー名で取得（存在しない場合は位置依存でフォールバック）
        let get = |name: &str| headers.iter().position(|h| h == name).and_then(|i| rec.get(i).map(|s| s.to_string()));
        let url = get("url").or_else(|| rec.get(0).map(|s| s.to_string())).ok_or("url がありません")?;
        let username = get("username").or_else(|| rec.get(1).map(|s| s.to_string())).ok_or("username がありません")?;
        let password = get("password").or_else(|| rec.get(2).map(|s| s.to_string())).ok_or("password がありません")?;
        let title = get("title").or_else(|| rec.get(3).map(|s| s.to_string()));
        let note = get("note").or_else(|| rec.get(4).map(|s| s.to_string()));
        // created_at は無視して現在時刻を使用
        let _ = insert_password(db, &url, &username, &password, title.as_deref(), note.as_deref()).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyRecord {
    id: String,
    rp_id: String,
    credential_id: String,
    user_handle: String,
    public_key: String,
    sign_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transports: Option<String>,
    created_at: String,
}

async fn insert_passkey(
    db: &Connection,
    rp_id: &str,
    credential_id: &str,
    user_handle: &str,
    public_key: &str,
    sign_count: i64,
    title: Option<&str>,
    transports: Option<&str>,
) -> Result<PasskeyRecord, Box<dyn std::error::Error + Send + Sync>> {
    let id = uuid::Uuid::new_v4().to_string();
    let rec = PasskeyRecord {
        id: id.clone(),
        rp_id: rp_id.to_string(),
        credential_id: credential_id.to_string(),
        user_handle: user_handle.to_string(),
        public_key: public_key.to_string(),
        sign_count,
        title: title.map(|s| s.to_string()),
        transports: transports.map(|s| s.to_string()),
        created_at: Utc::now().to_rfc3339(),
    };
    db.execute(
        "INSERT INTO passkeys (id, rp_id, credential_id, user_handle, public_key, sign_count, title, transports, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![rec.id, rec.rp_id, rec.credential_id, rec.user_handle, rec.public_key, rec.sign_count, rec.title, rec.transports, rec.created_at],
    )?;
    Ok(rec)
}

async fn get_passkeys_by_user(
    db: &Connection,
    rp_id: &str,
    user_handle: &str,
) -> Result<Vec<PasskeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = db.prepare("SELECT id, rp_id, credential_id, user_handle, public_key, sign_count, title, transports, created_at FROM passkeys WHERE rp_id = ?1 AND user_handle = ?2")?;
    let rows = stmt.query_map(params![rp_id, user_handle], |row| {
        Ok(PasskeyRecord {
            id: row.get(0)?,
            rp_id: row.get(1)?,
            credential_id: row.get(2)?,
            user_handle: row.get(3)?,
            public_key: row.get(4)?,
            sign_count: row.get(5)?,
            title: row.get(6)?,
            transports: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows { out.push(r?); }
    Ok(out)
}

async fn search_passkeys(
    db: &Connection,
    keyword: &str,
) -> Result<Vec<PasskeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let like = format!("%{}%", keyword);
    let mut stmt = db.prepare(
        "SELECT id, rp_id, credential_id, user_handle, public_key, sign_count, title, transports, created_at FROM passkeys \
         WHERE id LIKE ?1 OR rp_id LIKE ?1 OR credential_id LIKE ?1 OR user_handle LIKE ?1 OR IFNULL(title,'') LIKE ?1 OR IFNULL(transports,'') LIKE ?1",
    )?;
    let rows = stmt.query_map(params![like], |row| {
        Ok(PasskeyRecord {
            id: row.get(0)?,
            rp_id: row.get(1)?,
            credential_id: row.get(2)?,
            user_handle: row.get(3)?,
            public_key: row.get(4)?,
            sign_count: row.get(5)?,
            title: row.get(6)?,
            transports: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows { out.push(r?); }
    out.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(out)
}

async fn delete_passkey(db: &Connection, id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let n = db.execute("DELETE FROM passkeys WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(format!("id={} が見つかりません", id).into());
    }
    Ok(())
}

fn export_passkeys_csv(db: &Connection, path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut wtr = WriterBuilder::new().from_path(path)?;
    wtr.write_record(["id", "rp_id", "credential_id", "user_handle", "public_key", "sign_count", "title", "transports", "created_at"])?;
    let mut stmt = db.prepare("SELECT id, rp_id, credential_id, user_handle, public_key, sign_count, title, transports, created_at FROM passkeys ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;
    for r in rows {
        let (id, rp_id, credential_id, user_handle, public_key, sign_count, title, transports, created_at) = r?;
        wtr.write_record([
            id,
            rp_id,
            credential_id,
            user_handle,
            public_key,
            sign_count.to_string(),
            title.unwrap_or_default(),
            transports.unwrap_or_default(),
            created_at,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

async fn import_passkeys_csv(db: &Connection, path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut rdr = ReaderBuilder::new().has_headers(true).from_path(path)?;
    let headers = rdr.headers()?.clone();
    for result in rdr.records() {
        let rec = result?;
        let get = |name: &str| headers.iter().position(|h| h == name).and_then(|i| rec.get(i).map(|s| s.to_string()));
        let rp_id = get("rp_id").or_else(|| rec.get(0).map(|s| s.to_string())).ok_or("rp_id がありません")?;
        let credential_id = get("credential_id").or_else(|| rec.get(1).map(|s| s.to_string())).ok_or("credential_id がありません")?;
        let user_handle = get("user_handle").or_else(|| rec.get(2).map(|s| s.to_string())).ok_or("user_handle がありません")?;
        let public_key = get("public_key").or_else(|| rec.get(3).map(|s| s.to_string())).ok_or("public_key がありません")?;
        let sign_count = get("sign_count").or_else(|| rec.get(4).map(|s| s.to_string())).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
        // title は6番目（インデックス5）想定（なければNone）
        let title = get("title").or_else(|| rec.get(5).map(|s| s.to_string()));
        let transports = get("transports").or_else(|| rec.get(6).map(|s| s.to_string()));
        let _ = insert_passkey(db, &rp_id, &credential_id, &user_handle, &public_key, sign_count, title.as_deref(), transports.as_deref()).await?;
    }
    Ok(())
}

fn derive_key_for_id(id: &str) -> Result<[u8; 32], String> {
    let secret = env::var("AUTH_SECRET").map_err(|_| "環境変数 AUTH_SECRET が未設定です".to_string())?;
    let hk = Hkdf::<Sha256>::new(Some(id.as_bytes()), secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"password-at-rest", &mut okm).map_err(|_| "鍵導出に失敗しました".to_string())?;
    Ok(okm)
}

fn encrypt_for_id(id: &str, plaintext: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let key_bytes = derive_key_for_id(id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| format!("cipher init error: {}", e))?;
    let mut nonce = [0u8; 12];
    // ランダムノンス
    let rnd = OsRng.next_u64();
    // 12バイトに充填（u64 + u32）
    nonce[..8].copy_from_slice(&rnd.to_le_bytes());
    nonce[8..].copy_from_slice(&(OsRng.next_u32()).to_le_bytes());
    let ct = cipher
        .encrypt((&nonce).into(), plaintext.as_bytes())
        .map_err(|e| format!("encrypt error: {}", e))?;
    let mut buf = Vec::with_capacity(12 + ct.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ct);
    Ok(B64.encode(buf))
}

fn decrypt_for_id(id: &str, b64: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let data = B64.decode(b64)?;
    if data.len() < 12 { return Err("データ長が不正です".into()); }
    let (nonce, ct) = data.split_at(12);
    let key_bytes = derive_key_for_id(id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| format!("cipher init error: {}", e))?;
    let pt = cipher
        .decrypt(nonce.into(), ct)
        .map_err(|e| format!("decrypt error: {}", e))?;
    Ok(String::from_utf8(pt).unwrap_or_default())
}
