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

#[tokio::main]
async fn main() {
    // CLI:
    // - `password` -> デフォルト16文字のパスワードを出力
    // - `password 24` -> 指定長のパスワードを出力
    // - `password add <url> <user> [password|length] [--title <title>] [--note <note>]` -> DBに保存
    // - `password get <url>` -> URLで検索してユーザID/パスワード/タイトル/備考を取得
    // - `password search <keyword>` -> 部分一致で検索（url/username/title/note）しID付きで一覧
    // - `password update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]` -> レコード更新（idはFirestoreのドキュメントID）
    // - `password delete <id>` -> レコード削除（idはFirestoreのドキュメントID）
    // Rustls 0.23+: 明示的に CryptoProvider をインストール（結果は無視）
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = env::args();
    let _prog = args.next();
    match args.next().as_deref() {
        Some("export") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let path = match args.next() { Some(v) => v, None => { eprintln!("使い方: password export <csv_path>"); std::process::exit(1);} };
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
            let path = match args.next() { Some(v) => v, None => { eprintln!("使い方: password import <csv_path>"); std::process::exit(1);} };
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            if let Err(e) = import_csv(&db, &path).await {
                eprintln!("インポートに失敗しました: {}", e);
                std::process::exit(1);
            } else {
                println!("インポート完了: {}", path);
            }
        }
        Some("auth") => {
            let secret = match args.next() { Some(v) => v, None => { eprintln!("使い方: password auth <secret> [--ttl MINUTES]"); std::process::exit(1);} };
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
            match session_status() {
                Ok(Some(rem)) => println!("認証済み: 残り {} 秒", rem),
                Ok(None) => { eprintln!("未認証です"); std::process::exit(1); }
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
                println!("保存しました: url={} user={}", url, username);
            }
        }
        Some("get") => {
            if let Err(msg) = ensure_authenticated() { eprintln!("{}", msg); std::process::exit(1); }
            let url = match args.next() { Some(v) => v, None => {
                eprintln!("使い方: password get <url>");
                std::process::exit(1);
            }};
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            match fetch_by_url(&db, &url).await {
                Ok(entries) => {
                        if entries.is_empty() {
                            eprintln!("見つかりませんでした: url={}", url);
                            std::process::exit(1);
                        } else {
                            for (username, password, title, note) in entries {
                                // タイトル/備考は存在する場合のみ表示
                                match (title.as_deref(), note.as_deref()) {
                                    (Some(t), Some(n)) => println!("user=\"{}\" password=\"{}\" title=\"{}\" note=\"{}\"", username, password, t, n),
                                    (Some(t), None) => println!("user=\"{}\" password=\"{}\" title=\"{}\"", username, password, t),
                                    (None, Some(n)) => println!("user=\"{}\" password=\"{}\" note=\"{}\"", username, password, n),
                                    (None, None) => println!("user=\"{}\" password=\"{}\"", username, password),
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
                eprintln!("使い方: password search <keyword>");
                std::process::exit(1);
            }};
            let db = match init_db().await { Ok(db) => db, Err(e) => { eprintln!("DB初期化に失敗しました: {}", e); std::process::exit(1);} };
            match search_entries(&db, &keyword).await {
                Ok(entries) => {
                        if entries.is_empty() {
                            eprintln!("見つかりませんでした: keyword={}", keyword);
                            std::process::exit(1);
                        } else {
                            for (id, url, username, title, note) in entries {
                                match (title.as_deref(), note.as_deref()) {
                                    (Some(t), Some(n)) => println!("id={} url=\"{}\" user=\"{}\" title=\"{}\" note=\"{}\"", id, url, username, t, n),
                                    (Some(t), None) => println!("id={} url=\"{}\" user=\"{}\" title=\"{}\"", id, url, username, t),
                                    (None, Some(n)) => println!("id={} url=\"{}\" user=\"{}\" note=\"{}\"", id, url, username, n),
                                    (None, None) => println!("id={} url=\"{}\" user=\"{}\"", id, url, username),
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
const SYMBOL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/"; // スペースやバックスラッシュ、`'"` は除外

fn generate_password(len: usize) -> String {
    // 総合アルファベット
    let mut alphabet: Vec<u8> = Vec::with_capacity(UPPER.len() + LOWER.len() + DIGIT.len() + SYMBOL.len());
    alphabet.extend_from_slice(UPPER);
    alphabet.extend_from_slice(LOWER);
    alphabet.extend_from_slice(DIGIT);
    alphabet.extend_from_slice(SYMBOL);

    if len == 0 {
        return String::new();
    }

    // 少なくとも各カテゴリから1文字ずつ確保（ただし必要な長さを超えない）
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    for cat in [UPPER, LOWER, DIGIT, SYMBOL] {
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
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".password_cli").join("session")
}

fn ensure_authenticated() -> Result<(), String> {
    match session_status() {
        Ok(Some(rem)) => {
            if rem <= 0 { Err("セッションが期限切れです。`password auth <secret>` を実行してください".to_string()) } else { Ok(()) }
        }
        Ok(None) => Err("未認証です。`password auth <secret>` を実行してください".to_string()),
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
        &format!("INSERT INTO {} (id, url, username, password, title, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", COLLECTION),
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

async fn search_entries(db: &Connection, keyword: &str) -> Result<Vec<(String, String, String, Option<String>, Option<String>)>, Box<dyn std::error::Error + Send + Sync>> {
    let like = format!("%{}%", keyword);
    let mut stmt = db.prepare(&format!(
        "SELECT id, url, username, title, note FROM {} WHERE 
            id LIKE ?1 OR url LIKE ?1 OR username LIKE ?1 OR IFNULL(title,'') LIKE ?1 OR IFNULL(note,'') LIKE ?1 ",
        COLLECTION
    ))?;
    let rows = stmt.query_map(params![like], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut out: Vec<(String, String, String, Option<String>, Option<String>)> = Vec::new();
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
        "使い方: password add <url> <user> [password|length] [--title <title>] [--note <note>]"
    );
    std::process::exit(1);
}

fn db_file_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".password_cli").join("passwords.db")
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
