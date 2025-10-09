use std::env;
use rusqlite::{params, Connection};
use rand::rngs::OsRng;
use rand::RngCore;

fn main() {
    // CLI:
    // - `password` -> デフォルト16文字のパスワードを出力
    // - `password 24` -> 指定長のパスワードを出力
    // - `password add <url> <user> [password|length] [--title <title>] [--note <note>]` -> DBに保存
    // - `password get <url>` -> URLで検索してユーザID/パスワード/タイトル/備考を取得
    // - `password search <keyword>` -> 部分一致で検索（url/username/title/note）しID付きで一覧
    // - `password update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]` -> レコード更新
    // - `password delete <id>` -> レコード削除
    let mut args = env::args();
    let _prog = args.next();
    match args.next().as_deref() {
        Some("add") => {
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

            match init_db() {
                Ok(conn) => {
                    if let Err(e) = insert_password(&conn, &url, &username, &password, title.as_deref(), note.as_deref()) {
                        eprintln!("保存に失敗しました: {}", e);
                        std::process::exit(1);
                    } else {
                        println!("保存しました: url={} user={}", url, username);
                    }
                }
                Err(e) => {
                    eprintln!("DB初期化に失敗しました: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("get") => {
            let url = match args.next() { Some(v) => v, None => {
                eprintln!("使い方: password get <url>");
                std::process::exit(1);
            }};
            match init_db() {
                Ok(conn) => match fetch_by_url(&conn, &url) {
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
                    Err(e) => {
                        eprintln!("検索に失敗しました: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("DB初期化に失敗しました: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("search") => {
            let keyword = match args.next() { Some(v) => v, None => {
                eprintln!("使い方: password search <keyword>");
                std::process::exit(1);
            }};
            match init_db() {
                Ok(conn) => match search_entries(&conn, &keyword) {
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
                    Err(e) => {
                        eprintln!("検索に失敗しました: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("DB初期化に失敗しました: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("update") => {
            let id: i64 = match args.next().and_then(|s| s.parse::<i64>().ok()) {
                Some(v) => v,
                None => {
                    eprintln!("使い方: password update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]");
                    std::process::exit(1);
                }
            };
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
            match init_db() {
                Ok(conn) => {
                    if let Err(e) = update_entry(&conn, id, new_url.as_deref(), new_user.as_deref(), new_password.as_deref(), title.as_deref(), note.as_deref()) {
                        eprintln!("更新に失敗しました: {}", e);
                        std::process::exit(1);
                    } else {
                        println!("更新しました: id={}", id);
                    }
                }
                Err(e) => {
                    eprintln!("DB初期化に失敗しました: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("delete") => {
            let id: i64 = match args.next().and_then(|s| s.parse::<i64>().ok()) {
                Some(v) => v,
                None => {
                    eprintln!("使い方: password delete <id>");
                    std::process::exit(1);
                }
            };
            match init_db() {
                Ok(conn) => {
                    if let Err(e) = delete_entry(&conn, id) {
                        eprintln!("削除に失敗しました: {}", e);
                        std::process::exit(1);
                    } else {
                        println!("削除しました: id={}", id);
                    }
                }
                Err(e) => {
                    eprintln!("DB初期化に失敗しました: {}", e);
                    std::process::exit(1);
                }
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

fn init_db() -> rusqlite::Result<Connection> {
    let conn = Connection::open("passwords.db")?;
    // 新スキーマ（title, noteを追加）でCREATE。既存DBには後続のALTERで対応。
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            title TEXT,
            note TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        [],
    )?;

    // 既存DBへの後方互換: 欠けている列を追加（エラーは無視して続行）
    let _ = conn.execute("ALTER TABLE passwords ADD COLUMN title TEXT", []);
    let _ = conn.execute("ALTER TABLE passwords ADD COLUMN note TEXT", []);
    Ok(conn)
}

fn insert_password(
    conn: &Connection,
    url: &str,
    username: &str,
    password: &str,
    title: Option<&str>,
    note: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO passwords (url, username, password, title, note) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![url, username, password, title.unwrap_or(""), note.unwrap_or("")],
    )?;
    Ok(())
}

fn fetch_by_url(conn: &Connection, url: &str) -> rusqlite::Result<Vec<(String, String, Option<String>, Option<String>)>> {
    let mut stmt = conn.prepare(
        "SELECT username, password, NULLIF(title, ''), NULLIF(note, '')
         FROM passwords
         WHERE url = ?1
         ORDER BY created_at DESC, id DESC",
    )?;
    let rows = stmt.query_map(params![url], |row| {
        let u: String = row.get(0)?;
        let p: String = row.get(1)?;
        let t: Option<String> = row.get(2)?;
        let n: Option<String> = row.get(3)?;
        Ok((u, p, t, n))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn search_entries(conn: &Connection, keyword: &str) -> rusqlite::Result<Vec<(i64, String, String, Option<String>, Option<String>)>> {
    let like = format!("%{}%", keyword);
    let mut stmt = conn.prepare(
        "SELECT id, url, username, NULLIF(title, ''), NULLIF(note, '')
         FROM passwords
         WHERE url LIKE ?1 OR username LIKE ?1 OR title LIKE ?1 OR note LIKE ?1
         ORDER BY created_at DESC, id DESC",
    )?;
    let rows = stmt.query_map(params![like], |row| {
        let id: i64 = row.get(0)?;
        let url: String = row.get(1)?;
        let user: String = row.get(2)?;
        let title: Option<String> = row.get(3)?;
        let note: Option<String> = row.get(4)?;
        Ok((id, url, user, title, note))
    })?;
    let mut out = Vec::new();
    for r in rows { out.push(r?); }
    Ok(out)
}

fn update_entry(
    conn: &Connection,
    id: i64,
    url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    title: Option<&str>,
    note: Option<&str>,
) -> rusqlite::Result<()> {
    // 動的にSET句を構築
    let mut sets: Vec<&str> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();
    if let Some(v) = url { sets.push("url = ?"); bind_values.push(v.to_string()); }
    if let Some(v) = username { sets.push("username = ?"); bind_values.push(v.to_string()); }
    if let Some(v) = password { sets.push("password = ?"); bind_values.push(v.to_string()); }
    if let Some(v) = title { sets.push("title = ?"); bind_values.push(v.to_string()); }
    if let Some(v) = note { sets.push("note = ?"); bind_values.push(v.to_string()); }
    let sql = format!("UPDATE passwords SET {} WHERE id = ?", sets.join(", "));

    let mut stmt = conn.prepare(&sql)?;
    // 参照のライフタイムを満たすため、まず所有するStringを保持し、その参照を束ねる
    let mut bind_refs: Vec<&dyn rusqlite::ToSql> = Vec::new();
    for v in &bind_values {
        bind_refs.push(v as &dyn rusqlite::ToSql);
    }
    bind_refs.push(&id);
    stmt.execute(rusqlite::params_from_iter(bind_refs))?;
    Ok(())
}

fn delete_entry(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM passwords WHERE id = ?1", params![id])?;
    Ok(())
}

fn print_add_usage_and_exit() {
    eprintln!(
        "使い方: password add <url> <user> [password|length] [--title <title>] [--note <note>]"
    );
    std::process::exit(1);
}
