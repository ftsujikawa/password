use std::env;
use rand::rngs::OsRng;
use rand::RngCore;
use firestore::*;
use serde::{Deserialize, Serialize};
use chrono::Utc;

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

const COLLECTION: &str = "passwords";

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

async fn init_db() -> Result<FirestoreDb, Box<dyn std::error::Error + Send + Sync>> {
    let project_id = std::env::var("PROJECT_ID")?;
    let db = FirestoreDb::new(&project_id).await?;
    Ok(db)
}

async fn insert_password(
    db: &FirestoreDb,
    url: &str,
    username: &str,
    password: &str,
    title: Option<&str>,
    note: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let id = uuid::Uuid::new_v4().to_string();
    let rec = PasswordRecord {
        id: id.clone(),
        url: url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        title: title.map(|s| s.to_string()),
        note: note.map(|s| s.to_string()),
        created_at: Utc::now().to_rfc3339(),
    };
    db.fluent()
        .insert()
        .into(COLLECTION)
        .document_id(&id)
        .object(&rec)
        .execute()
        .await?;
    Ok(())
}

async fn fetch_by_url(db: &FirestoreDb, url: &str) -> Result<Vec<(String, String, Option<String>, Option<String>)>, Box<dyn std::error::Error + Send + Sync>> {
    use futures::StreamExt;
    let mut stream = db
        .fluent()
        .select()
        .from(COLLECTION)
        .filter(|q| q.for_all([q.field(path!(PasswordRecord::url)).eq(url)]))
        .obj()
        .stream_query()
        .await?;
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        let rec: PasswordRecord = item?;
        out.push((rec.username, rec.password, rec.title, rec.note));
    }
    Ok(out)
}

async fn search_entries(db: &FirestoreDb, keyword: &str) -> Result<Vec<(String, String, String, Option<String>, Option<String>)>, Box<dyn std::error::Error + Send + Sync>> {
    use futures::StreamExt;
    // 全件ストリームを取得してクライアント側で部分一致フィルタ
    let mut stream = db
        .fluent()
        .select()
        .from(COLLECTION)
        .obj()
        .stream_query()
        .await?;
    let kw = keyword.to_lowercase();
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        let rec: PasswordRecord = item?;
        let hay = format!("{}\n{}\n{}\n{}\n{}", rec.url, rec.username, rec.title.clone().unwrap_or_default(), rec.note.clone().unwrap_or_default(), rec.id);
        if hay.to_lowercase().contains(&kw) {
            out.push((rec.id, rec.url, rec.username, rec.title, rec.note));
        }
    }
    // created_at降順にしたいが、ここではクライアント側で簡易に並び替え
    out.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(out)
}

async fn update_entry(
    db: &FirestoreDb,
    id: &str,
    url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    title: Option<&str>,
    note: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 現在のドキュメントを取得
    let mut current: PasswordRecord = match db
        .fluent()
        .select()
        .by_id_in(COLLECTION)
        .obj()
        .one(id)
        .await? {
            Some(v) => v,
            None => { return Err(format!("id={} が見つかりません", id).into()); }
        };
    if let Some(v) = url { current.url = v.to_string(); }
    if let Some(v) = username { current.username = v.to_string(); }
    if let Some(v) = password { current.password = v.to_string(); }
    if let Some(v) = title { current.title = Some(v.to_string()); }
    if let Some(v) = note { current.note = Some(v.to_string()); }

    db.fluent()
        .update()
        .in_col(COLLECTION)
        .document_id(id)
        .object(&current)
        .execute()
        .await?;
    Ok(())
}

async fn delete_entry(db: &FirestoreDb, id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    db.fluent()
        .delete()
        .from(COLLECTION)
        .document_id(id)
        .execute()
        .await?;
    Ok(())
}

fn print_add_usage_and_exit() {
    eprintln!(
        "使い方: password add <url> <user> [password|length] [--title <title>] [--note <note>]"
    );
    std::process::exit(1);
}
