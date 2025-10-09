# 仕様書: パスワード生成・保存・取得CLI

## 概要
- 本ツールはコマンドラインから安全なパスワードを生成し、SQLiteに「URL・ユーザID・パスワード」を1組として保存・取得できるユーティリティです。さらに、各レコードに任意の**タイトル(title)**と**備考(note)**を付与できます。
- 主要機能
  - **パスワード生成**: 乱数で安全なパスワードを出力
  - **保存**: 生成または手動指定のパスワードをSQLiteへ保存（タイトル/備考付き）
  - **取得**: URLを指定してユーザID・パスワード・タイトル・備考を取得

## 対象ファイル・構成
- プロジェクトルート: `password/`
  - 依存設定: `Cargo.toml`
  - 実装: `src/main.rs`
  - DBファイル: `passwords.db`（プロジェクト直下に自動生成）

## 依存関係
- `Cargo.toml` の `[dependencies]`
  - `rand = "0.8"`（安全な乱数生成）
  - `rusqlite = { version = "0.31", features = ["bundled"] }`（SQLiteバンドル）

## コマンド仕様
- 実行形式: `cargo run -- [コマンド|引数]`
- コマンド一覧
  - **デフォルト生成**
    - 仕様: 長さ16のパスワードを生成して標準出力
    - 使用例: `cargo run`
  - **長さ指定生成**
    - 仕様: 指定長さのパスワードを生成して標準出力
    - 引数: `<length: usize>`
    - 使用例: `cargo run -- 24`
  - **保存（add）**
    - 仕様: URL・ユーザIDとともにパスワードをDBへ保存。任意でタイトル/備考も付与
    - 形式: `add <url> <user> [password|length] [--title <title>] [--note <note>]`
      - 第3引数未指定: 長さ16で自動生成
      - 第3引数が数値: 指定長で生成
      - 第3引数が文字列: その文字列をそのまま保存
    - 使用例:
      - `cargo run -- add https://example.com alice`
      - `cargo run -- add https://example.com alice 24 --title "Example" --note "メインアカウント"`
      - `cargo run -- add https://example.com alice "S3cure!Pass" --title "社内用"`
  - **取得（get）**
    - 仕様: URLで検索し、ユーザID・パスワード・タイトル・備考を取得して出力
    - 形式: `get <url>`
    - 出力: `user="<user>" password="<password>" [title="<title>"] [note="<note>"]`
    - 使用例: `cargo run -- get https://example.com`
  - **部分一致検索（search）**
    - 仕様: `url`/`username`/`title`/`note` のいずれかにキーワードが部分一致するレコードを検索し、IDとともに一覧表示
    - 形式: `search <keyword>`
    - 出力例: `id=12 url="https://example.com" user="alice" title="Example" note="メインアカウント"`
    - 使用例: `cargo run -- search example`
  - **更新（update）**
    - 仕様: 指定した `id` のレコードを部分更新
    - 形式: `update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]`
    - 備考: `--length` 指定時は新しいパスワードを生成して更新
    - 使用例: `cargo run -- update 12 --password "N3w!Pass" --title "Private"`
  - **削除（delete）**
    - 仕様: 指定した `id` のレコードを削除
    - 形式: `delete <id>`
    - 使用例: `cargo run -- delete 12`

## 振る舞い・出力例
- 生成のみ
  - 入力: `cargo run -- 16`
  - 出力例: `9;D?I!kD@_?HMyE,`
- 保存
  - 入力: `cargo run -- add www.example user01`
  - 出力: `保存しました: url=www.example user=user01`
- 取得
  - 入力: `cargo run -- get www.example`
  - 出力例（複数件ある場合は新しい順で複数行出力）:
    - `user="user01" password="S3cure!Pass"`

## 実装詳細（関数・処理）
- ファイル: `src/main.rs`
  - CLI分岐: `main()`
    - `add`/`get`/数値（長さ）/未指定の分岐を実装。
    - `add`は `--title`/`--note` オプションを受け付ける。
    - `search`/`update`/`delete` を追加。
  - パスワード生成: `generate_password(len: usize) -> String`
    - 文字集合:
      - `UPPER`: `A-Z`
      - `LOWER`: `a-z`
      - `DIGIT`: `0-9`
      - `SYMBOL`: `!@#$%^&*()-_=+[]{};:,.?/`
        - 扱いにくい文字（空白、バックスラッシュ、各種クォート等）は除外
    - 生成ポリシー:
      - `len == 0` は空文字
      - 各カテゴリから最低1文字ずつ確保（ただし`len`未満なら超過しない）
      - 残りは全体集合からランダムに補充
      - 最後にFisher-Yatesでシャッフル
    - 乱数源: `rand::rngs::OsRng` を用いたリジェクションサンプリング（偏り防止）
  - DB初期化: `init_db() -> rusqlite::Result<Connection>`
    - DBファイル: `passwords.db`
    - テーブル自動生成: `passwords`
      - スキーマは後述
  - 保存: `insert_password(conn, url, username, password, title, note) -> rusqlite::Result<()>`
    - `INSERT INTO passwords (url, username, password, title, note) VALUES (?1, ?2, ?3, ?4, ?5)`
  - 取得: `fetch_by_url(conn, url) -> rusqlite::Result<Vec<(String, String, Option<String>, Option<String>)>>`
    - `SELECT username, password, NULLIF(title, ''), NULLIF(note, '') FROM passwords WHERE url = ?1 ORDER BY created_at DESC, id DESC`
  - 部分一致検索: `search_entries(conn, keyword) -> rusqlite::Result<Vec<(i64, String, String, Option<String>, Option<String>)>>`
    - `SELECT id, url, username, NULLIF(title, ''), NULLIF(note, '') FROM passwords WHERE url LIKE ?1 OR username LIKE ?1 OR title LIKE ?1 OR note LIKE ?1 ORDER BY created_at DESC, id DESC`
  - 更新: `update_entry(conn, id, url, username, password, title, note) -> rusqlite::Result<()>`
    - 動的に`SET`句を組み立て、指定されたフィールドのみ更新
  - 削除: `delete_entry(conn, id) -> rusqlite::Result<()>`
  - エラーメッセージ表示・終了:
    - 失敗時は標準エラー出力にメッセージを出し、`exit(1)` で終了
    - 使用例ヘルプ: `print_add_usage_and_exit()`（`--title`/`--note`を含む）

## データベース仕様
- DBファイル: `passwords.db`
- テーブル: `passwords`
  - `id INTEGER PRIMARY KEY AUTOINCREMENT`
  - `url TEXT NOT NULL`
  - `username TEXT NOT NULL`
  - `password TEXT NOT NULL`
  - `title TEXT`（任意）
  - `note TEXT`（任意）
  - `created_at TEXT NOT NULL DEFAULT (datetime('now'))`
- インデックス: なし（必要に応じて `url` へ追加可能）

## セキュリティ方針
- 乱数: `OsRng`（OSのCSPRNG）を使用
- 生成アルゴリズム:
  - カテゴリ混在を保障（可能な範囲）
  - リジェクションサンプリングで指数バイアスの回避
  - シャッフルで先頭固定回避
- 現状は**平文保存・平文表示**。運用環境では暗号化やキーチェーン連携を推奨（拡張案参照）。

## エラーハンドリング・終了コード
- 正常終了: `0`
- エラー終了: `1`
  - DB初期化失敗、保存失敗、取得失敗、見つからない、引数不足など

## 制限事項・既知の注意点
- パスワードの暗号化保存は未対応
- URL完全一致検索（部分一致は未実装）
- 複数アカウントが同一URLに紐づく場合、**新しい順**に複数行を出力
- `SYMBOL`に含まれない記号が必要な場合は `SYMBOL` を編集

## 拡張案
- **暗号化保存**: マスターキー、OSキーチェーン、libsodium/age等の採用
- **検索拡張**: LIKE検索、ユーザID指定検索、一覧（`list`）
- **更新/削除**: `update`/`delete` サブコマンドの追加
- **出力形式**: JSON/CSV出力、パイプ連携
- **バリデーション**: パスワード強度検査、URL/ユーザIDの検証
- **インデックス**: `url` へのインデックス追加で検索高速化

## 関連シンボル（参照）
- 関数: `main()`, `generate_password()`, `init_db()`, `insert_password()`, `fetch_by_url()`, `print_add_usage_and_exit()`
- ファイル:
  - 実装: `src/main.rs`
  - 依存: `Cargo.toml`
  - DB: `passwords.db`

## テスト例（手動）
- 生成: `cargo run -- 20`
- 保存（自動生成）: `cargo run -- add https://example.com alice`
- 保存（長さ指定）: `cargo run -- add https://example.com alice 30`
- 保存（手動）: `cargo run -- add https://example.com alice "S3cure!Pass"`
- 取得: `cargo run -- get https://example.com`
 - 検索: `cargo run -- search example`
 - 更新: `cargo run -- update 1 --length 24 --title "Rotated"`
 - 削除: `cargo run -- delete 1`
