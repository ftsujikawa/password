# 仕様書: パスワード生成・保存・取得CLI

## 概要
- 本ツールはコマンドラインから安全なパスワードを生成し、SQLiteに「URL・ユーザID・パスワード」を1組として保存・取得できるユーティリティです。さらに、各レコードに任意の**タイトル(title)**と**備考(note)**を付与できます。
- 併せて、**パスキー(passkey)** 情報（`rp_id`/`credential_id`/`user_handle`/`public_key`/`sign_count`/`transports`）の保存・検索・削除・CSV入出力にも対応します。
- すべての機密操作はセッション認証が必要です（`tsupasswd auth <secret>`）。

## 対象ファイル・構成
- プロジェクトルート: `password/`
  - 依存設定: `Cargo.toml`
  - 実装: `src/main.rs`
  - DBファイル: `~/.password_cli/passwords.db`（`HOME` 配下に自動生成）
  - セッションファイル: `~/.password_cli/session`（有効期限UNIX秒を保存）

## 依存関係
- `Cargo.toml` の `[dependencies]`
  - `rand = "0.8"`
  - `tokio = { version = "1", features = ["full"] }`
  - `serde = { version = "1", features = ["derive"] }`
  - `chrono = "0.4"`
  - `futures = "0.3"`
  - `uuid = { version = "1", features = ["v4"] }`
  - `rustls = { version = "0.23", features = ["ring"] }`
  - `rusqlite = { version = "0.31" }`
  - `chacha20poly1305 = { version = "0.10", features = ["rand_core"] }`
  - `hkdf = "0.12"`, `sha2 = "0.10"`, `base64 = "0.22"`, `csv = "1.3"`
  - `serde_json = "1"`（`--json` 出力用）
  - （開発用）`assert_cmd`, `predicates`, `tempfile`

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
  - **認証（auth）**
    - 仕様: セッションを開始し、期限（分）を設定
    - 形式: `auth <secret> [--ttl MINUTES]`
    - 使用例: `cargo run -- auth $AUTH_SECRET --ttl 30`
  - **ログアウト（logout）**
    - 仕様: セッションファイルを削除
    - 使用例: `cargo run -- logout`
  - **状態（status）**
    - 仕様: 残り有効秒数を表示
    - 使用例: `cargo run -- status`
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
    - 形式: `get <url> [--json]`
    - 出力:
      - 既定: `user="<user>" password="<password>" [title="<title>"] [note="<note>"]`
      - `--json`: JSON配列（各要素が1レコード）
    - 使用例:
      - `cargo run -- get https://example.com`
      - `cargo run -- get https://example.com --json`
  - **部分一致検索（search）**
    - 仕様: `url`/`username`/`title`/`note` のいずれかにキーワードが部分一致するレコードを検索し、IDとともに一覧表示
    - 形式: `search <keyword> [--json]`
    - 出力:
      - 既定: `id=<id> url="<url>" user="<user>" [title="<title>"] [note="<note>"]`
      - `--json`: JSON配列（各要素が1レコード）
    - 使用例:
      - `cargo run -- search example`
      - `cargo run -- search example --json`
  - **更新（update）**
    - 仕様: 指定した `id` のレコードを部分更新
    - 形式: `update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]`
    - 備考: `--length` 指定時は新しいパスワードを生成して更新
    - 使用例: `cargo run -- update 12 --password "N3w!Pass" --title "Private"`
  - **削除（delete）**
    - 仕様: 指定した `id` のレコードを削除
    - 形式: `delete <id>`
    - 使用例: `cargo run -- delete 12`
  - **エクスポート（export）**
    - 仕様: `passwords` テーブルをCSVへ出力（パスワードは復号して平文で出力）
    - 形式: `export <csv_path>`
    - 使用例: `cargo run -- export ./passwords.csv`
  - **インポート（import）**
    - 仕様: `passwords` レコードをCSVから取り込み（`created_at` は現在時刻）
    - 形式: `import <csv_path>`
    - 使用例: `cargo run -- import ./passwords.csv`
  - **パスキー（passkey サブコマンド）**
    - `passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV]`
    - `passkey get <rp_id> <user_handle> [--json]`
    - `passkey search <keyword> [--json]`
    - `passkey delete <id>`
    - `passkey export <csv_path>`
    - `passkey import <csv_path>`
    - 出力例（get/search）:
      - `id=<ID> rp_id="example.com" credential_id="cred-123" user_handle="user-abc" sign_count=42 transports="usb,nfc"`

### ヘルプ表示（--help/-h/help）

`tsupasswd --help` などで、全コマンド・サブコマンドと主要オプションを一覧表示します。

```
使い方:
  tsupasswd [長さ]
  tsupasswd add <url> <username> [password|length] [--title <title>] [--note <note>]
  tsupasswd get <url> [--json]
  tsupasswd search <keyword> [--json]
  tsupasswd update <id> [--url U] [--user NAME] [--password PASS | --length N] [--title T] [--note N]
  tsupasswd delete <id>
  tsupasswd export <csv_path>
  tsupasswd import <csv_path>
  tsupasswd auth <secret> [--ttl MINUTES]
  tsupasswd logout
  tsupasswd status
  tsupasswd passkey add <rp_id> <credential_id> <user_handle> <public_key> [--sign-count N] [--transports CSV]
  tsupasswd passkey get <rp_id> <user_handle> [--json]
  tsupasswd passkey search <keyword> [--json]
  tsupasswd passkey delete <id>
  tsupasswd passkey export <csv_path>
  tsupasswd passkey import <csv_path>

共通オプション:
  -h, --help    このヘルプを表示

コマンド詳細の主なオプション:
  add:     --title <title>, --note <note>
  get:     --json
  search:  --json
  update:  --url U, --user NAME, --password PASS | --length N, --title T, --note N
  auth:    --ttl MINUTES
  passkey add: --sign-count N, --transports CSV
  passkey get/search: --json

環境変数:
  AUTH_SECRET        認証用シークレット（tsupasswd auth で使用）
  TSUPASSWD_ENCODING 出力エンコーディング（utf8 / sjis）。Windowsのリダイレクト/パイプ時に有効
```

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
    - `username="user01" password="S3cure!Pass"`
 - パスキー取得
   - 入力: `cargo run -- passkey get example.com user-abc`
   - 出力例: `id=<ID> rp_id="example.com" credential_id="cred-123" user_handle="user-abc" sign_count=42 transports="usb,nfc"`

## 実装詳細（関数・処理）
- ファイル: `src/main.rs`
  - CLI分岐: `main()`
    - `auth`/`logout`/`status` によるセッション管理。
    - `add`/`get`/`search`/`update`/`delete`/`export`/`import`（パスワード用）。
    - `passkey` サブコマンド群: `add`/`get`/`search`/`delete`/`export`/`import`。
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
  - DB初期化: `init_db()`
    - DBファイル: `~/.password_cli/passwords.db`
    - テーブル自動生成: `passwords`, `passkeys`
  - パスワード保存: `insert_password()`
    - 保存時に `encrypt_for_id(id, password)` を用いて暗号化して格納
  - 取得: `fetch_by_url()`
    - 取得時に `decrypt_for_id(id, enc_pw)` で復号（失敗時は暗号文のまま出力）
  - 検索: `search_entries()`（`id/url/username/title/note` の部分一致）
  - 更新: `update_entry()`（指定項目のみ更新、パスワードは再暗号化）
  - 削除: `delete_entry()`
  - CSV: `export_csv()` / `import_csv()`（パスワードはCSVでは平文）
  - パスキー: `insert_passkey()` / `get_passkeys_by_user()` / `search_passkeys()` / `delete_passkey()` / `export_passkeys_csv()` / `import_passkeys_csv()`
  - エラーメッセージ表示・終了:
    - 失敗時は標準エラー出力にメッセージを出し、`exit(1)` で終了
    - 使用例ヘルプ: `print_add_usage_and_exit()`（`--title`/`--note`を含む）

## データベース仕様
- DBファイル: `~/.password_cli/passwords.db`
- テーブル: `passwords`
  - `id TEXT PRIMARY KEY`
  - `url TEXT NOT NULL`
  - `username TEXT NOT NULL`
  - `password TEXT NOT NULL`（暗号化済み）
  - `title TEXT`
  - `note TEXT`
  - `created_at TEXT NOT NULL`
- テーブル: `passkeys`
  - `id TEXT PRIMARY KEY`
  - `rp_id TEXT NOT NULL`
  - `credential_id TEXT NOT NULL`
  - `user_handle TEXT NOT NULL`
  - `public_key TEXT NOT NULL`
  - `sign_count INTEGER NOT NULL`
  - `transports TEXT`（CSV文字列, 任意）
  - `created_at TEXT NOT NULL`

## セキュリティ方針
- 乱数: `OsRng`（OSのCSPRNG）を使用
- 生成アルゴリズム:
  - カテゴリ混在を保障（可能な範囲）
  - リジェクションサンプリングで指数バイアスの回避
  - シャッフルで先頭固定回避
- パスワードは**保存時に暗号化**、取得時に復号
  - 鍵導出: `HKDF-SHA256` で `salt=id`、`ikm=AUTH_SECRET`、`info="password-at-rest"`
  - 方式: `ChaCha20-Poly1305`（12Bランダムノンス + 本文 + 認証タグ）をBase64で保存
- 認証: `tsupasswd auth <secret>` 実行時に `~/.password_cli/session` に有効期限を書き込み、各コマンド開始時に `ensure_authenticated()` で検証

## エラーハンドリング・終了コード
- 正常終了: `0`
- エラー終了: `1`
  - DB初期化失敗、保存失敗、取得失敗、見つからない、引数不足など
  - 未認証、セッション期限切れ

## 制限事項・既知の注意点
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
  - DB: `~/.password_cli/passwords.db`

## テスト例（手動）
- 生成: `cargo run -- 20`
- 保存（自動生成）: `cargo run -- add https://example.com alice`
- 保存（長さ指定）: `cargo run -- add https://example.com alice 30`
- 保存（手動）: `cargo run -- add https://example.com alice "S3cure!Pass"`
- 取得: `cargo run -- get https://example.com`
 - 検索: `cargo run -- search example`
 - 更新: `cargo run -- update 1 --length 24 --title "Rotated"`
 - 削除: `cargo run -- delete 1`

## テスト（自動）
- 統合テスト: `tests/passkey_cli.rs`
  - セッション開始後、`passkey add/get/search/export/delete` の一連を検証
  - テストごとに `HOME` を一時ディレクトリ、`AUTH_SECRET` を固定
  - 実行: `cargo test`
