# YadoriLink

**クラウドのように同期し、ファイルはクラウドに置かない。**

[English README](README.md)

YadoriLink は、アカウント・デバイス・共有・権限管理を提供しながら、
ファイルの中身は自分のデバイスの上に置いたままにします。

ファイルは認可されたデバイス同士で直接同期されます。
YadoriLink はその調整を行いますが、ファイルは保存しません。

> 1.0 以前 — 開発中です。

## できること

- 自分のデバイス間での、直接・暗号化された同期
- アカウント単位の共有、権限、アクセスの取り消し
- バージョン履歴、競合の保存、オンデマンドのローカル容量管理

macOS、Windows、Linux で動作します。

## 試す

ソースからビルド:

```bash
cargo build --workspace --release
./target/release/yadorilink --help
```

調整サービスにアクセスできる環境で:

```bash
yadorilink daemon start
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
```

自分の別のデバイスを追加する:

```bash
yadorilink share joinable
yadorilink share join my-share --path ~/some/folder
```

他の人と共有する:

```bash
yadorilink share invite my-share --role editor
# 受け取った人は:
yadorilink share accept <code> --path ~/some/folder
```

## しくみ

YadoriLink は「管理」と「保存」を分けています。

調整サービスが扱うのは、アカウント、デバイスの識別、共有、権限、接続の仲介です。
ファイルの中身は利用者のデバイスに留まり、認可されたデバイスの間だけを移動します。

## 開発

YadoriLink は主に Rust で書かれています。

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

主なコンポーネント:

- `crates/yadorilink-daemon` — 同期デーモン
- `crates/yadorilink-cli` — コマンドラインインターフェース
- `crates/yadorilink-transport` — デバイス間の接続
- `crates/yadorilink-desktop-app` — デスクトップアプリ
- `shell-ext/macos` — Finder 連携
- `shell-ext/windows` — エクスプローラー連携

プラットフォームごとのパッケージとインストールについては
[`installer/`](installer/) 以下の README を参照してください。

## セキュリティ

[SECURITY.md](SECURITY.md) を参照してください。

## コントリビュート

[CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## ライセンス

[MIT](LICENSE-MIT) または [Apache-2.0](LICENSE-APACHE) のいずれかを選択できます。
