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

## インストール

[GitHub Releases](https://github.com/juntaki/yadorilink/releases) から、お使いの
プラットフォーム向けのインストーラーをダウンロードします。

| プラットフォーム | ダウンロード |
|---|---|
| macOS | `yadorilink-macos.pkg`（署名・公証済み） |
| Windows | `yadorilink-setup-unsigned.exe`（現在は未署名。下記参照） |
| Linux (Debian/Ubuntu) | `yadorilink-linux-amd64.deb` |

各ファイルの隣に `.sha256` チェックサムがあります。インストール手順、初回起動、
更新、アンインストールは各プラットフォームの README にあります:
[macOS](installer/macos/README.md)、[Windows](installer/windows/README.md)、
[Linux](installer/linux/README.md)。

**Windows:** インストーラーは現時点でコード署名されていないため、Windows
SmartScreen が「発行元不明」の警告を表示します。「実行」を選ぶ前に、ダウンロード
したファイルの SHA-256 を公開されている `.sha256` と照合してください。また、
長期間オフラインだったために同期履歴の再構築が必要になった Windows
デバイスは、まだサポートされていません。デーモンは
`the rebootstrap is blocked: DurabilityUnsupported` と報告して再構築を拒否し、
フォルダには手を加えません。

リリース版は自動的に YadoriLink の調整サービス（`https://control.yadori.link`）
に接続します。別の調整サービスを使うには、`yadorilink` コマンドやデーモンを実行する
前に `YADORILINK_COORDINATION_ADDR` を設定します（例:
`YADORILINK_COORDINATION_ADDR=http://127.0.0.1:8787`）。

## はじめて使う

インストール後、デーモンを起動します（macOS と Windows ではインストーラーが起動
します。Linux では `systemctl --user enable --now yadorilink-daemon`）。その後:

```bash
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

`yadorilink status` と `yadorilink doctor` でデーモンの状態を確認できます。
フォルダグループがリセットされて退避された項目がある場合は、
`yadorilink preserved list` で一覧でき、`preserved restore`、`retry`、
`discard` で扱えます。

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

## 更新とリセット（1.0 以前）

すべてのデバイスを同じリリースに更新してください。1.0 以前のリリース間では、
互換性のための移行は保証されません。バージョンの非互換で起動できない場合は、
YadoriLink のローカルのアプリケーション状態と認証情報を削除してセットアップし直して
ください。同期フォルダとその中のファイルは削除されません。状態の場所は各
プラットフォームの README に記載されています。

## しくみ

YadoriLink は「管理」と「保存」を分けています。

調整サービスが扱うのは、アカウント、デバイスの識別、共有、権限、接続の仲介です。
ファイルの中身は利用者のデバイスに留まり、認可されたデバイスの間だけを移動します。

## ソースからビルド

開発用、または自分でビルドしたい場合:

```bash
cargo build --workspace --release
./target/release/yadorilink --help
```

ビルド時の設定がない場合、ソースからのビルドは `YADORILINK_COORDINATION_ADDR`
を設定しない限り `http://127.0.0.1:8787` に接続します。リリース版は
`YADORILINK_DEFAULT_COORDINATION_ADDR` を本番の調整サービスに設定してビルド
されています。ビルド時に同じ変数を設定すれば、独自の既定値を埋め込めます。実行時の
優先順位は `YADORILINK_COORDINATION_ADDR`、コンパイル時の既定値、
`http://127.0.0.1:8787` の順です。デーモンは `yadorilink daemon start` で自分で
起動します。

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

[SECURITY.md](.github/SECURITY.md) を参照してください。

## コントリビュート

[CONTRIBUTING.md](.github/CONTRIBUTING.md) を参照してください。

## ライセンス

[GNU Affero General Public License v3.0 only](LICENSE) (AGPL-3.0-only) の下で提供されます。

ホスト型コーディネーションサービス (`control.yadori.link`) には
[プライバシーポリシー](PRIVACY_POLICY.md) と [利用規約](TERMS_OF_SERVICE.md) が適用されます
(正本: <https://yadori.link/ja/privacy/>、<https://yadori.link/ja/terms/>)。
