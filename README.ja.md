# YadoriLink

**中央ストレージにファイル内容を置かない、ローカルファーストなピアツーピア・フォルダー同期ツールです。**

[English README](README.md) ·
[YadoriLink を選ぶ理由](#yadorilink-を選ぶ理由) ·
[何が違うのか](#何が違うのか) ·
[現在の状態](#現在の状態) ·
[クイックスタート](#クイックスタート) ·
[ソースからビルド](#ソースからビルド)

YadoriLink は、自分のデバイス間や共有グループ内でフォルダーを同期します。ファイル内容は、認証済みかつ暗号化されたトランスポート上でデバイス間を直接移動します。調整サービスが扱うのはアカウント、デバイス ID、共有メンバーシップだけで、ファイル内容を見たり、保存したり、中継したりしません。

## YadoriLink を選ぶ理由

- **ピアツーピアで、事業者が中継するデータ経路はありません**: ファイル内容はデバイス間だけを直接移動します。YadoriLink はリレーもデータを転送するサーバーも運用しないため、プロジェクトが利用者のファイル通信を運ぶこと(そのコストを負担すること)は一切ありません。家庭やモバイルの NAT 越しでも直接接続できるよう、トランスポートは LAN 探索、IPv6、STUN によるアドレス探索、協調的なホールパンチング、ルーターのポートマッピングを試みます。それでも到達できないピアは、黙って中継装置経由にするのではなく、理由付きで「接続できません(cannot connect)」と表示します。
- **内容を見ない調整サービス**: 調整プレーンの役割は、アカウント、デバイス ID、共有メンバーシップの管理だけです。平文のファイル内容を受け取らない設計です。
- **単一コードベースでクロスプラットフォーム**: CLI、デーモン、同期エンジンは、Linux、Windows、macOS を対象にした 1 つの Rust ワークスペースです。
- **CLI ファースト、デーモンバックエンド**: セルフホストやパワーユーザーに向く、スクリプト化しやすい構成です。
- **オープンソースのクライアント**: ファイル、鍵、ワイヤープロトコルに触れるコードを読んで、ビルドして、監査できます。

## 何が違うのか

ピアツーピア同期自体は新しいものではありません。Syncthing や Resilio Sync は、中央クラウドにファイル内容を保存せずにフォルダー間同期を行います。Dropbox は、アカウントや共有の管理を非常に簡単にします。YadoriLink は、その組み合わせを目指しています。

- Dropbox のようなアカウント、デバイス ID、共有メンバーシップ管理
- サーバー保存・転送ではなく、Syncthing / Resilio 風の直接ピアツーピア転送
- 同期、トランスポート、暗号化スタックを確認できる Rust 実装
- リレーや事業者が運用するフォールバック経路をあえて持たない設計。2 台が直接到達できない場合でも、そのデータを既に持つ別のデバイスが時間をかけて両者を橋渡しし(認可済みピア間のストアアンドフォワード)、データプレーンを誰も運用せずに共有グループが収束します。

## 現在の状態

YadoriLink は pre-1.0 で、活発に開発中です。現時点では次の状態です。

- **CLI + デーモン** (`yadorilink`, `yadorilink-daemon`) が主要かつ最もよくテストされているインターフェースです。まずここから触るのが適しています。
- **デスクトップ状態表示アプリ** (`yadorilink-status-app`) は軽量な読み取り専用ビューアです。まだ本格的な GUI オンボーディング / 管理アプリではありません。
- **macOS Finder / File Provider 連携** は動きますが、App Sandbox 下で動かすには実際の Apple Developer 署名 ID が必要です。CI が公開するのは未署名の生バイナリで、パッケージ済み `.pkg` ではありません。詳しくは [`installer/macos/README.md`](installer/macos/README.md) を参照してください。
- **Windows Explorer シェル拡張** は x86_64 でビルド・実行できます。プロジェクト全体として `arm64` は未検証で、実験的扱いです。
- **ホスト型の調整サービス** は <https://yadorilink.juntaki.com> で稼働中です(現在は早期テスター向けフェーズ)。このリポジトリは引き続き、クライアント、同期、トランスポートのコード確認、ツールのビルド、ローカル CLI / デーモンの試用の場です。

## クイックスタート

このリポジトリだけで今すぐできることは、クライアントをビルドして CLI を確認することです。

```bash
cargo build --workspace --release
./target/release/yadorilink --help
```

調整サービスへアクセスできる場合の初回フローは次のようになります。

```bash
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share
yadorilink link ~/some/folder my-share
yadorilink status
```

プラットフォーム別のインストーラー動作、シェル連携、検証手順は、下記のインストールドキュメントを参照してください。

## インストール

### 最新の開発ビルド

ビルド済みの開発版は GitHub Releases からダウンロードできます。

https://github.com/juntaki/yadorilink/releases/tag/nightly

- Linux: `.deb` パッケージまたはバイナリ tarball
- Windows: 未署名インストーラーまたはバイナリ zip
- macOS: 未署名バイナリ tarball

YadoriLink は pre-1.0 です。これらのビルドはテストと早期フィードバック向けです。Windows ビルドは未署名なので SmartScreen の警告は想定内です。macOS ビルドも未署名かつ notarize されていません。

直接リンク:

- Linux `.deb`: <https://github.com/juntaki/yadorilink/releases/download/nightly/yadorilink-linux-amd64.deb>
- Windows installer: <https://github.com/juntaki/yadorilink/releases/download/nightly/yadorilink-setup.exe>
- macOS tarball: <https://github.com/juntaki/yadorilink/releases/download/nightly/yadorilink-macos.tar.gz>

### 開発用アーティファクト

GitHub Actions artifacts は主にメンテナーとテスター向けです。これは保持期間のある CI 出力であり、一般ユーザー向けの主なダウンロード導線ではありません。通常のダウンロードには GitHub Releases を使ってください。

CI workflow は引き続き、実行ごとの artifacts も公開します。

- `yadorilink-linux-artifacts`: `.deb` パッケージと Linux バイナリ tarball
- `yadorilink-windows-artifacts`: 未署名の `yadorilink-setup.exe` と Windows バイナリ zip
- `yadorilink-macos-artifacts`: macOS バイナリ tarball

注意:

- Linux アーティファクトには `SHA256SUMS` と `.deb.sha256` sidecar が含まれます。
- Windows アーティファクトには `SHA256SUMS` とインストーラーの `.sha256` sidecar が含まれます。CI ビルドは未署名なので、SmartScreen の警告は想定内です。
- macOS CI は生バイナリのみ公開します。署名済み `.pkg` を作るには、署名できる Mac と Actions 外の notarization フローが必要です。

### プラットフォーム別インストール / パッケージング資料

- Linux パッケージのビルド / インストール: [`installer/linux/README.md`](installer/linux/README.md)
- Windows パッケージング: [`installer/windows/README.md`](installer/windows/README.md)
- macOS パッケージング: [`installer/macos/README.md`](installer/macos/README.md)

## リポジトリ構成

| パス | 役割 |
|---|---|
| `crates/yadorilink-cli` | ユーザー向け CLI (`yadorilink`) |
| `crates/yadorilink-daemon` | バックグラウンド同期デーモン (`yadorilink-daemon`) |
| `crates/yadorilink-transport` | ピアトランスポート、NAT 越え、接続管理 |
| `crates/yadorilink-sync-core` | 同期エンジンと調停ロジック |
| `crates/yadorilink-local-storage` | ローカルブロックストア |
| `crates/yadorilink-ipc-proto` | 共有 protobuf とワイヤーフォーマット定義 |
| `crates/yadorilink-desktop-app` | デスクトップ状態表示アプリ (`yadorilink-status-app`) |
| `shell-ext/windows` | Explorer シェル拡張と CfAPI ホスト |
| `shell-ext/macos` | Finder / File Provider 連携 |

## ソースからビルド

### コアワークスペース

macOS と Windows:

```bash
cargo build --workspace --release
```

Linux では、デスクトップ状態表示アプリはサポート対象のパッケージングフローに含まれません。配布対象のバイナリは次のようにビルドします。

```bash
cargo build --workspace --release --exclude yadorilink-desktop-app
```

### テストとチェック

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Linux で CI と同じ条件にする場合は、デスクトップアプリを除外します。

```bash
cargo clippy --workspace --exclude yadorilink-desktop-app --all-targets -- -D warnings
cargo test --workspace --exclude yadorilink-desktop-app
```

### プラットフォーム別パッケージング

Linux:

```bash
./installer/linux/build-deb.sh
```

Windows:

```powershell
cargo build --workspace --release
cd shell-ext\windows
cargo build --release
cd ..\..
powershell -ExecutionPolicy Bypass -File installer\windows\build-installer.ps1
```

macOS:

```bash
./installer/macos/build-pkg.sh
```

## コントリビューション

Issue や Pull Request を送る前に [CONTRIBUTING.md](CONTRIBUTING.md) を読んでください。脆弱性は公開 issue ではなく、[SECURITY.md](SECURITY.md) の手順で報告してください。

## セキュリティ

YadoriLink は pre-1.0 で、活発に開発中です。脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

YadoriLink は次のいずれかを選択できるデュアルライセンスです。

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

どちらか好きな方の条件で利用できます。
