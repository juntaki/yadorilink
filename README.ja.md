# YadoriLink

**中央ストレージにファイル内容を置かない、ローカルファーストなピアツーピア・フォルダー同期ツールです。**

[English README](README.md) ·
[YadoriLink を選ぶ理由](#yadorilink-を選ぶ理由) ·
[何が違うのか](#何が違うのか) ·
[いまできること](#いまできること) ·
[現在の状態](#現在の状態) ·
[クイックスタート](#クイックスタート) ·
[ソースからビルド](#ソースからビルド)

YadoriLink は、自分のデバイス間や共有グループ内でフォルダーを同期します。ファイル内容は、認証済みかつ暗号化されたトランスポート上でデバイス間を直接移動します。調整サービスが扱うのはアカウント、デバイス ID、共有メンバーシップだけで、ファイル内容を見たり、保存したり、中継したりしません。

## YadoriLink を選ぶ理由

- **ピアツーピアで、事業者のデータ経路はありません**: ファイル内容はデバイス間だけを直接移動します。YadoriLink が運用するサーバーやサービスが利用者のデータを転送することは一切ないため、プロジェクトが利用者のファイル通信を運ぶこと(そのコストを負担すること)はありません。家庭やモバイルの NAT 越しでも直接接続できるよう、トランスポートは IPv6、STUN によるアドレス探索、ルーターのポートマッピングを試みます。それでも直接接続できない場合は、既に信頼して共有関係にあるデバイスが明示的な opt-in のうえであなたの暗号化されたピア通信を中継できます(デフォルトでは無効。中継するデバイスは暗号化されたバイト列を転送するだけで、復号はしません)。そのようなデバイスがないピアは、同意していない中間装置を黙って経由させられるのではなく、理由付きで「接続できません(cannot connect)」と表示されます。
- **内容を見ない調整サービス**: 調整プレーンの役割は、アカウント、デバイス ID、共有メンバーシップの管理だけです。平文のファイル内容を受け取らない設計です。
- **単一コードベースでクロスプラットフォーム**: CLI、デーモン、同期エンジンは、Linux、Windows、macOS を対象にした 1 つの Rust ワークスペースです。
- **CLI ファースト、デーモンバックエンド**: セルフホストやパワーユーザーに向く、スクリプト化しやすい構成です。
- **オープンソースのクライアント**: ファイル、鍵、ワイヤープロトコルに触れるコードを読んで、ビルドして、監査できます。

## 何が違うのか

ピアツーピア同期自体は新しいものではありません。Syncthing や Resilio Sync は、中央クラウドにファイル内容を保存せずにフォルダー間同期を行います。Dropbox は、アカウントや共有の管理を非常に簡単にします。YadoriLink は、その組み合わせを目指しています。

- Dropbox のようなアカウント、デバイス ID、共有メンバーシップ管理
- サーバー保存・転送ではなく、Syncthing / Resilio 風の直接ピアツーピア転送
- 同期、トランスポート、暗号化スタックを確認できる Rust 実装
- 事業者が運用するデータプレーンをあえて持たない設計。2 台が直接到達できない場合でも、そのデータを既に持つ別のデバイスが時間をかけて両者を橋渡しし(認可済みピア間のストアアンドフォワード)、データプレーンを誰も運用せずに共有グループが収束します。

## いまできること

2 つのフォルダーを同期させること以外に、次のことができます。

- **役割付きの共有**: `share invite <group>` は、自分が所有するフォルダーグループに対して**一度きり・期限付き**の招待を発行し、コード、`yadorilink://` URL、ターミナル上の QR コードの 3 通りで表示します(既定の有効期限は 7 日、`--ttl-secs` で変更可能)。役割は `viewer`(読み取り専用)または `editor` で、UI 上の見た目だけでなく**受信側のデーモンが実際に強制**します。viewer 役割のデバイスが署名した変更は、到着時点で拒否されます。`--require-approval` を付けると、招待の受諾は「申請」になり、`share approve` で承認する(または `share deny` で断る)までアクセスは一切与えられません。待っている相手は `share pending` で確認できます。`share members` は「アクセスできる人」の一覧、`share change-role` は既存メンバーの役割を viewer / editor 間でその場で変更(取り消して招待し直す必要はありません)、`share revoke` はアクセスの取り消しです。降格も取り消しも、接続中のピアには次回ポーリングを待たずに速やかに反映されます。同じアカウントの別デバイスには、招待ではなく `share grant` / `share joinable` / `share join` を使います。
- **選択的同期(オンデマンド)**: `--on-demand` でリンクすると、ファイルはプレースホルダーとして現れ、最初のアクセス時に取得されます。`--max-local-size` で上限を設ければ自動退避も働きます。個々のファイルは `pin` / `unpin` / `evict` / `materialization-status` で制御し、`share set-storage-mode` でフォルダー全体を `eager` と `on-demand` の間で切り替えられます。中央のコピーが存在しない以上、最後の完全レプリカを手放す操作は、他のデバイスが全ファイルを保持していると確認できるまで拒否されます。
- **バージョン履歴・ゴミ箱・コンフリクト**: `versions <file>` は保持されている全バージョンを一覧し、`restore` はそのひとつを新しい現行バージョンとして復元します。削除したファイルは `trash list` / `trash restore` で復旧できます。保持ポリシーは全リンク共通の固定で、リンクごとに設定する項目はありません。古いバージョンは「直近 10 世代以内」と「30 日以内」の**どちらかを満たす限り**保持され、両方を外れて初めて破棄されます(「どちらか早い方まで」ではありません)。同時編集は「片方が黙って消える」のではなくコンフリクトコピーになり、`conflicts list` で一覧できます。
- **フォルダー巻き戻し(プレビューのみ)**: `rewind <group> --at 2h`(`--at 7d` や unix ナノ秒でも可)は、フォルダー全体をその時点に戻したら何が変わるかを表示します。`--verbose` でパス単位まで出せます。**読み取り専用**で、何も適用しません。
- **単発送信**: `send <path> <device>` は、リンクも同期も設定せずに、同じアカウントの別デバイスへファイルやディレクトリを直接送ります。受信側は `inbox` で届いたものを見て、`receive` で受け取ります(中断しても再開できます)。
- **LAN 上のピア発見**: 調整プレーンから既に伝えられているピアデバイスは、ローカルネットワーク上でも直接見つけられます。30 秒ごとに protobuf の告知を IPv4 ブロードキャストアドレスと `224.0.0.251` の両方へ、いずれも UDP ポート 31027 で送ります。**mDNS / DNS-SD ではありません**。Bonjour や Avahi がこのパケットを見ることはなく、IPv4 のみの対応です。照合はピア一覧全体に対して行われ、フォルダーグループ単位ではありません。一覧さえ届いていれば LAN 経由の再接続に調整プレーンへの往復は不要なので、調整プレーンが落ちている間も LAN 上のピア同士は見つけ合えます。ただし調整プレーンから独立しているわけではありません。ピア一覧は再起動をまたいでキャッシュされないため、調整プレーンに一度も到達できていないコールドスタートでは何も発見できません。
- **ローカルホストの REST + SSE API と Web ダッシュボード**: デーモン自身が提供します(下記参照)。
- **運用ツール**: `doctor`(カテゴリ別の接続診断)、`connections`(直近の接続試行と失敗理由)、`limits set`(再起動なしで実行中デーモンに反映される帯域制限)、`ignore list` / `test` / `explain`、`diagnose export`(秘匿処理済みのサポートバンドル)、`backup export` / `import`、`account export` とセルフサービスの `account delete`、そして `update check`(リリースマニフェストを取得して発行者署名を検証し、このプラットフォームとチャンネルに新しいビルドが該当するかを知らせます)。

上のリストを過大に読まれないように、**まだ実装していないこと**も明記します。

- **他人に渡せる Owner 役割**: フォルダーグループの所有アカウントは常に 1 つで、招待・承認・取り消し・役割変更といった管理操作はすべてその所有アカウント専用です。`--role owner` はどのコマンドでも受け付けませんし、所有権の移譲もできません。
- **アプリからのアップデート適用**: `update check` は動きますが、その先が配線されていません。配布ビルドのどの経路もアップデート成果物をダウンロードしないため、プラットフォームのインストーラーに渡せる検証済み成果物がそもそも存在しません。`update install` もトレイの「Install Update」も、毎回 fail-closed で失敗します(「no verified update is ready to install」)。更新はパッケージマネージャーか GitHub Releases から入れ直してください。
- **繰り返し使える共有リンク**: 招待はすべて一度きりです。5 人に共有するなら招待を 5 つ発行します。
- **巻き戻しの実行**: `rewind` はプレビュー専用で、実際に戻すフラグはありません。
- **モバイルクライアント**: Linux、macOS、Windows のみです。

## 現在の状態

YadoriLink は pre-1.0 で、活発に開発中です。現時点では次の状態です。

- **CLI + デーモン** (`yadorilink`, `yadorilink-daemon`) が主要かつ最もよくテストされているインターフェースです。まずここから触るのが適しています。
- **デスクトップアプリ** (`yadorilink-status-app`) は macOS のメニューバー / Windows の通知領域に常駐するトレイアプリです(Linux 向けには配布していません)。初回セットアップウィザード(Google サインイン → デバイス登録 → フォルダーグループの**作成** → 最初のフォルダー選択。他アカウントからの招待の受諾はウィザードには含まれません)を実行でき、稼働状況を表示し、フォルダーごとに 2 つのウィンドウを開きます。「詳細」ウィンドウは、そのフォルダーの状態・コンフリクト・ゴミ箱・ファイルごとのバージョン履歴を表示し、そこから操作もできます。ゴミ箱からの復元、バージョンの復元、個々のファイルの pin / unpin / hydrate / evict です(evict はローカルのファイルをプレースホルダーに戻します)。「共有」ウィンドウでは、役割・有効期限・承認要否を選んで招待を発行し、リンク / QR コード / メールで渡し、既にアクセスできる相手を一覧し、メンバーの役割を変更し、承認待ちの申請を承認・却下し、アクセスを取り消せます。トレイ自体からも、フォルダーの追加 / 削除(追加時はアカウントが既に持っているグループから選びます)、一時停止 / 再開、帯域プリセット、アップデート確認、診断エクスポート、アカウント管理が行えます。「ログイン時に起動」の切り替えを除けば、デスクトップアプリでできることは CLI でもでき、CLI にできることはさらに多くあります。
- **HTTP API と Web ダッシュボード**(デーモン自身が提供、下記参照)は、状態表示に加えて一時停止 / 再開、pin / unpin、evict、restore をカバーします。デスクトップのない headless / NAS 環境向けです。
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
yadorilink daemon start          # インストーラー経由ならサービスとして起動することもできます
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

`share create` は、フォルダーグループの作成とローカルフォルダーのリンクを 1 ステップで行います。作成したデバイスがそのグループの最初の完全レプリカになるため、グループを公開する前にローカルのフォルダーが存在している必要があります。

同じアカウントの 2 台目を追加するときは、参加できるグループを一覧してから参加します。

```bash
yadorilink share joinable
yadorilink share join my-share --path ~/some/folder --storage-mode on-demand
```

別のアカウントと共有するときは、一度きりの招待を発行して相手に受諾してもらいます。

```bash
yadorilink share invite my-share --role editor        # コード・URL・QR を表示します
yadorilink share accept <code-or-url> --path ~/their/folder
```

プラットフォーム別のインストーラー動作、シェル連携、検証手順は、下記のインストールドキュメントを参照してください。

## HTTP API と Web ダッシュボード

`yadorilink-daemon` は、小さなダッシュボードを HTTP でも提供します。デスクトップのない headless な Linux マシンや NAS のように、同期状況を見る手段が SSH + CLI しかない環境で役に立ちます。読み取りが中心で、status、links、conflicts、connections、versions、materialization と `/api/events` の Server-Sent-Events ストリーム、それに決まった操作(pause / resume、pin / unpin、evict、restore)だけを公開します。共有・リンク・アカウント管理は HTTP には一切出していません。

既定では `http://127.0.0.1:8484`(IPv6 ループバックが使える場合は `[::1]:8484` も)で待ち受けます。デーモンの起動ログには、ポート番号と、書き出したトークンファイルのパス(所有者のみ読み書き可能、`0600`)が出ます。ログはそのファイルより広く読まれたり長く残ったりしがちなので、トークンの値そのものはログに出しません。トークンはそのファイルから読み取ってください。

```bash
cat <token_path>   # デーモンの起動ログに出力されたパス
```

ブラウザでダッシュボードの URL を開き、そのトークンを貼り付けます。同じトークンで `/api/` 以下の REST エンドポイントと `/api/events` の Server-Sent-Events ストリームも認証されます。

`YADORILINK_HTTP_API_DISABLE` を(`0` / `false` 以外の値で)設定するとダッシュボードごと無効化でき、`YADORILINK_HTTP_API_PORT` でポートを変更できます。開発中にダッシュボードのフロントエンドをローカルの開発サーバーから動かす場合は、`YADORILINK_HTTP_API_DEV_ORIGIN` に許可する `Origin` をひとつだけ指定できます。本番では絶対に設定しないでください。

**信頼モデル**: デーモンの制御ソケット(CLI がデーモンと話すための経路)は Unix ドメインソケットで、ファイルパーミッションによって守られています。接続できるのは所有 OS ユーザーだけです。HTTP ダッシュボードは同じ制御チャネルの上に乗っていますが、ループバックの TCP ポートで待ち受けるため、デーモンの所有者以外のローカルユーザーアカウントも接続を試みること自体はできます。リクエストを成立させないための鍵がベアラートークンです。これは「uid で守る」から「所有 uid だけが読めるトークンファイルの所持で守る」への、意図的な信頼境界の移動です。したがって、ループバックポートに到達でき、かつそのトークンファイルを読めるローカルユーザーは、このデーモンに対して CLI と同等のアクセスを持つことになります。

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
| `crates/yadorilink-local-storage` | ローカルブロックストア |
| `crates/yadorilink-ipc-proto` | 共有 protobuf とワイヤーフォーマット定義 |
| `crates/yadorilink-http-api` | デーモンが提供するローカルホストの HTTP/REST + SSE ダッシュボード |
| `crates/yadorilink-desktop-app` | デスクトップトレイアプリ (`yadorilink-status-app`) |
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
