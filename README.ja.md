<!-- English source SHA-256: 042dfd1f971e2a895223216b56e2eaa8b0119c40748dfe2230db4fc208e2d004 -->
<h1 align="center">sibuna</h1>
<p align="center">分散型エッジロードバランサーおよび Web アプリケーションファイアウォール</p>
<p align="center">
  <a href="#features">機能</a> ·
  <a href="#load-balancing">負荷分散</a> ·
  <a href="#beside-haproxy-and-envoy">ベンチマーク</a> ·
  <a href="#quickstart">クイックスタート</a> ·
  <a href="#console">コンソール</a> ·
  <a href="#how-it-works">仕組み</a> ·
  <a href="#documentation">ドキュメント</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

Sibuna は、単一のエッジノードでもメッシュ構成でも、TCP、UDP、HTTP のトラフィックを正常なサーバーに振り分けます。エッジで TLS を終端し、指定した HTTP ルートを検査して、DDoS フラッドからバックエンドを保護できます。

## Sibuna の利用例

- **公開 Web サイト**

  ブラウザからの接続を HTTP/2 または HTTP/3 で受け、Let's Encrypt で公開証明書を自動更新します。リクエストを検査したうえで HTTP/1.1 レプリカに転送します。
- **内部 gRPC サービス**

  ローカル CA で内部ホスト名の証明書を発行します。クライアントはそのルート証明書を信頼し、TLS 経由でサービスを呼び出します。HTTP/2 バックエンドが gRPC メッセージとトレーラーを転送します。
- **エッジノードのクラスター**

  検証済みのルーティング設定をメッシュ全体に配布します。各ノードは自身のバックエンドプールにトラフィックを転送しながら、アクセス禁止（BAN）や学習済みのアフィニティを共有できます。

[Sibuna とは何か](https://insanai.github.io/sibuna/ja/book/introduction.html)

<a id="features"></a>

## 機能

- **単一バイナリ：** エンジン、組み込み SQLite ストレージ、ブラウザソルバー、コンソールアセットを 1 つの実行ファイルに収録。
- **ネイティブパッケージ：** Linux、macOS、Windows、FreeBSD、OpenBSD に対応。ブラウザソルバーには WebAssembly を使用。
- **ブラウザチャレンジ：** 逐次プルーフ・オブ・ワーク（デフォルト）または Hashcash を用い、完了後に署名付きセッションを発行。
- **アクセスポリシー：** アドレス、パス、ヘッダー、User-Agent に応じて、リクエストを許可・チャレンジ・重み付け・拒否。
- **負荷分散：** 複数サーバーの前段で TCP、UDP、HTTP を処理。TLS 終端、証明書の自動取得、クラスターモードに対応。詳細は[負荷分散](#load-balancing)を参照。
- **[エッジでの DDoS 対策](https://insanai.github.io/sibuna/ja/book/operations.html#edge-admission-under-attack)** クライアント IP ごと・フロントエンドごとに同時フロー数を制限できます。高負荷時には新規アドレスの受け入れを制限し、確認済みフロー向けに UDP の処理枠を確保できます。回線を飽和させる規模のフラッド攻撃には上流でのフィルタリングが必要です。
- **TLS フィンガープリント：** 信頼できるイングレスが転送する JA4 フィンガープリントを完全一致または前方一致で照合。
- **アプリケーション検査：** SQL インジェクション、XSS、パストラバーサル、コマンドインジェクションの検査を内蔵。
- **ローカルレートリミット：** バーストトラフィックと継続トラフィックを制御し、ルールごとの上限も設定可能。
- **運用コンソール：** トラフィック状況、サンプリングされた国別アクティビティ、記録済みインシデントの確認、およびポリシー編集。
- **クラスター対応：** 別ビルドにより、PostgreSQL を通じてポリシーとレピュテーションを共有。

<a id="load-balancing"></a>

## 負荷分散

Sibuna 1.0.0-rc.7 にはエッジモードが含まれています。リリース候補を[ソースからビルド](#build-from-source)することもできます。

```sh
sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80
sibuna lb --tls auto --domain example.org --server 10.0.0.1:80
sibuna lb --bind :8080 --server 10.0.0.1:80 --print-config > edge.jlv
sibuna check -f edge.jlv
sibuna --config-file edge.jlv
```

[Jlavi で Sibuna を設定する](https://insanai.github.io/sibuna/ja/book/jlavi.html)

- **転送：** TCP / UDP、サーバー名（完全一致またはワイルドカード）でルーティングする TLS パススルー、QUIC パススルー、PROXY プロトコル。
- **攻撃時の防御：** クライアントアドレスごと・フロントエンドごとのフロー上限、接続受け付け時に評価されメッシュ全体で共有されるアクセス禁止（BAN）、自動 BAN、TCP リセットまたはターピットによる拒否、既知クライアントを優先的に受け入れる高負荷保護モード、複数コアで動作するアクセプトスレッド、確認済みクライアント向けに予備枠を確保する UDP パケットバジェット。
- **HTTP：** HAProxy 形式の PEM バンドルによる TLS 終端と耐量子鍵交換（X25519MLKEM768）。HTTP/1.1、HTTP/2、HTTP/3、WebSocket に対応し、ホスト名（完全一致または `*.example.org` のようなワイルドカード）とパスで HTTP/1.1、HTTP/2、HTTP/3 サーバーへルーティング。Linux では CPU コアごとに 1 つのイベント駆動ワーカーが接続を処理。
- **証明書：** ACME による自動取得・更新、フォールバック認証局、外部アカウントバインディング（EAB）。フックプログラム、RFC 2136 更新、Cloudflare API を用いた DNS 経由のワイルドカード証明書。OCSP ステープリング。ガード経由のオンデマンド証明書発行。`localhost`、内部ホスト名、IP アドレス向けのローカル認証局（失効リストおよび独自 ACME サーバー付き）。
- **サーバー：** ヘルスチェック、スロースタート、ドレイン、重み付け、スティッキーセッション、サーバーごとのフロー上限。
- **無停止での運用変更：** 設定のリロードが受理されると、確立済みの TCP ストリームはそのまま維持されます。管理ソケットからサーバーのドレイン、重み変更、追加、削除を実行できます（`sibuna ctl /run/sibuna/edge.sock set server app/10.0.0.1:80 state drain`）。Linux では新しい実行ファイルが旧プロセスからリスニングソケットと UDP マッピングを引き継ぎます（QUIC 接続は終了します）。
- **クラスター：** メッシュ内のノードがスティッキーテーブルとサーバーのフロー上限を共有し、クライアントを担当ノードへ転送します。PostgreSQL データベースから 1 つの設定を全ノードに配信・ロールバックでき、メモリマップファイルで再起動後もアフィニティのヒントを保持します。
- **フック：** 接続時およびリクエスト時に実行。組み込みでのコンパイル、実行時間上限付きの WebAssembly、または Unix ソケット経由のエージェントとして動作。
- **オブザーバビリティ：** メトリクス、アクセスログ、およびサーバー・フロー・拒否状況を表示するコンソール画面。

Gate や Shield は必要なホスト名だけに適用することも、一切適用しないこともできます。設定ファイルが常に正となり、実行時の変更は次のリロードまで有効です。

本番トラフィックでの実運用検証はまだ完了していません。クラスター機能は 3 台のホストでテスト済みです。各[設計議論](https://insanai.github.io/sibuna/sid/)に、実装済みの内容と既知の課題を記載しています。

<a id="quickstart"></a>

## クイックスタート

プラットフォームに合った[リリースをダウンロード](https://github.com/insanai/sibuna/releases/tag/v1.0.0-rc.7)してください。標準パッケージにはストレージとコンソールのサポートが含まれます。コンソールは `--console` で起動します。

| プラットフォーム | パッケージ | 動作要件 |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 以降、musl 静的リンク |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 以降、musl 静的リンク |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 12 以降 |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 12 以降 |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2016 以降、ネイティブの `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-1.0.0-rc.7-freebsd-15.1-amd64.pkg` | FreeBSD 15.1、CLI パッケージ |
| OpenBSD x86-64 | `sibuna-1.0.0-rc.7.tgz` | OpenBSD 7.9、CLI パッケージ |

macOS 向けビルドは未署名です。各パッケージにはライセンス、ソースへのリンク、ビルドマニフェストが含まれます。使用する前に、`SHA256SUMS` と照合してアーカイブを検証してください。

Debian/RPM パッケージは Linux x86-64 と ARM64 に、Arch の `sibuna-bin` は x86-64 に対応します。FreeBSD 15.1 と OpenBSD 7.9 のパッケージは x86-64 に対応し、CLI をインストールします。Linux パッケージには、任意で有効化できる無効状態の systemd サービスが含まれます。BSD パッケージはサービス・アカウント・状態ファイルを作成しません。これらは上流の配布物であり、コミュニティリポジトリへの採録とは別です。リリースには Helm チャートとコンテナイメージ `ghcr.io/insanai/sibuna` も含まれます。インストール、検証、プライベートな状態ファイル、アップグレード、Kubernetes 構成については[パッケージ運用ガイド](https://insanai.github.io/sibuna/ja/book/operations.html)を参照してください。

[Sibuna Homebrew tap](https://github.com/insanai/homebrew-sibuna) は、検証済みのリリースアーカイブをインストールする CLI 用 Formula を提供しています。macOS と Linux（Apple Silicon、ARM64、x86-64）に対応し、公開済みの最新リリースに追従します。インストールしてもサービスは起動しません：

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

Linux x86-64 で、アプリがポート 3000 で待ち受けている場合：

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-rc.7/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-rc.7/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

`http://127.0.0.1:8080` を開くとローカルで試せます。公開サイトでは、信頼できるイングレスで HTTPS を終端し、Sibuna のリスナーは非公開にしてください。Caddy または nginx での構成は[デプロイガイド](https://insanai.github.io/sibuna/ja/book/operations.html)に従ってください。

デフォルトのモードは `reverse_proxy` です。イングレスがリクエストを転送し、Sibuna にアクセス判定を問い合わせる構成では `--mode forward_auth` を使用します。ガイドには両方の設定例を掲載しています。Shield の内蔵検査はデフォルトで有効です。内蔵検査を使わずにアクセス制御のみを行う場合は `--gate` を指定します。アクセスルールは `--policy-file <file>` で指定でき、ブラウザチャレンジを実行できない API クライアントやヘルスチェック向けのルールも含められます。`./sibuna --help` で全オプションを確認できます。

Windows では ZIP を展開し、PowerShell で `.\sibuna.exe --help` を実行します。停止するには Ctrl+C を押します。シード、認証情報、データファイルへのアクセスは Windows ACL で制限してください。

<a id="build-from-source"></a>

### ソースからビルドする

すべての機能セットのビルドに **Rust 1.100** が必要です。JSON のみのデーモンは `--no-default-features` でビルドし、必要に応じて `sqlite,console` を選択します。ブラウザソルバーとコンソール UI は WebAssembly にコンパイルされた Rust であり、ビルドに Node や npm は不要です。

```sh
git clone https://github.com/insanai/sibuna.git
cd sibuna
rustup toolchain install 1.100.0 --profile minimal --target wasm32-unknown-unknown
cargo +1.100.0 build --release -p sibuna
```

実行ファイルは `target/release/sibuna` に出力されます。`--data-dir` を指定すると状態を SQLite に保存します。クラスター版は `--features postgres-tls` でビルドし、`--database-url-file` と `--cluster-node` で 1 つの PostgreSQL データベースを共有します。テスト、lint、バイナリサイズ検査については [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

<a id="console"></a>

## コンソール

コンソールは同じ実行ファイル内で動作します。デーモンを停止した状態で管理者を初期設定してください：

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

`http://127.0.0.1:19446/console/` を開き、一時パスワードを変更してください。[運用ガイド](https://insanai.github.io/sibuna/ja/book/operations.html)では、HTTPS アクセス、GeoIP のインポート、ユーザー管理、API トークン、ウォールディスプレイについて説明しています。

![ナビゲーション、国別アクティビティの地球儀、リクエスト結果、観測範囲、国別サンプルを表示した Sibuna コンソール](docs/readme/images/console-globe-93225dc9.png)

地球儀ビューは直近 1 分間にサンプリングされた国別アクティビティを表示します。マーカーはおおよその国の位置を示し、矢印は設定されたサーバー位置へ向かいます。個々のライブ接続を表すものではありません。GeoIP には別途インポートしたデータセットが必要です。地球儀上にサーバーを配置するには `--console-location <latitude,longitude>` を設定してください。

<details>
<summary>トラフィック概要、セキュリティ概要、ポリシー、インシデント調査</summary>

**トラフィック概要** - ライブのリクエスト結果、許可・チャレンジカウンター、ノード稼働状態、スパークライン。

![リクエスト、許可、チャレンジ、拒否のカウンターを表示した Sibuna コンソールのトラフィック概要](docs/readme/images/console-traffic-fba02476.png)

**セキュリティ概要** - 記録された検出結果、チャレンジ、アクセス禁止（BAN）、ライブのイベントフィード。

![検査、チャレンジ、アクセス禁止、ハニーポットの検出結果を表示した Sibuna コンソールのセキュリティ概要](docs/readme/images/console-security.png)

**ポリシー** - ノードが順に適用するルールと記録されたヒット数。

![適用中の設定と許可ルールを表示した Sibuna コンソールのポリシーページ](docs/readme/images/console-policies.png)

**イベント** - 記録されたインシデント。モジュール、国、アドレス、パス、時刻で絞り込めます。

![インシデントのフィルターと記録された SQL インジェクション検出結果を表示した Sibuna コンソールのイベントページ](docs/readme/images/console-events.png)

</details>

地球儀とトラフィック概要は、v1.0.0-beta.2 を実行して通常の Chrome ウィンドウでキャプチャしたものです。その他の画面は v1.0.0-beta.1 のものです。すべての画像は生成トラフィックとテスト用 GeoIP マッピングを用いたローカルテストノードで撮影しており、表示されている数値はベンチマーク結果ではありません。

<a id="how-it-works"></a>

## 仕組み

フロントエンドが接続を受け付けます。TCP や UDP ではフローごとにサーバーを選択します。HTTP ではリクエストごとにホストとパスを照合し、ルートのファイアウォールポリシーを適用して、許可したトラフィックを該当プールの正常なサーバーに転送します。各エッジノードが自律的にこの判定を行いながら、ピア間でアフィニティや BAN 情報の更新を共有します。

リクエストは許可、チャレンジ要求、拒否のいずれかに判定されます。チャレンジを解いた訪問者には署名付きセッションが発行されます。その後のリクエストも、適用対象のポリシーおよびレートリミット検査を通過する必要があります。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="パズルを解いて署名付きセッションを受け取り、その後のリクエストでもルールを確認する">
</picture>

Gate はアクセスルール、セッション、ローカルレートリミットを評価します。Shield はそこに内蔵の攻撃検査エンジンを追加します。デフォルトは Shield で、起動時に `--gate` を指定すると Gate が有効になります。

<details>
<summary>Gate、Shield、および Sibuna 内部のクレート構成</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate と Shield のリクエスト判定：許可、チャレンジ、ブロック">
</picture>

図は Gate と Shield の内蔵検査を示しています。有効なセッションを持っていても、適用対象の攻撃検査やレートリミットはバイパスされません。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna 内部のクレートの役割">
</picture>

クレートはネットワーク、証明、ポリシー、ローカル状態、ストレージ、管理の各責務に分離されています。それぞれの役割は[技術ガイド](https://insanai.github.io/sibuna/ja/book/)で詳しく解説しています。

</details>

<a id="deployment-limits"></a>

### デプロイ時の制約

非公開リスナーは外部イングレスの背後で HTTP/1.1 を使用します。エッジモードでは TLS、HTTP/2、HTTP/3 を Sibuna で終端し、HTTP/1.1、HTTP/2、HTTP/3 のサーバープールへ転送できます。Forward-auth はイングレスから渡されたメタデータを検査します。リバースプロキシモードでは、内蔵検査エンジンはボディの先頭 8 KiB を対象とし、アップロードはアプリへストリーミング転送します。WebSocket メッセージは検査せずに中継します。検査エンジンはヒューリスティックベースであり、完全な言語パーサーではありません。

レートリミットはノードごとにローカルで適用されます。Sibuna はボリュメトリック（大容量）ネットワーク攻撃の緩和機能は提供しません。無停止のバイナリ入れ替えとイベント駆動ワーカーは Linux のみ対応しています。チャレンジは発行元ノードに紐付くため、チャレンジとその解答は同じノードへルーティングしてください。コンソールの厳格な性能目標はまだ正式な検証を通過していません。本番アプリと並べてコンソールを有効化する前に、[デプロイ時の制約と測定結果](https://insanai.github.io/sibuna/ja/book/operations.html)を確認してください。

<a id="benchmarks"></a>

## ベンチマーク

技術ガイドには各測定のソースリビジョン、設定、ホスト情報を記録しています。これらの測定は 1 台のマシン上でいくつかのワークロードを実行した際のリクエスト処理コストを示すものであり、防御性能やボット識別精度の同等性を測るものではありません。

<a id="sibuna-on-one-host"></a>

### 1 台のホスト上の Sibuna

これらの測定には AMD Ryzen 9 5950X を使用しました。デーモンに 4 CPU を割り当ててインメモリで動作させ、負荷生成器とスタブオリジンを別の 8 CPU で動かしています。`wrk` はループバック経由で 64 接続を使用しました。数値は 3 回実行の中央値です。

- forward-auth モードでは、全ワークロードで毎秒 197,532〜211,636 リクエストを処理し、p99 レイテンシは 305〜327 μs、リクエストあたり CPU 時間は 11.7〜13.8 μs でした。上限は負荷生成器側で律速していました。
- プロキシしたリクエストは毎秒 138,965〜147,303 件、ピークメモリ使用量は約 16 MiB でした。
- 毎秒 100,000 件の許可済みリクエストという同一負荷条件で、p99.9 レイテンシは forward-auth モードで 62 μs、リバースプロキシモードで 150 μs でした。

<a id="beside-haproxy-and-envoy"></a>

### HAProxy・Envoy との比較

2026 年 11 月 25 日に、同一ホスト上で Sibuna、HAProxy 3.0.11、および BoringSSL 版 Envoy 1.40.2 を測定しました。各プロキシに 8 CPU と 8 ワーカースレッドを割り当て、同じオリジン、証明書、負荷生成器を用い、ループバック経由の 256 接続で 2 バイトのレスポンスを返しています。最初の 3 行は 8 秒間の測定を 3 回行った際の毎秒リクエスト数の中央値、最後の 3 行は測定終了時の常駐メモリです。各ケースの処理量のばらつきは最大 4% 以内で、すべてのリクエストが正常に完了しました。

| ケース | Sibuna | HAProxy | Envoy |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 220,040 | 220,323 | 70,909 |
| TLS 上の HTTP/1.1 | 174,611 | 165,199 | 63,399 |
| HTTP/2 | 104,132 | 153,899 | 68,972 |
| 常駐メモリ（HTTP/1.1） | 14 MiB | 48 MiB | 58 MiB |
| 常駐メモリ（TLS 上の HTTP/1.1） | 21 MiB | 61 MiB | 61 MiB |
| 常駐メモリ（HTTP/2） | 116 MiB | 112 MiB | 140 MiB |

平文 HTTP では Sibuna と HAProxy はほぼ互角でした。HTTP/2 では HAProxy が Sibuna より約 48% 多くのリクエストを処理し、メモリ使用量もわずかに少なくなりました。Envoy は静的な設定でルーターフィルターを使用しています。設定やワークロード次第で結果は変わり得ます。こうした短時間の測定だけでは、動的設定、アプリケーション遅延、実ネットワーク上の性能は十分に判断できません。[測定手法と結果](https://insanai.github.io/sibuna/ja/book/benchmarks.html#sibuna-haproxy-and-envoy)

<a id="beside-anubis"></a>

### Anubis との比較

公式の Anubis 1.27.0 リリースバイナリを、同一のワークロード・CPU・負荷生成器で測定しました。Hashcash の計算量は揃えています（Sibuna は先頭ゼロ 8 ビット、Anubis は 16 進数先頭ゼロ 2 桁）。オリジンには `caddy respond` を使用しました。表はセッションを持つ許可済みリクエストの結果です。

| 許可済みリクエスト | Sibuna Gate | Sibuna Shield | Anubis 1.27.0 |
| --- | ---: | ---: | ---: |
| Forward auth、req/s | 210,682 | 208,635 | 36,509 |
| Forward auth、p99 | 305 μs | 308 μs | 7,477 μs |
| Forward auth、リクエストあたり CPU 時間 | 12.1 μs | 13.2 μs | 106.3 μs |
| リバースプロキシ、req/s | 106,376 | 103,298 | 19,398 |
| リバースプロキシ、p99 | 3,331 μs | 3,321 μs | 11,062 μs |

2 回目の測定では、各製品に 2 CPU を割り当ててアドミッション処理の各操作を計測しました。Anubis はデフォルトの Ed25519 トークンと HS512 トークンでそれぞれ 1 回ずつ実行しています。

| 毎秒の操作数 | Sibuna（鍵付き BLAKE3） | Anubis（Ed25519） | Anubis（HS512） |
| --- | ---: | ---: | ---: |
| 有効なセッションの確認 | 88,104 | 10,951 | 16,976 |
| 未認証の確認 | 78,997 | 28,619 | 27,785 |
| チャレンジの初期化 | 42,664 | 7,893 | 7,952 |
| 証明の検証 | 57,924 | 12,668 | 19,261 |

Sibuna のピークメモリは 16 MiB 前後にとどまりました。Anubis は forward-auth モードで約 33 MiB、リバースプロキシモードで最大約 600 MiB を使用しました。Anubis は広く使われている優れたツールであり、これらの数値は順位付けではありません。また、いくつかの項目は同一条件の比較ではありません（forward-auth モードの Anubis は一部パスに自ら応答し、ペイロード検査を行わず、チャレンジページも異なります）。測定はループバック上で実施し、TLS、実ブラウザ、ストレージは使用していません。

手法、ばらつき、再実行コマンドは[ベンチマーク記録](benchmarks/results/README.md)を参照してください：[product-latest.md](benchmarks/results/product-latest.md)、[latency-latest.md](benchmarks/results/latency-latest.md)、[comparison-latest.md](benchmarks/results/comparison-latest.md)、[admission-latest.md](benchmarks/results/admission-latest.md)。各差異の詳細は技術ガイドの第 X 部で解説しています。

<a id="documentation"></a>

## ドキュメント

- [技術ガイド](https://insanai.github.io/sibuna/ja/book/)：概念、アルゴリズム、実例、測定結果。
- [ホワイトペーパー](https://insanai.github.io/sibuna/ja/whitepaper/)：アーキテクチャ、証明、設計の詳細。
- [運用ガイド](https://insanai.github.io/sibuna/ja/book/operations.html)：インストールとデプロイ。
- [リファレンス](https://insanai.github.io/sibuna/ja/book/reference.html)：CLI とプロトコルの詳細。
- [設計議論](https://insanai.github.io/sibuna/sid/)：設計判断とエンジニアリング仕様。
- [貢献ガイド](CONTRIBUTING.md)：ソースビルドと各種チェック。

<a id="other-software-to-consider"></a>

## あわせて検討できるソフトウェア

- [Anubis](https://github.com/TecharoHQ/anubis)：クローラートラフィックを抑えるためのブラウザチャレンジ。
- [BunkerWeb](https://github.com/bunkerity/bunkerweb)：nginx、ModSecurity、CRS、ボットチャレンジ。
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)：コネクター経由で利用する WAF エンジン。
- [Coraza](https://github.com/corazawaf/coraza)：ModSecurity ルールと CRS に対応した Go 製 WAF ライブラリ。
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)：WAF エンジン向けの攻撃検出ルールセット。

これらのプロジェクトは Web 防御の異なる領域をカバーしています。Sibuna の検査エンジンは内蔵型であり、CRS やその他の ModSecurity ルールセットは実行しません。より幅広いルール網羅性が必要なアプリでは、Sibuna を本格的な WAF と組み合わせて運用してください。

<a id="license"></a>

## ライセンス

Sibuna のライセンスは **LGPL 3.0 以降**です。このライセンスはエンジン、ライブラリ、ブラウザソルバー、および WebAssembly インターフェースを含むコンソールを対象とします。

適用範囲は [LICENSE](LICENSE)、条文全文は [LICENSES](LICENSES)、依存関係一覧は [NOTICE](NOTICE) を参照してください。各リリースタグでソースとビルドスクリプトを入手できます。

Sibuna は Vikrant Rathore が作成し、Ronak Rathore と Kanak Rathore が協力しています。別のライセンス条件を希望する企業は Vikrant Rathore までお問い合わせください。サードパーティ製ライブラリおよび資料には、それぞれのライセンスが適用されます。
