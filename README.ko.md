<!-- English source SHA-256: cc1aaa74c7ebf304bf574d29f14c1d1eb9196b30744f92f833e9d2712778bbb8 -->
<h1 align="center">sibuna</h1>
<p align="center">분산 로드 밸런서와 웹 애플리케이션 방화벽</p>
<p align="center">
  <a href="#features">기능</a> ·
  <a href="#load-balancing">로드 밸런싱</a> ·
  <a href="#beside-haproxy-and-envoy">벤치마크</a> ·
  <a href="#quickstart">빠른 시작</a> ·
  <a href="#console">콘솔</a> ·
  <a href="#how-it-works">작동 방식</a> ·
  <a href="#documentation">문서</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

Sibuna는 TCP, UDP, HTTP 트래픽을 정상 서버로 전달합니다. 에지 하나를 운영하거나 여러 에지를 메시로 연결하고, 각 에지에서 TLS를 종료하고 선택한 HTTP 경로에 방화벽을 적용할 수 있습니다.

## Sibuna 활용 사례

- **공개 웹사이트**

  HTTP/2 또는 HTTP/3로 브라우저 요청을 받고 Let's Encrypt로 공개 인증서를 갱신합니다. 요청을 검사한 뒤 HTTP/1.1 복제 서버로 전달합니다.
- **내부 gRPC 서비스**

  로컬 CA로 내부 이름의 인증서를 발급합니다. 클라이언트는 루트 인증서를 신뢰하고 TLS로 서비스를 호출합니다. HTTP/2 백엔드가 gRPC 메시지와 트레일러를 전달합니다.
- **에지 노드 클러스터**

  검증한 라우팅 설정을 메시에 배포합니다. 각 노드는 자체 백엔드 풀로 트래픽을 전달하면서 차단 정보와 학습한 서버 할당을 공유할 수 있습니다.

[Sibuna란 무엇인가](https://insanai.github.io/sibuna/ko/book/introduction.html)

<a id="features"></a>

## 기능

- **실행 파일 하나:** 엔진, 내장 SQLite 저장소, 브라우저 솔버와 콘솔 리소스를 포함합니다.
- **네이티브 패키지:** Linux, macOS, Windows, FreeBSD, OpenBSD를 지원합니다. 브라우저 솔버는 WebAssembly를 사용합니다.
- **브라우저 챌린지:** 순차 작업 증명(기본값) 또는 Hashcash를 사용합니다. 완료하면 서명된 세션을 발급합니다.
- **접근 정책:** 주소, 경로, 헤더, User-Agent에 따라 요청을 허용하거나, 챌린지를 제시하거나, 가중치를 매기거나, 거부합니다.
- **로드 밸런싱:** 여러 서버 앞에서 TCP, UDP, HTTP를 처리하며 TLS 종료, 자동 인증서, 클러스터 모드를 지원합니다. [로드 밸런싱](#load-balancing)을 참고하세요.
- **TLS 지문:** 신뢰할 수 있는 인그레스가 전달한 JA4 지문을 정확히 일치하거나 접두사로 비교합니다.
- **앱 검사:** SQL 인젝션, XSS, 경로 탐색, 명령 인젝션을 검사하는 기능이 내장되어 있습니다.
- **로컬 속도 제한:** 순간적으로 몰리는 트래픽과 지속적인 트래픽을 제어합니다. 규칙별 제한도 설정할 수 있습니다.
- **운영 콘솔:** 트래픽, 표본으로 수집한 국가별 활동, 기록된 인시던트를 확인하고 정책을 편집합니다.
- **클러스터 지원:** 별도 빌드는 PostgreSQL을 통해 정책과 평판 데이터를 공유합니다.

<a id="load-balancing"></a>

## 로드 밸런싱

Sibuna 1.0.0-rc.3에는 엣지 모드가 포함됩니다. [소스에서 릴리스 후보를 빌드](#build-from-source)할 수도 있습니다.

```sh
sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80
sibuna lb --tls auto --domain example.org --server 10.0.0.1:80
sibuna lb --bind :8080 --server 10.0.0.1:80 --print-config > edge.jlv
sibuna check -f edge.jlv
sibuna --config-file edge.jlv
```

[Jlavi로 Sibuna 구성하기](https://insanai.github.io/sibuna/ko/book/jlavi.html)

- **전달:** TCP와 UDP, 서버 이름으로 라우팅하는 TLS 패스스루, QUIC 패스스루, PROXY 프로토콜.
- **HTTP:** HAProxy 형식의 PEM 번들로 TLS를 종료하고, 양자 내성 키 교환(X25519MLKEM768)을 사용합니다. HTTP/1.1, HTTP/2, HTTP/3, WebSocket을 지원하고, 호스트 이름과 경로에 따라 HTTP/1.1, HTTP/2, HTTP/3 서버로 라우팅합니다. Linux에서는 이벤트 기반 워커가 연결을 처리하며, 워커는 프로세서마다 하나입니다.
- **인증서:** 갱신, 대체 인증 기관, 외부 계정 바인딩을 갖춘 ACME 자동 발급; 훅 프로그램, RFC 2136 업데이트 또는 Cloudflare API를 이용한 DNS 기반 와일드카드 인증서; OCSP 스테이플링; 가드 뒤에서 요청 시 발급하는 인증서; `localhost`, 내부 이름, IP 주소를 위한 로컬 인증 기관. 로컬 인증 기관은 폐기 목록과 자체 ACME 서버를 갖추고 있습니다.
- **서버:** 헬스 체크, 슬로 스타트, 드레이닝, 가중치, 스티키 세션, 서버별 플로 수 제한.
- **실행 중 변경:** 설정을 성공적으로 다시 불러오면 기존 TCP 연결이 유지됩니다. 관리 소켓으로 서버를 드레이닝하고, 가중치를 바꾸고, 추가하고, 제거합니다(`sibuna ctl /run/sibuna/edge.sock set server app/10.0.0.1:80 state drain`). Linux에서는 새 실행 파일이 이전 실행 파일에서 리스닝 소켓과 UDP 매핑을 넘겨받습니다. QUIC 연결은 끊어집니다.
- **클러스터:** 메시의 노드는 스티키 테이블과 서버의 플로 제한을 공유하고, 클라이언트를 그 클라이언트를 소유한 노드로 전달합니다. PostgreSQL 데이터베이스는 하나의 설정을 모든 노드에 배포하고 되돌릴 수 있습니다. 매핑된 파일이 재시작 후에도 어피니티 힌트를 유지합니다.
- **훅:** 연결 단계와 요청 단계에서 실행됩니다. 함께 컴파일하거나, 예산이 정해진 WebAssembly로, 또는 Unix 소켓의 에이전트로 실행합니다.
- **관측:** 메트릭, 액세스 로그, 서버와 플로와 거부를 보여 주는 콘솔 화면.

Gate 또는 Shield는 필요한 이름에만 적용하거나, 어디에도 적용하지 않을 수 있습니다. 설정 파일이 기준으로 남습니다. 실행 중의 변경은 다음에 설정을 다시 불러올 때까지만 유지됩니다.

프로덕션 트래픽 검증은 아직 남아 있습니다. 클러스터 기능은 호스트 세 대에서 테스트했습니다. 각 [설계 논의](https://insanai.github.io/sibuna/sid/)에 구현된 내용과 알려진 한계가 정리되어 있습니다.

<a id="quickstart"></a>

## 빠른 시작

플랫폼에 맞는 [릴리스를 다운로드하세요](https://github.com/insanai/sibuna/releases/tag/v1.0.0-rc.3). 기본 패키지에는 저장소와 콘솔 지원이 포함됩니다. 콘솔은 `--console` 옵션으로 시작합니다.

| 플랫폼 | 패키지 | 요구 사항 |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 이상; musl 정적 링크 |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 이상; musl 정적 링크 |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 12 이상 |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 12 이상 |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2016 이상; 네이티브 `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-1.0.0-rc.3-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI 패키지 |
| OpenBSD x86-64 | `sibuna-1.0.0-rc.3.tgz` | OpenBSD 7.9; CLI 패키지 |

macOS 빌드에는 서명이 없습니다. 각 패키지에는 라이선스, 소스 링크와 빌드 명세가 포함됩니다. 사용하기 전에 `SHA256SUMS`로 압축 파일을 검증하세요.

Debian/RPM 패키지는 Linux x86-64와 ARM64를 지원하고, Arch `sibuna-bin`은 x86-64를 지원합니다. FreeBSD 15.1과 OpenBSD 7.9 패키지는 x86-64를 지원하며 CLI를 설치합니다. Linux 패키지에는 선택적인 systemd 서비스가 비활성 상태로 포함됩니다. BSD 패키지는 서비스, 계정, 상태를 만들지 않습니다. 이는 업스트림 다운로드이며, 커뮤니티 저장소 채택은 별개입니다. 릴리스에는 Helm 차트와 컨테이너 이미지 `ghcr.io/insanai/sibuna`도 포함됩니다. 설치, 검증, 비공개 상태, 업그레이드, Kubernetes 설정은 [패키지 운영 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)를 참고하세요.

[Sibuna Homebrew tap](https://github.com/insanai/homebrew-sibuna)은 검증된 릴리스 압축 파일을 설치하는 CLI formula를 제공합니다. macOS와 Linux(Apple Silicon, ARM64, x86-64)를 지원합니다. tap은 게시된 최신 릴리스를 따릅니다. 설치해도 서비스는 시작되지 않습니다:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

Linux x86-64에서 앱이 3000번 포트로 요청을 받는 경우:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-rc.3/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-rc.3/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

`http://127.0.0.1:8080`을 열어 로컬에서 시험할 수 있습니다. 공개 사이트에서는 신뢰할 수 있는 인그레스에서 HTTPS를 종료하고, Sibuna의 리스너는 외부에 공개하지 마세요. Caddy나 nginx 설정은 [배포 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)를 따르세요.

기본 모드는 `reverse_proxy`입니다. 인그레스가 요청을 전달하고 Sibuna에 접근 결정을 묻는 구성이라면 `--mode forward_auth`를 사용하세요. 가이드에는 두 가지 구성이 모두 나와 있습니다. Shield의 내장 검사는 기본적으로 켜져 있습니다. 이 검사기 없이 접근 제어만 사용하려면 `--gate`를 지정하세요. `--policy-file <file>`로 접근 규칙을 선택하세요. 여기에는 브라우저 챌린지를 실행할 수 없는 API 클라이언트와 상태 점검을 위한 규칙도 포함됩니다. `./sibuna --help`는 모든 옵션을 보여 줍니다.

Windows에서는 ZIP을 풀고 PowerShell에서 `.\sibuna.exe --help`를 실행하세요. Ctrl+C로 종료합니다. Windows ACL로 시드, 자격 증명과 데이터 파일에 대한 접근을 제한하세요.

<a id="build-from-source"></a>

### 소스에서 빌드하기

**Rust 1.100**로 빌드하고 테스트합니다. 기본 JLV 컴파일러에 이 버전이 필요합니다. JSON 전용 데몬은 Rust 1.100에서 `--no-default-features`로 빌드하고, 필요에 따라 `sqlite,console`을 선택할 수 있습니다. 브라우저 솔버와 콘솔 인터페이스는 WebAssembly로 컴파일한 Rust 코드입니다. 빌드에는 Node나 npm이 필요하지 않습니다.

```sh
git clone https://github.com/insanai/sibuna.git
cd sibuna
rustup toolchain install 1.100.0 --profile minimal --target wasm32-unknown-unknown
cargo +1.100.0 build --release -p sibuna
```

실행 파일은 `target/release/sibuna`입니다. `--data-dir`을 지정하면 상태를 SQLite에 저장합니다. 클러스터 빌드는 `--features postgres-tls`를 사용하며, `--database-url-file`과 `--cluster-node`로 하나의 PostgreSQL 데이터베이스를 공유합니다. 테스트, 린트, 크기 검사는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

<a id="console"></a>

## 콘솔

콘솔은 같은 실행 파일에서 동작합니다. 데몬을 중지한 상태에서 관리자 계정을 초기화하세요:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

`http://127.0.0.1:19446/console/`을 열고 임시 비밀번호를 바꾸세요. [운영 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)에는 HTTPS 접근, GeoIP 가져오기, 사용자, API 토큰과 벽면 디스플레이가 설명되어 있습니다.

![탐색 메뉴, 국가별 활동 지구본, 요청 결과, 관측 범위와 국가별 샘플을 보여 주는 Sibuna 콘솔](docs/readme/images/console-globe-93225dc9.png)

지구본은 최근 1분 동안 표본으로 수집한 국가별 활동을 보여 줍니다. 표식은 국가의 대략적인 위치를 나타냅니다. 화살표는 설정된 서버 위치를 향합니다. 화살표가 개별 실시간 연결을 나타내는 것은 아닙니다. GeoIP 데이터셋은 별도로 가져와야 합니다. `--console-location <latitude,longitude>`로 지구본에 서버 위치를 설정하세요.

<details>
<summary>트래픽 개요, 보안 개요, 정책과 인시던트 조사</summary>

**트래픽 개요** - 실시간 요청 결과, 허용 및 챌린지 카운터, 노드 상태와 스파크라인.

![요청, 허용, 챌린지, 거부 수가 표시된 Sibuna 콘솔 트래픽 개요](docs/readme/images/console-traffic-fba02476.png)

**보안 개요** - 기록된 탐지 결과, 챌린지, 차단과 실시간 이벤트 피드를 확인합니다.

![검사, 챌린지, 차단, 허니팟 탐지 결과가 표시된 Sibuna 콘솔 보안 개요](docs/readme/images/console-security.png)

**정책** - 노드가 적용하는 규칙을 순서대로, 기록된 적중 횟수와 함께 보여 줍니다.

![적용된 구성과 허용 규칙이 표시된 Sibuna 콘솔 정책 페이지](docs/readme/images/console-policies.png)

**이벤트** - 기록된 인시던트를 모듈, 국가, 주소, 경로, 시간으로 필터링해 확인합니다.

![인시던트 필터와 기록된 SQL 인젝션 탐지 결과가 표시된 Sibuna 콘솔 이벤트 페이지](docs/readme/images/console-events.png)

</details>

지구본과 트래픽 개요는 v1.0.0-beta.2를 실행하는 일반 Chrome 창에서 캡처했으며, 다른 화면은 v1.0.0-beta.1입니다. 모든 캡처는 생성된 트래픽과 테스트 GeoIP 매핑을 사용하는 로컬 테스트 노드에서 촬영했습니다. 표시된 수치는 벤치마크 결과가 아닙니다.

<a id="how-it-works"></a>

## 작동 방식

프런트엔드가 연결을 받습니다. TCP와 UDP에서는 흐름마다 서버를 선택합니다. HTTP에서는 요청마다 호스트와 경로를 확인하고 해당 경로의 방화벽 정책을 적용한 뒤, 허용된 요청을 선택한 풀의 정상 서버로 보냅니다. 각 에지가 이 결정을 내리는 동안 피어들은 서버 할당 정보와 차단 목록의 변경 사항을 교환합니다.

요청은 허용되거나, 챌린지를 받거나, 거부될 수 있습니다. 챌린지를 해결한 방문자는 서명된 세션을 받습니다. 이후 요청도 해당 정책과 속도 제한 검사를 통과해야 합니다.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="퍼즐을 풀고 서명된 세션을 받은 뒤에도 후속 요청의 규칙을 검사합니다">
</picture>

Gate는 접근 규칙, 세션과 로컬 속도 제한을 검사합니다. Shield는 내장 공격 검사기를 추가합니다. 기본값은 Shield이며, 시작할 때 `--gate`를 지정하면 Gate를 사용합니다.

<details>
<summary>Gate, Shield와 Sibuna 내부의 크레이트</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate와 Shield의 요청 결정: 허용, 챌린지 또는 차단">
</picture>

그림은 Gate와 Shield의 내장 검사를 보여 줍니다. 유효한 세션도 해당 공격 검사나 요청 제한을 우회하지 않습니다.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna 내부 크레이트의 역할">
</picture>

각 크레이트는 네트워킹, 증명, 정책, 로컬 상태, 저장소와 관리를 나누어 담당합니다. [기술 안내서](https://insanai.github.io/sibuna/ko/book/)에서 그 역할을 설명합니다.

</details>

<a id="deployment-limits"></a>

### 배포 제한

비공개 리스너는 외부 인그레스 뒤에서 HTTP/1.1을 사용합니다. 엣지 모드에서는 Sibuna에서 TLS, HTTP/2, HTTP/3를 종료하고 HTTP/1.1, HTTP/2 또는 HTTP/3 서버 풀로 전달할 수 있습니다. Forward-auth는 인그레스가 제공한 메타데이터를 검사합니다. 리버스 프록시 모드에서 내장 검사기는 본문의 처음 8 KiB를 검사합니다. 업로드는 앱으로 스트리밍됩니다. WebSocket 메시지는 검사 없이 중계합니다. 검사기는 휴리스틱이며, 완전한 언어 파서가 아닙니다.

속도 제한은 노드별로 적용됩니다. Sibuna는 대규모 네트워크 트래픽 공격을 완화하는 기능을 제공하지 않습니다. 연결을 잃지 않는 실행 파일 교체와 이벤트 기반 워커는 Linux에만 있습니다. 챌린지는 이를 발급한 노드에 묶여 있으므로, 챌린지와 그 해답은 같은 노드로 라우팅하세요. 콘솔의 엄격한 성능 목표는 아직 공식적으로 통과하지 못했습니다. 운영 앱과 함께 콘솔을 켜기 전에 [배포 제한과 측정 결과](https://insanai.github.io/sibuna/ko/book/operations.html)를 검토하세요.

<a id="benchmarks"></a>

## 벤치마크

안내서는 각 실행의 소스 리비전, 설정과 호스트를 기록합니다. 이 측정은 한 머신에서 몇 가지 작업 부하를 처리할 때의 요청 비용을 보여 줍니다. 동등한 보호 수준이나 봇 탐지 정확도를 측정하지는 않습니다.

<a id="sibuna-on-one-host"></a>

### 호스트 한 대에서의 Sibuna

이 실행에는 AMD Ryzen 9 5950X를 사용했습니다. 데몬은 CPU 네 개를 사용했고 메모리에서 실행했습니다. 요청 생성기와 스텁 원본 서버는 다른 CPU 여덟 개에서 실행했습니다. `wrk`는 루프백으로 연결 64개를 사용했습니다. 수치는 세 번 실행한 결과의 중앙값입니다.

- Forward-auth 모드에서 모든 작업 부하는 초당 197,532에서 211,636개의 요청을 처리했습니다. p99는 305에서 327 us, 요청당 CPU 시간은 11.7에서 13.8 us였습니다. 병목은 요청 생성기였습니다.
- 프록시를 거친 요청은 초당 138,965에서 147,303개를 처리했습니다. 최대 메모리는 약 16 MiB였습니다.
- 허용된 요청을 초당 100,000개로 똑같이 보냈을 때, p99.9 지연 시간은 forward-auth 모드에서 62 us, 리버스 프록시 모드에서 150 us였습니다.

<a id="beside-haproxy-and-envoy"></a>

### HAProxy, Envoy와 함께 측정

2026년 11월 25일 같은 호스트에서 Sibuna, HAProxy 3.0.11, BoringSSL을 쓰는 Envoy 1.40.2를 측정했습니다. 각 프록시에 CPU 8개와 작업 스레드 8개를 할당했습니다. 같은 원본 서버, 인증서, 부하 생성기를 사용했고 루프백 연결 256개에서 2바이트 응답을 받았습니다. 처음 세 행은 8초씩 세 번 측정한 초당 요청 수의 중앙값입니다. 마지막 세 행은 측정 종료 시점의 상주 메모리입니다. 처리량의 편차는 최대 4%였고 모든 요청이 완료됐습니다.

| 사례 | Sibuna | HAProxy | Envoy |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 220,040 | 220,323 | 70,909 |
| TLS 위의 HTTP/1.1 | 174,611 | 165,199 | 63,399 |
| HTTP/2 | 104,132 | 153,899 | 68,972 |
| 상주 메모리, HTTP/1.1 | 14 MiB | 48 MiB | 58 MiB |
| 상주 메모리, TLS 위의 HTTP/1.1 | 21 MiB | 61 MiB | 61 MiB |
| 상주 메모리, HTTP/2 | 116 MiB | 112 MiB | 140 MiB |

평문 HTTP에서는 Sibuna와 HAProxy의 처리량이 거의 같았습니다. HTTP/2에서는 HAProxy가 Sibuna보다 약 48% 많은 요청을 처리했고 메모리도 조금 덜 사용했습니다. Envoy에는 정적 설정과 라우터 필터를 사용했습니다. 설정이나 부하를 바꾸면 결과도 달라질 수 있습니다. 이 짧은 측정으로는 동적 설정, 애플리케이션 지연 시간, 실제 네트워크 성능을 판단하기 어렵습니다. [벤치마크](https://insanai.github.io/sibuna/ko/book/benchmarks.html#sibuna-haproxy-and-envoy)

<a id="beside-anubis"></a>

### Anubis와 함께 측정

공식 Anubis 1.27.0 릴리스 바이너리를 같은 작업 부하, CPU와 요청 생성기로 측정했습니다. Hashcash 작업량은 맞추었습니다. Sibuna는 0인 비트 8개, Anubis는 0인 16진수 자리 2개입니다. 원본 서버는 `caddy respond`였습니다. 표는 세션이 있는 허용된 요청의 결과입니다.

| 허용된 요청 | Sibuna Gate | Sibuna Shield | Anubis 1.27.0 |
| --- | ---: | ---: | ---: |
| Forward auth, req/s | 210,682 | 208,635 | 36,509 |
| Forward auth, p99 | 305 us | 308 us | 7,477 us |
| Forward auth, 요청당 CPU | 12.1 us | 13.2 us | 106.3 us |
| 리버스 프록시, req/s | 106,376 | 103,298 | 19,398 |
| 리버스 프록시, p99 | 3,331 us | 3,321 us | 11,062 us |

두 번째 실행에서는 각 제품에 CPU 두 개를 주고 허용 처리 작업의 시간을 측정했습니다. Anubis는 기본 Ed25519 토큰으로 한 번, HS512 토큰으로 한 번 실행했습니다.

| 초당 작업 수 | Sibuna (키 기반 BLAKE3) | Anubis (Ed25519) | Anubis (HS512) |
| --- | ---: | ---: | ---: |
| 유효한 세션 검사 | 88,104 | 10,951 | 16,976 |
| 인증되지 않은 요청 검사 | 78,997 | 28,619 | 27,785 |
| 챌린지 시작 | 42,664 | 7,893 | 7,952 |
| 증명 검증 | 57,924 | 12,668 | 19,261 |

Sibuna의 최대 메모리는 16 MiB 근처에 머물렀습니다. Anubis는 forward-auth 모드에서 약 33 MiB, 리버스 프록시 모드에서 최대 약 600 MiB를 사용했습니다. Anubis는 널리 쓰이는 유능한 도구이며, 이 표는 순위가 아닙니다. 몇몇 행은 같은 조건의 비교가 아닙니다. forward-auth 모드에서 Anubis는 일부 경로에 직접 응답하고, 페이로드를 검사하지 않으며, 챌린지 페이지도 다릅니다. 이 실행은 루프백을 사용했고 TLS, 실제 브라우저, 저장소는 사용하지 않았습니다.

방법, 범위와 재실행 명령은 [벤치마크 기록](benchmarks/results/README.md)을 참고하세요: [product-latest.md](benchmarks/results/product-latest.md), [latency-latest.md](benchmarks/results/latency-latest.md), [comparison-latest.md](benchmarks/results/comparison-latest.md), [admission-latest.md](benchmarks/results/admission-latest.md). 기술 안내서의 제X부에서 각 차이를 설명합니다.

<a id="documentation"></a>

## 문서

- [기술 안내서](https://insanai.github.io/sibuna/ko/book/): 개념, 알고리즘, 예제와 측정 결과.
- [백서](https://insanai.github.io/sibuna/ko/whitepaper/): 아키텍처, 증명과 설계 세부 사항.
- [운영 가이드](https://insanai.github.io/sibuna/ko/book/operations.html): 설치와 배포.
- [참조 문서](https://insanai.github.io/sibuna/ko/book/reference.html): CLI와 프로토콜 세부 사항.
- [설계 논의](https://insanai.github.io/sibuna/sid/): 결정과 엔지니어링 계약.
- [기여 안내](CONTRIBUTING.md): 소스 빌드와 검사.

<a id="other-software-to-consider"></a>

## 함께 검토할 소프트웨어

- [Anubis](https://github.com/TecharoHQ/anubis): 크롤러 트래픽을 줄이는 브라우저 챌린지.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS와 봇 챌린지.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): 커넥터를 통해 사용하는 WAF 엔진.
- [Coraza](https://github.com/corazawaf/coraza): ModSecurity 규칙과 CRS를 지원하는 Go WAF 라이브러리.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): WAF 엔진용 공격 탐지 규칙.

이 프로젝트들은 웹 보호의 서로 다른 영역을 다룹니다. Sibuna의 검사기는 내장되어 있으며, CRS나 다른 ModSecurity 규칙 집합을 실행하지 않습니다. 앱에 더 넓은 범위의 규칙이 필요하다면 Sibuna를 완전한 WAF와 함께 사용하세요.

<a id="license"></a>

## 라이선스

Sibuna의 라이선스는 **LGPL 3.0 이상**입니다. 이 라이선스는 엔진, 라이브러리, 브라우저 솔버, 그리고 WebAssembly 인터페이스를 포함한 콘솔에 적용됩니다.

[LICENSE](LICENSE)는 적용 범위를 설명합니다. [LICENSES](LICENSES)에는 전체 약관이 있습니다. [NOTICE](NOTICE)에는 의존성이 나열되어 있습니다. 각 릴리스 태그에서 소스와 빌드 스크립트를 확인할 수 있습니다.

Sibuna는 Vikrant Rathore가 작성했으며, Ronak Rathore와 Kanak Rathore가 도왔습니다. 다른 라이선스 조건이 필요한 회사는 Vikrant Rathore에게 문의할 수 있습니다. 타사 라이브러리와 자료에는 각자의 라이선스가 적용됩니다.
