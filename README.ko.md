<!-- English source SHA-256: 331b33dcfa1187045c4d09efe004a4c272482ff10db48816f67090e01a0a80f8 -->
<h1 align="center">sibuna</h1>
<p align="center">브라우저 작업 증명과 선택형 콘솔로 웹 서비스를 보호합니다.</p>
<p align="center">
  <a href="#features">기능</a> ·
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

**Sibuna는 웹사이트와 API를 원치 않는 봇 트래픽으로부터 보호하도록 돕습니다.** 앱으로 요청을 전달하거나 Caddy, nginx 같은 기존 프록시와 함께 사용할 수 있습니다.

요청을 보내는 데는 대개 비용이 적게 듭니다. 그 요청을 처리하는 데는 앱이 더 많은 일을 해야 할 수 있습니다. Sibuna는 접근을 허용하기 전에 클라이언트에게 퍼즐을 풀도록 요청합니다. 이 퍼즐은 증명을 만드는 데 검증보다 많은 연산이 들도록 설계되었습니다. 이로써 자동화 클라이언트가 사이트 접근 비용을 더 많이 부담하게 됩니다.

연산에는 에너지도 들지만, 그 양은 하드웨어와 설정에 따라 달라집니다. 작업 증명은 접근 비용을 더합니다. 작업 증명은 방문자가 사람임을 증명하지 않으며 모든 공격을 막지도 않습니다. 접근이 허용된 클라이언트는 서명된 세션으로 다시 방문할 수 있어 요청마다 새 퍼즐을 풀 필요가 없습니다. 이후 이 클라이언트가 무엇을 요청할 수 있는지는 접근 규칙과 로컬 속도 제한으로 제어하세요.

<a id="features"></a>

## 기능

- **실행 파일 하나:** 엔진, 내장 SQLite 저장소, 브라우저 솔버와 콘솔 리소스를 포함합니다.
- **네이티브 패키지:** Linux, macOS, Windows, FreeBSD, OpenBSD를 지원합니다. 브라우저 솔버는 WebAssembly를 사용합니다.
- **브라우저 챌린지:** 순차 작업 증명(기본값) 또는 Hashcash를 사용합니다. 완료하면 서명된 세션을 발급합니다.
- **접근 정책:** 주소, 경로, 헤더, User-Agent에 따라 요청을 허용하거나, 챌린지를 제시하거나, 가중치를 매기거나, 거부합니다.
- **TLS 지문:** 신뢰할 수 있는 인그레스가 전달한 JA4 지문을 정확히 일치하거나 접두사로 비교합니다.
- **앱 검사:** SQL 인젝션, XSS, 경로 탐색, 명령 인젝션을 검사하는 기능이 내장되어 있습니다.
- **로컬 속도 제한:** 순간적으로 몰리는 트래픽과 지속적인 트래픽을 제어합니다. 규칙별 제한도 설정할 수 있습니다.
- **운영 콘솔:** 트래픽, 표본으로 수집한 국가별 활동, 기록된 인시던트를 확인하고 정책을 편집합니다.
- **클러스터 지원:** 별도 빌드는 PostgreSQL을 통해 정책과 평판 데이터를 공유합니다.

<a id="quickstart"></a>

## 빠른 시작

플랫폼에 맞는 [릴리스를 다운로드하세요](https://github.com/insanai/sibuna/releases/tag/v1.0.0-beta.2). 기본 패키지에는 저장소와 콘솔 지원이 포함됩니다. 콘솔은 `--console` 옵션으로 시작합니다.

| 플랫폼 | 패키지 | 요구 사항 |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 이상; musl 정적 링크 |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 이상; musl 정적 링크 |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 12 이상 |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 12 이상 |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2016 이상; 네이티브 `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-1.0.0-beta.2-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI 패키지 |
| OpenBSD x86-64 | `sibuna-1.0.0-beta.2.tgz` | OpenBSD 7.9; CLI 패키지 |

이번 릴리스는 베타 릴리스입니다. macOS 빌드에는 서명이 없습니다. 각 패키지에는 라이선스, 소스 링크와 빌드 명세가 포함됩니다. 사용하기 전에 `SHA256SUMS`로 압축 파일을 검증하세요.

Debian/RPM 패키지는 Linux x86-64와 ARM64를 지원하고, Arch `sibuna-bin`은 x86-64를 지원합니다. FreeBSD 15.1과 OpenBSD 7.9 패키지는 x86-64를 지원하며 CLI를 설치합니다. Linux 패키지에는 선택적인 systemd 서비스가 비활성 상태로 포함됩니다. BSD 패키지는 서비스, 계정, 상태를 만들지 않습니다. 이는 업스트림 다운로드이며, 커뮤니티 저장소 채택은 별개입니다. 릴리스에는 Helm 차트와 컨테이너 이미지 `ghcr.io/insanai/sibuna`도 포함됩니다. 설치, 검증, 비공개 상태, 업그레이드, Kubernetes 설정은 [패키지 운영 가이드](https://insanai.github.io/sibuna/book/operations.html)를 참고하세요.

[Sibuna Homebrew tap](https://github.com/insanai/homebrew-sibuna)은 검증된 릴리스 압축 파일을 설치하는 CLI formula를 제공합니다. macOS와 Linux(Apple Silicon, ARM64, x86-64)를 지원합니다. tap은 게시된 최신 릴리스를 따르므로 이번 베타도 이미 제공합니다. 설치해도 서비스는 시작되지 않습니다:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

Linux x86-64에서 앱이 3000번 포트로 요청을 받는 경우:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.2/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.2/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

`http://127.0.0.1:8080`을 열어 로컬에서 시험할 수 있습니다. 공개 사이트에서는 신뢰할 수 있는 인그레스에서 HTTPS를 종료하고, Sibuna의 리스너는 외부에 공개하지 마세요. Caddy나 nginx 설정은 [배포 가이드](https://insanai.github.io/sibuna/book/operations.html)를 따르세요.

기본 모드는 `reverse_proxy`입니다. 인그레스가 요청을 전달하고 Sibuna에 접근 결정을 묻는 구성이라면 `--mode forward_auth`를 사용하세요. 가이드에는 두 가지 구성이 모두 나와 있습니다. Shield의 내장 검사는 기본적으로 켜져 있습니다. 이 검사기 없이 접근 제어만 사용하려면 `--gate`를 지정하세요. `--policy-file <file>`로 접근 규칙을 선택하세요. 여기에는 브라우저 챌린지를 실행할 수 없는 API 클라이언트와 상태 점검을 위한 규칙도 포함됩니다. `./sibuna --help`는 모든 옵션을 보여 줍니다.

Windows에서는 ZIP을 풀고 PowerShell에서 `.\sibuna.exe --help`를 실행하세요. Ctrl+C로 종료합니다. Windows ACL로 시드, 자격 증명과 데이터 파일에 대한 접근을 제한하세요.

<a id="build-from-source"></a>

### 소스에서 빌드하기

**Rust 1.99**로 빌드하고 테스트합니다. 브라우저 솔버와 콘솔 인터페이스는 WebAssembly로 컴파일한 Rust 코드입니다. 빌드에는 Node나 npm이 필요하지 않습니다.

```sh
git clone https://github.com/insanai/sibuna.git
cd sibuna
rustup target add wasm32-unknown-unknown
cargo build --release -p sibuna
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

`http://127.0.0.1:19446/console/`을 열고 임시 비밀번호를 바꾸세요. [운영 가이드](https://insanai.github.io/sibuna/book/operations.html)에는 HTTPS 접근, GeoIP 가져오기, 사용자, API 토큰과 벽면 디스플레이가 설명되어 있습니다.

![Sibuna 콘솔의 지구본, 요청 타임라인과 관측 범위](docs/readme/images/console-globe.png)

지구본은 최근 1분 동안 표본으로 수집한 국가별 활동을 보여 줍니다. 표식은 국가의 대략적인 위치를 나타냅니다. 화살표는 설정된 서버 위치를 향합니다. 화살표가 개별 실시간 연결을 나타내는 것은 아닙니다. GeoIP 데이터셋은 별도로 가져와야 합니다. `--console-location <latitude,longitude>`로 지구본에 서버 위치를 설정하세요.

<details>
<summary>트래픽 개요, 보안 개요, 정책과 인시던트 조사</summary>

**트래픽 개요** - 요청 결과, 관측 시간 범위와 실시간 업데이트를 확인합니다.

![요청, 허용, 챌린지, 거부 수가 표시된 Sibuna 콘솔 트래픽 개요](docs/readme/images/console-traffic.png)

**보안 개요** - 기록된 탐지 결과, 챌린지, 차단과 실시간 이벤트 피드를 확인합니다.

![검사, 챌린지, 차단, 허니팟 탐지 결과가 표시된 Sibuna 콘솔 보안 개요](docs/readme/images/console-security.png)

**정책** - 노드가 적용하는 규칙을 순서대로, 기록된 적중 횟수와 함께 보여 줍니다.

![적용된 구성과 허용 규칙이 표시된 Sibuna 콘솔 정책 페이지](docs/readme/images/console-policies.png)

**이벤트** - 기록된 인시던트를 모듈, 국가, 주소, 경로, 시간으로 필터링해 확인합니다.

![인시던트 필터와 기록된 SQL 인젝션 탐지 결과가 표시된 Sibuna 콘솔 이벤트 페이지](docs/readme/images/console-events.png)

</details>

로컬 테스트 노드에서 v1.0.0-beta.1을 실행하고 헤드리스 Chromium으로 캡처한 화면입니다. 트래픽과 GeoIP 매핑은 테스트 데이터입니다. 표시된 수치는 벤치마크 결과가 아닙니다.

<a id="how-it-works"></a>

## 작동 방식

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

각 크레이트는 네트워킹, 증명, 정책, 로컬 상태, 저장소와 관리를 나누어 담당합니다. [기술 안내서](https://insanai.github.io/sibuna/book/)에서 그 역할을 설명합니다.

</details>

<a id="deployment-limits"></a>

### 배포 제한

Sibuna의 비공개 리스너는 HTTP/1.1을 사용합니다. 공개 TLS와 HTTP/2는 인그레스에서 처리합니다. Forward-auth는 인그레스가 제공한 메타데이터를 검사합니다. 리버스 프록시 모드에서 내장 검사기는 본문의 처음 8 KiB를 검사합니다. 업로드는 앱으로 스트리밍됩니다. WebSocket 메시지는 검사 없이 중계합니다. 검사기는 휴리스틱이며, 완전한 언어 파서가 아닙니다.

속도 제한은 노드별로 적용됩니다. Sibuna는 대규모 네트워크 트래픽 공격을 완화하는 기능을 제공하지 않습니다. 챌린지는 이를 발급한 노드에 묶여 있으므로, 챌린지와 그 해답은 같은 노드로 라우팅하세요. 콘솔의 엄격한 성능 목표는 아직 공식적으로 통과하지 못했습니다. 운영 앱과 함께 콘솔을 켜기 전에 [배포 제한과 측정 결과](https://insanai.github.io/sibuna/book/operations.html)를 검토하세요.

<a id="benchmarks"></a>

## 벤치마크

안내서는 각 실행의 소스 리비전, 설정과 호스트를 기록합니다. 이 측정은 한 머신에서 몇 가지 작업 부하를 처리할 때의 요청 비용을 보여 줍니다. 동등한 보호 수준이나 봇 탐지 정확도를 측정하지는 않습니다.

<a id="sibuna-on-one-host"></a>

### 호스트 한 대에서의 Sibuna

이 실행에는 AMD Ryzen 9 5950X를 사용했습니다. 데몬은 CPU 네 개를 사용했고 메모리에서 실행했습니다. 요청 생성기와 스텁 원본 서버는 다른 CPU 여덟 개에서 실행했습니다. `wrk`는 루프백으로 연결 64개를 사용했습니다. 수치는 세 번 실행한 결과의 중앙값입니다.

- Forward-auth 모드에서 모든 작업 부하는 초당 197,532에서 211,636개의 요청을 처리했습니다. p99는 305에서 327 us, 요청당 CPU 시간은 11.7에서 13.8 us였습니다. 병목은 요청 생성기였습니다.
- 프록시를 거친 요청은 초당 138,965에서 147,303개를 처리했습니다. 최대 메모리는 약 16 MiB였습니다.
- 허용된 요청을 초당 100,000개로 똑같이 보냈을 때, p99.9 지연 시간은 forward-auth 모드에서 62 us, 리버스 프록시 모드에서 150 us였습니다.

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

방법, 범위와 재실행 명령은 [벤치마크 기록](benchmarks/results/README.md)을 참고하세요: [product-latest.md](benchmarks/results/product-latest.md), [latency-latest.md](benchmarks/results/latency-latest.md), [comparison-latest.md](benchmarks/results/comparison-latest.md), [admission-latest.md](benchmarks/results/admission-latest.md). 기술 안내서의 제VIII부에서 각 차이를 설명합니다.

<a id="documentation"></a>

## 문서

- [기술 안내서](https://insanai.github.io/sibuna/book/): 개념, 알고리즘, 예제와 측정 결과.
- [백서](https://insanai.github.io/sibuna/whitepaper/): 아키텍처, 증명과 설계 세부 사항.
- [운영 가이드](https://insanai.github.io/sibuna/book/operations.html): 설치와 배포.
- [참조 문서](https://insanai.github.io/sibuna/book/reference.html): CLI와 프로토콜 세부 사항.
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
