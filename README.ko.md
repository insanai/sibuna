<!-- English source SHA-256: 0e595d6fb27cba412aeae226ee13400d0d2eb66ac54aef03dace51a4a43911fb -->
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

**Sibuna는 웹사이트와 API가 원치 않는 봇 트래픽에 대응하도록 돕습니다.** 앱으로 요청을 전달하거나 Caddy, nginx, Traefik 같은 기존 프록시와 함께 사용할 수 있습니다.

요청을 보내는 데 드는 비용은 적어도, 앱이 이를 처리하는 데는 더 많은 연산이 필요할 수 있습니다. Sibuna는 접근을 허용하기 전에 클라이언트에게 퍼즐을 풀도록 요청합니다. 증명을 만드는 데 검증보다 많은 연산이 들도록 설계된 퍼즐입니다. 이를 통해 자동화 클라이언트도 사이트 접근 비용의 일부를 부담하게 됩니다.

연산에는 에너지도 들지만, 그 양은 하드웨어와 설정에 따라 달라집니다. 작업 증명은 접근 비용을 더할 뿐, 방문자가 사람임을 증명하거나 모든 공격을 막지는 않습니다. 접근이 허용된 클라이언트는 서명된 세션으로 다시 방문할 수 있어 요청마다 새 퍼즐을 풀 필요가 없습니다. 이후 요청에는 접근 규칙과 로컬 속도 제한을 적용하세요.

<a id="features"></a>

## 기능

- **실행 파일 하나:** 엔진, 내장 저장소, 브라우저 솔버와 콘솔 리소스를 포함합니다.
- **네이티브 패키지:** Linux, macOS, Windows를 지원합니다. 브라우저 솔버는 WebAssembly를 사용합니다.
- **브라우저 챌린지:** Hashcash 또는 순차 작업 증명을 설정할 수 있습니다. 완료하면 서명된 세션을 발급합니다.
- **접근 정책:** 주소, 경로, 헤더, User-Agent에 따라 요청을 허용하거나 챌린지를 제시하거나 거부합니다.
- **앱 검사:** SQL 인젝션, XSS, 경로 탐색 공격을 검사하는 기능이 내장되어 있습니다.
- **선택형 OWASP CRS:** 서명된 규칙 업데이트, Audit와 Enforce 모드, 격리된 테스트와 롤백을 지원합니다.
- **로컬 속도 제한:** 순간적으로 몰리는 트래픽과 지속적인 트래픽을 제어합니다. 규칙별 제한도 설정할 수 있습니다.
- **운영 콘솔:** 트래픽, 표본으로 수집한 국가별 활동, 기록된 인시던트를 확인하고 정책을 편집합니다.
- **클러스터 지원:** 별도로 소스에서 빌드한 클러스터 버전은 Zaxonlite로 정책과 평판 데이터를 복제합니다.

<a id="quickstart"></a>

## 빠른 시작

플랫폼에 맞는 [릴리스를 다운로드하세요](https://github.com/insanai/sibuna/releases/tag/v0.3.5). 기본 패키지에는 저장소와 콘솔 지원이 포함됩니다. 콘솔은 `--console` 옵션으로 시작합니다.

| 플랫폼 | 패키지 | 요구 사항 |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 이상; musl 정적 링크 |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 이상; musl 정적 링크 |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 이상 |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 이상 |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 이상; 네이티브 `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-0.3.5-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI 패키지 |
| OpenBSD x86-64 | `sibuna-0.3.5.tgz` | OpenBSD 7.9; CLI 패키지 |

macOS 빌드에는 서명이 없습니다. 각 패키지에는 라이선스, 소스 링크와 빌드 명세가 포함됩니다. 사용하기 전에 `SHA256SUMS`로 압축 파일을 검증하세요.

Debian/RPM 패키지는 Linux x86-64와 ARM64를 지원하고 Arch `sibuna-bin`는 x86-64를 지원합니다. FreeBSD 15.1과 OpenBSD 7.9 패키지는 x86-64를 지원하며 CLI를 설치합니다. Linux 패키지는 선택적인 비활성 systemd 서비스를 포함합니다. BSD 패키지는 서비스, 계정, 상태를 생성하지 않습니다. 이는 업스트림 다운로드이며 커뮤니티 저장소 채택은 별도 절차입니다. 릴리스에는 Homebrew 소스 formula와 Helm 차트도 포함됩니다. 설치, 검증, 비공개 상태, 업그레이드, Kubernetes 설정은 [패키지 운영 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)를 참조하세요.

Linux x86-64에서 앱이 3000번 포트로 요청을 받는 경우:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

`http://127.0.0.1:8080`을 열어 로컬에서 시험할 수 있습니다. 공개 사이트에서는 신뢰할 수 있는 인그레스에서 HTTPS를 종료하고, Sibuna의 리스너는 외부에 공개하지 마세요. Caddy와 nginx 설정은 [배포 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)를 따르세요.

기본 모드는 `reverse_proxy`입니다. 인그레스가 요청을 전달하고 Sibuna에는 접근 여부만 묻는 구성이라면 `--mode forward_auth`를 사용하세요. 가이드에는 두 가지 구성이 모두 나와 있습니다. Shield의 내장 검사는 기본적으로 켜져 있습니다. 이 검사기 없이 접근 제어만 사용하려면 `--gate`를 지정하세요. `--policy-file <file>`로 접근 규칙을 선택할 수 있습니다. 브라우저 챌린지를 실행할 수 없는 API 클라이언트와 상태 점검에도 규칙을 마련하세요.

Windows에서는 ZIP을 풀고 PowerShell에서 `.\sibuna.exe --help`를 실행하세요. Ctrl+C로 종료합니다. Windows ACL로 시드, 자격 증명과 데이터 파일에 대한 접근을 제한하세요.

<a id="build-from-source"></a>

### 소스에서 빌드하기

**Zig 0.17.0**을 사용하세요. 고정된 도구 체인의 체크섬과 의존성 소스 정보는 저장소에 있습니다.

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

실행 파일은 `zig-out/bin/sibuna`에 생성됩니다. 클러스터 빌드에는 `-Dcluster=true`와 OpenSSL 3가 필요합니다. 빌드 검사는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

<a id="enable-owasp-crs"></a>

### OWASP CRS 활성화하기

CRS는 기본적으로 꺼져 있습니다. 지원되는 서명 릴리스를 다운로드하고 검증한 뒤 Audit로 시작하세요. CRS에 따른 거부를 적용하지 않고 검사 결과를 검토할 수 있습니다.

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

새 후보 디렉터리를 사용하세요. 후보를 검사해도 실행 중인 데몬은 바뀌지 않습니다. CLI와 콘솔에서 업데이트를 준비하고, 변경 사항을 검토하고, 검증된 후보를 선택할 수 있습니다. 앱의 정상 트래픽을 테스트하고 제외 항목을 검토한 후 Enforce를 시작하세요. 업데이트, 롤백, 본문 제한과 불완전한 검사는 [CRS 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)를 참고하세요. Forward-auth에는 `--crs-profile headers`가 필요하며, 이 모드에서는 앱의 전체 본문을 볼 수 없습니다.

<a id="console"></a>

## 콘솔

콘솔은 같은 실행 파일에서 동작합니다. 데몬을 중지한 상태에서 관리자 계정을 초기화하세요.

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

`http://127.0.0.1:19446/console/`을 열고 임시 비밀번호를 바꾸세요. [운영 가이드](https://insanai.github.io/sibuna/ko/book/operations.html)에는 HTTPS 접근, GeoIP 가져오기와 CRS 업데이트가 설명되어 있습니다. 콘솔과 함께 검사를 켜려면 위 예제의 CRS 옵션을 명령에 추가하세요.

![Sibuna 콘솔의 지구본, 요청 타임라인과 관측 범위](docs/readme/images/console-globe.jpg)

지구본은 최근 1분 동안 표본으로 수집한 국가별 활동을 보여 줍니다. 표식은 국가의 대략적인 위치를 나타내고, 화살표는 설정된 서버 위치를 향합니다. 개별 실시간 연결을 표시하는 것은 아닙니다. GeoIP 데이터셋은 별도로 가져와야 합니다. `--console-location <latitude,longitude>`로 지구본에 서버 위치를 설정하세요.

<details>
<summary>트래픽 개요, 정책 편집기와 인시던트 조사</summary>

**트래픽 개요** — 요청 결과, 관측 시간 범위와 실시간 업데이트를 확인합니다.

![허용, 챌린지, 거부 요청 수가 표시된 Sibuna 콘솔 트래픽 개요](docs/readme/images/console-dashboard.jpg)

**정책 편집기** — 결제 경로에 적용하는 챌린지 규칙 예제입니다. 일치 조건과 설정을 명시합니다.

![결제 경로의 챌린지 규칙 초안이 표시된 Sibuna 콘솔 정책 편집기](docs/readme/images/console-policy-editor.jpg)

**인시던트 조사** — 기록된 증거와 민감 정보를 가린, 길이가 제한된 요청 헤더를 확인합니다.

![민감 정보가 가려진 헤더와 응답 상태가 표시된 Sibuna 콘솔 인시던트 증거](docs/readme/images/console-incident.jpg)

</details>

검토용 노드에서 v0.2.0을 실행하고 Chrome으로 찍은 화면입니다. 트래픽과 GeoIP 매핑은 테스트 데이터입니다. 표시된 수치는 벤치마크 결과가 아닙니다.

<a id="how-it-works"></a>

## 작동 방식

요청은 허용되거나, 챌린지를 받거나, 거부될 수 있습니다. 챌린지를 해결한 방문자는 서명된 세션을 받습니다. 이후 요청도 해당 정책과 속도 검사를 통과해야 합니다.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="퍼즐을 풀고 서명된 세션을 받은 뒤에도 후속 요청의 규칙을 검사합니다">
</picture>

Gate는 접근 규칙, 세션과 로컬 속도 제한을 검사합니다. Shield는 내장 공격 검사기를 추가합니다. 네이티브 CRS는 별도로 설정합니다. 먼저 Audit로 결과를 검토한 후 Enforce를 켜세요.

<details>
<summary>Gate, Shield와 Sibuna 내부 모듈</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate와 Shield의 요청 결정: 허용, 챌린지 또는 차단">
</picture>

그림은 Gate와 Shield의 내장 검사를 보여 줍니다. 선택형 CRS는 별도의 검사를 추가합니다. 유효한 세션도 해당 공격 검사나 요청 제한을 우회하지 않습니다.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna 내부 모듈의 역할">
</picture>

각 모듈은 네트워킹, 증명, 정책, 로컬 상태와 관리를 나누어 담당합니다. [기술 안내서](https://insanai.github.io/sibuna/ko/book/)에서 그 역할을 설명합니다.

</details>

<a id="deployment-limits"></a>

### 배포 제한

Sibuna의 비공개 리스너는 HTTP/1.1을 사용합니다. 공개 TLS와 HTTP/2는 인그레스에서 처리합니다. Forward-auth는 인그레스가 제공한 메타데이터를 검사합니다. 리버스 프록시의 전체 CRS 검사는 설정된 본문 및 작업량 제한을 따릅니다. 내장 검사기는 본문의 첫 8 KiB를 검사합니다. CRS를 끄면 업로드는 스트리밍으로 전달됩니다. WebSocket 메시지는 검사 없이 중계합니다.
전체 CRS의 기본 제한은 요청 4 MiB, 응답 1 MiB입니다. 검사를 위해 본문을 버퍼링합니다. Enforce는 불완전한 검사를 거부합니다. 켜기 전에 앱에 맞는 제한과 스트리밍 예외를 검토하세요.

속도 제한은 노드별로 적용됩니다. Sibuna는 대규모 네트워크 트래픽 공격을 완화하는 서비스가 아닙니다. 콘솔의 엄격한 성능 목표도 아직 공식적으로 통과하지 못했습니다. 운영 앱과 함께 콘솔을 켜기 전에 [배포 제한과 측정 결과](https://insanai.github.io/sibuna/ko/book/operations.html)를 검토하세요.

<a id="benchmarks"></a>

## 벤치마크

안내서는 각 실행의 소스 리비전, 설정과 호스트를 기록합니다. 이 측정은 특정 작업 부하에서의 요청 비용을 보여 줍니다. 동등한 보호 수준이나 봇 탐지 정확도를 측정하지는 않습니다.

<a id="three-product-comparison"></a>

### 세 제품 비교

2026년 10월 4일에 **Sibuna v0.2.0**, Anubis 1.27.0, BunkerWeb 1.6.15를 비교했습니다. 서버와 요청 생성기는 서로 다른 물리 호스트에서 실행했습니다. 각 제품에 CPU 네 개와 연결 64개를 사용했고, 동일한 Caddy 원본 서버를 두었습니다. 챌린지와 관리 인터페이스는 비활성 상태였습니다. 표는 다섯 번 실행한 결과의 중앙값입니다.

| 구성 | 정상 GET (req/s) | p99 (ms) | 8 KiB JSON POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| 원본 서버 직접 접근 | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS 꺼짐 | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS 켜짐 | 2,730 | 32.73 | 797 | 98.42 |

이 표에서 BunkerWeb의 CRS 구성은 v0.2.0 Shield 구성보다 넓은 범위를 검사합니다. Sibuna v0.3.0에서 네이티브 CRS를 추가했으며, 이 비교는 그 엔진이 추가되기 전에 수행했습니다. 두 호스트는 공유 컨테이너입니다. CPU 주파수와 다른 호스트 작업은 통제하지 않았습니다.

<a id="native-crs-in-v030"></a>

### v0.3.0의 네이티브 CRS

이 별도 실행에서는 대시보드 여덟 개와 제품용 CPU 네 개를 사용했습니다. 다른 호스트에서 연결 16개를 생성했습니다. 표는 다섯 라운드의 처리율 중앙값입니다. 내장 검사기는 꺼 두었습니다.

| 작업 부하 | CRS 꺼짐 (req/s) | Audit, paranoia 수준 1 (req/s) | Audit, paranoia 수준 2 (req/s) |
| --- | ---: | ---: | ---: |
| 작은 GET | 47,311 | 10,787 | 7,423 |
| 8 KiB JSON POST | 13,726 | 1,151 | 799 |
| 16 KiB multipart 업로드 | 6,704 | 4,248 | 2,887 |

paranoia 수준 1에서 각 작업 부하의 p99 지연 시간은 2.34 ms, 23.43 ms, 6.34 ms였습니다. CRS 구성별 프로세스 최대 RSS는 133.8–140.5 MiB였습니다. 측정한 요청 중 작업량 제한에 도달한 요청은 없었습니다. 깨끗한 소스 리비전 `d461e7f`을 사용했습니다. 페이로드와 동시성 조건이 세 제품 비교와 다르므로 두 표를 같은 조건의 비교로 볼 수는 없습니다.

범위, CPU, 메모리, Enforce 결과와 재실행 명령은 [벤치마크 기록](benchmarks/results/README.md)을 참고하세요. 이 수치가 별도의 console-impact 기준을 통과했다는 뜻은 아닙니다.

<a id="documentation"></a>

## 문서

- [기술 안내서](https://insanai.github.io/sibuna/ko/book/): 개념, 알고리즘, 예제와 측정 결과.
- [백서(영문)](https://insanai.github.io/sibuna/whitepaper/): 아키텍처, 증명과 설계 세부 사항.
- [운영 가이드](https://insanai.github.io/sibuna/ko/book/operations.html): 설치와 배포.
- [참조 문서](https://insanai.github.io/sibuna/ko/book/reference.html): CLI와 프로토콜 세부 사항.
- [설계 논의(영문)](https://insanai.github.io/sibuna/sid/): 결정과 엔지니어링 계약.
- [기여 안내(영문)](CONTRIBUTING.md): 소스 빌드와 검사.

<a id="other-software-to-consider"></a>

## 함께 검토할 소프트웨어

- [Anubis](https://github.com/TecharoHQ/anubis): 크롤러 트래픽을 줄이는 브라우저 챌린지.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS와 봇 챌린지.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): 커넥터를 통해 사용하는 WAF 엔진.
- [Coraza](https://github.com/corazawaf/coraza): ModSecurity 규칙과 CRS를 지원하는 Go WAF 라이브러리.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): WAF 엔진용 공격 탐지 규칙.

이 프로젝트들은 웹 보호의 서로 다른 영역을 다룹니다. Sibuna는 서명된 기본 CRS 릴리스를 평가합니다. 플러그인, Lua와 다른 ModSecurity 규칙 집합은 지원 범위에 포함되지 않습니다.

<a id="license"></a>

## 라이선스

엔진은 **LGPL 3.0**입니다. WebAssembly 인터페이스를 포함한 콘솔은 **AGPL 3.0**입니다. 기본 실행 파일은 둘을 함께 포함하며 AGPL 3.0으로 배포합니다. `-Dconsole=false`로 콘솔 없이 엔진을 빌드할 수 있습니다.

[LICENSE](LICENSE)는 적용 범위를 설명합니다. [LICENSES](LICENSES)에는 전체 약관이 있고, [NOTICE](NOTICE)에는 의존성이 나열되어 있습니다. 각 릴리스 태그에서 소스와 빌드 스크립트를 확인할 수 있습니다.

다른 라이선스 조건이 필요한 회사는 Vikrant Rathore와 Ronak Rathore에게 문의할 수 있습니다. 타사 라이브러리와 자료에는 각각의 라이선스가 적용됩니다.
