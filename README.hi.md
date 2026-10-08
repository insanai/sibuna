<!-- English source SHA-256: 48d28acad3b10231e32c88bcf3d43e324be89f143fe1bea1ee6492a32e5a1c0e -->
<h1 align="center">sibuna</h1>
<p align="center">ब्राउज़र में proof of work और वैकल्पिक console के साथ वेब सुरक्षा।</p>
<p align="center">
  <a href="#features">सुविधाएँ</a> ·
  <a href="#quickstart">शुरुआत करें</a> ·
  <a href="#console">Console</a> ·
  <a href="#how-it-works">यह कैसे काम करता है</a> ·
  <a href="#documentation">दस्तावेज़</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**Sibuna websites और APIs को अनचाहे bot traffic से बचाने में मदद करता है।** यह requests आपके app तक forward कर सकता है। Caddy, nginx या Traefik जैसे मौजूदा proxy के साथ भी काम कर सकता है।

Requests भेजना अक्सर सस्ता होता है। उन्हें process करने में आपके app को अधिक काम करना पड़ सकता है। Sibuna पहुँच देने से पहले clients से puzzle हल करवाता है। Puzzle इस तरह बनाया गया है कि proof बनाना उसे verify करने से अधिक computation माँगे। Automated clients साइट तक पहुँचने की लागत में अधिक हिस्सा उठाते हैं।

Computation में ऊर्जा भी लगती है। मात्रा hardware और settings पर निर्भर है। Proof of work प्रवेश की लागत जोड़ता है। यह आगंतुक के मानव होने का प्रमाण नहीं है और हर attack नहीं रोकता। Signed session स्वीकृत clients को हर request पर नया puzzle किए बिना लौटने देता है। बाद में वे क्या माँग सकते हैं, इसे access rules और local rate limits से नियंत्रित करें।

<a id="features"></a>

## सुविधाएँ

- **एक executable:** engine, embedded storage, browser solver और console assets।
- **Native packages:** Linux, macOS और Windows। Browser solver WebAssembly उपयोग करता है।
- **Browser challenges:** configurable Hashcash या sequential work, फिर signed session।
- **Access policies:** address, path, headers और User-Agent से allow, challenge या deny करें।
- **Application inspection:** SQL injection, XSS और path traversal के built-in checks।
- **वैकल्पिक OWASP CRS:** signed rule updates, Audit और Enforce modes, private tests और rollback।
- **Local rate limits:** bursts और sustained traffic नियंत्रित करें। वैकल्पिक per-rule limits भी हैं।
- **Operator console:** traffic, sampled country activity, recorded incidents और policy editing।
- **Cluster support:** अलग source build Zaxonlite से policy और reputation replicate करता है।

<a id="quickstart"></a>

## शुरुआत करें

अपने platform के लिए [release डाउनलोड करें](https://github.com/insanai/sibuna/releases/tag/v0.3.3)। Default package में storage और console support हैं। Console `--console` से शुरू होता है।

| Platform | Package | आवश्यकताएँ |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 या बाद का; statically linked musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 या बाद का; statically linked musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 या बाद का |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 या बाद का |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 या बाद का; native `sibuna.exe` |

macOS builds unsigned हैं। हर package में licenses, source links और build manifest हैं। उपयोग से पहले archive को `SHA256SUMS` से verify करें।

Linux x86-64 पर, यदि आपका app port 3000 पर सुन रहा है:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

स्थानीय रूप से आज़माने के लिए `http://127.0.0.1:8080` खोलें। Public site में trusted ingress पर HTTPS terminate करें और Sibuna listener private रखें। Caddy या nginx के लिए [deployment guide](https://insanai.github.io/sibuna/hi/book/operations.html) का पालन करें।

Default mode `reverse_proxy` है। यदि ingress requests forward करता है और Sibuna से access decision पूछता है, तो `--mode forward_auth` उपयोग करें। Guide में दोनों configurations हैं। Shield का built-in inspection default में enabled है। उस inspector के बिना admission के लिए `--gate` उपयोग करें। `--policy-file <file>` से access rules चुनें। उन API clients और health checks के rules भी रखें जो browser challenge नहीं चला सकते।

Windows पर ZIP extract करें और PowerShell में `.\sibuna.exe --help` चलाएँ। रोकने के लिए Ctrl+C दबाएँ। Windows ACLs से seed, credential और data files तक पहुँच सीमित करें।

<a id="build-from-source"></a>

### Source से build करें

**Zig 0.17.0** उपयोग करें। Pinned toolchain checksums और dependency sources repository में हैं।

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

Executable `zig-out/bin/sibuna` है। Cluster builds `-Dcluster=true` उपयोग करते हैं और उन्हें OpenSSL 3 चाहिए। Build checks के लिए [CONTRIBUTING.md](CONTRIBUTING.md) देखें।

<a id="enable-owasp-crs"></a>

### OWASP CRS सक्षम करें

CRS default में disabled है। Supported signed release डाउनलोड और verify करें। फिर Audit में शुरू करें ताकि CRS denials लागू किए बिना findings देख सकें:

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

नया candidate directory उपयोग करें। Candidate जाँचने से running daemon नहीं बदलता। CLI और console updates तैयार कर सकते हैं, changes review कर सकते हैं और verified candidate select कर सकते हैं। Application के सामान्य traffic को test करने और exclusions review करने के बाद Enforce शुरू करें। Updates, rollback, body limits और incomplete inspection के लिए [CRS guide](https://insanai.github.io/sibuna/hi/book/operations.html) देखें। Forward-auth में `--crs-profile headers` चाहिए। यह application के पूरे bodies नहीं देखता।

<a id="console"></a>

## Console

Console उसी executable में चलता है। Daemon बंद हो तो administrator bootstrap करें:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

`http://127.0.0.1:19446/console/` खोलें और temporary password बदलें। [Operations guide](https://insanai.github.io/sibuna/hi/book/operations.html) HTTPS access, GeoIP imports और CRS updates बताती है। Console के साथ inspection सक्षम करने के लिए ऊपर के example की CRS flags जोड़ें।

![Sibuna Console का globe, request timeline और coverage](docs/readme/images/console-globe.jpg)

Globe पिछले minute की sampled country activity दिखाता है। Markers देशों की अनुमानित positions हैं। Arrows server की configured location की ओर जाते हैं। ये individual live connections नहीं दिखाते। GeoIP के लिए dataset अलग import करना पड़ता है। Server को globe पर रखने के लिए `--console-location <latitude,longitude>` सेट करें।

<details>
<summary>Traffic overview, policy editor और incident investigation</summary>

**Traffic overview** — request परिणामों, observation windows और live updates।

![Sibuna Console का traffic overview: admitted, challenged और denied request counters](docs/readme/images/console-dashboard.jpg)

**Policy editor** — स्पष्ट matchers और settings वाला checkout challenge rule का उदाहरण।

![Sibuna Console policy editor में checkout का draft challenge rule](docs/readme/images/console-policy-editor.jpg)

**Incident investigation** — recorded evidence और bounded, redacted request heads।

![Sibuna Console incident evidence में redacted headers और response state](docs/readme/images/console-incident.jpg)

</details>

ये review node पर v0.2.0 के Chrome captures हैं। Traffic और GeoIP mappings test data हैं। दिखाए गए counts benchmark results नहीं हैं।

<a id="how-it-works"></a>

## यह कैसे काम करता है

Request admitted, challenged या denied हो सकता है। Challenge हल करने वाला आगंतुक signed session पाता है। बाद के requests पर भी लागू policy और rate checks होते हैं।

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Puzzle हल करें, signed session पाएँ और बाद के requests पर rules जाँचें">
</picture>

Gate access rules, sessions और local rate limits जाँचता है। Shield built-in attack inspector जोड़ता है। Native CRS अलग configure होता है। Enforce सक्षम करने से पहले findings review करने के लिए इसे Audit में शुरू करें।

<details>
<summary>Gate, Shield और Sibuna के अंदर के modules</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate और Shield के request decisions: allow, challenge या block">
</picture>

Diagram built-in Gate और Shield checks दिखाता है। वैकल्पिक CRS अपना inspection जोड़ता है। Valid session लागू attack checks या request limits bypass नहीं करता।

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna के अंदर के modules की ज़िम्मेदारियाँ">
</picture>

Modules networking, proofs, policies, local state और management अलग रखते हैं। [पुस्तक](https://insanai.github.io/sibuna/hi/book/) उनकी ज़िम्मेदारियाँ समझाती है।

</details>

<a id="deployment-limits"></a>

### Deployment की सीमाएँ

Sibuna अपने private listener पर HTTP/1.1 उपयोग करता है। Public TLS और HTTP/2 आपके ingress सँभालता है। Forward-auth ingress से मिली metadata inspect करता है। Full reverse-proxy CRS inspection configured body और work limits उपयोग करता है। Built-in inspector पहले 8 KiB देखता है। CRS disabled हो तो uploads stream होते हैं। WebSocket messages बिना inspection relay होते हैं। Full CRS में default request limit 4 MiB और response limit 1 MiB है। यह inspection के लिए bodies buffer करता है। Enforce incomplete inspection मना करता है। इसे सक्षम करने से पहले application की limits और streaming exceptions review करें।

Rate limits हर node के लिए local हैं। Sibuna volumetric network mitigation नहीं देता। Strict console performance target औपचारिक रूप से pass नहीं हुआ है। Production app के साथ console सक्षम करने से पहले [deployment limits और measurements](https://insanai.github.io/sibuna/hi/book/operations.html) देखें।

<a id="benchmarks"></a>

## Benchmarks

पुस्तक हर run का source revision, configuration और host दर्ज करती है। ये measurements एक workload में request cost दिखाते हैं। ये equivalent protection या bot accuracy नहीं मापते।

<a id="three-product-comparison"></a>

### तीन products की तुलना

इस run ने 4 October 2026 को **Sibuna v0.2.0**, Anubis 1.27.0 और BunkerWeb 1.6.15 की तुलना की। Server और request generator अलग physical hosts पर थे। हर product को चार CPUs, 64 connections और वही Caddy origin मिले। Challenges और management interfaces inactive थे। Table पाँच runs के medians दिखाता है।

| Profile | सामान्य GET (req/s) | p99 (ms) | 8 KiB JSON POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| सीधे origin | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS बंद | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS चालू | 2,730 | 32.73 | 797 | 98.42 |

इस table में BunkerWeb का CRS profile v0.2.0 Shield profile से अधिक inspect करता है। Sibuna v0.3.0 native CRS जोड़ता है। तुलना उस engine से पहले की है। दोनों hosts shared containers हैं। CPU frequency और अन्य host activity नियंत्रित नहीं थीं।

<a id="native-crs-in-v030"></a>

### v0.3.0 में native CRS

इस अलग run में आठ dashboards, product के लिए चार CPUs और दूसरे host से 16 connections थे। Table पाँच rounds के median rates दिखाता है। Built-in inspector disabled था।

| Workload | CRS disabled (req/s) | Audit, paranoia 1 (req/s) | Audit, paranoia 2 (req/s) |
| --- | ---: | ---: | ---: |
| छोटा GET | 47,311 | 10,787 | 7,423 |
| 8 KiB JSON POST | 13,726 | 1,151 | 799 |
| 16 KiB multipart upload | 6,704 | 4,248 | 2,887 |

Paranoia one पर इन workloads की p99 latency 2.34 ms, 23.43 ms और 6.34 ms थी। CRS profiles में peak process RSS 133.8–140.5 MiB था। कोई measured request work limit तक नहीं पहुँचा। Run में clean revision `d461e7f` था। इसके payloads और concurrency तीन-product comparison से अलग हैं। इसलिए दोनों tables matched comparison नहीं बनाते।

Ranges, CPU, memory, Enforce results और replay commands के लिए [benchmark records](benchmarks/results/README.md) देखें। ये figures अलग console-impact gate को pass नहीं करते।

<a id="documentation"></a>

## Documentation

- [पुस्तक](https://insanai.github.io/sibuna/hi/book/): concepts, algorithms, examples और measurements।
- [Whitepaper — English](https://insanai.github.io/sibuna/whitepaper/): architecture, proofs और design details।
- [Operations guide](https://insanai.github.io/sibuna/hi/book/operations.html): installation और deployment।
- [Reference](https://insanai.github.io/sibuna/hi/book/reference.html): CLI और protocol details।
- [Design discussions — English](https://insanai.github.io/sibuna/sid/): decisions और engineering contracts।
- [Contributing](CONTRIBUTING.md): source builds और checks।

<a id="other-software-to-consider"></a>

## अन्य software भी देखें

- [Anubis](https://github.com/TecharoHQ/anubis): crawler traffic घटाने के लिए browser challenges।
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS और bot challenges।
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): connectors से उपयोग किया जाने वाला WAF engine।
- [Coraza](https://github.com/corazawaf/coraza): ModSecurity rules और CRS support करने वाली Go WAF library।
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): WAF engines की attack-detection rules।

ये projects web protection के अलग हिस्सों को सँभालते हैं। Sibuna signed stock CRS releases evaluate करता है। Plugins, Lua और अन्य ModSecurity rule sets इसके scope के बाहर हैं।

<a id="license"></a>

## License

Engine **LGPL 3.0** के अंतर्गत है। Console और उसका WebAssembly interface **AGPL 3.0** के अंतर्गत हैं। Default executable दोनों को जोड़ता है और AGPL 3.0 के अंतर्गत वितरित होता है। Console के बिना engine build करने के लिए `-Dconsole=false` उपयोग करें।

[LICENSE](LICENSE) scope बताता है। [LICENSES](LICENSES) में पूरी terms हैं। [NOTICE](NOTICE) dependencies बताता है। Source और build scripts हर release tag में उपलब्ध हैं।

अन्य licensing terms चाहने वाली companies Vikrant Rathore और Ronak Rathore से संपर्क कर सकती हैं। Third-party libraries और materials अपने-अपने licenses रखते हैं।
