<!-- English source SHA-256: 331b33dcfa1187045c4d09efe004a4c272482ff10db48816f67090e01a0a80f8 -->
<h1 align="center">sibuna</h1>
<p align="center">ब्राउज़र में proof of work और वैकल्पिक कंसोल के साथ वेब सुरक्षा।</p>
<p align="center">
  <a href="#features">सुविधाएँ</a> ·
  <a href="#quickstart">त्वरित शुरुआत</a> ·
  <a href="#console">कंसोल</a> ·
  <a href="#how-it-works">कार्यप्रणाली</a> ·
  <a href="#documentation">दस्तावेज़</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**Sibuna वेबसाइटों और API को अनचाहे बॉट ट्रैफ़िक से बचाने में मदद करता है।** यह अनुरोधों को आपके ऐप तक फ़ॉरवर्ड कर सकता है, या Caddy या nginx जैसे किसी मौजूदा प्रॉक्सी के साथ काम कर सकता है।

अनुरोध भेजना अक्सर सस्ता होता है। उन्हें प्रोसेस करने में आपके ऐप को अधिक काम करना पड़ सकता है। Sibuna पहुँच देने से पहले क्लाइंट से एक पहेली हल करवाता है। पहेली इस तरह डिज़ाइन की गई है कि प्रमाण बनाने में उसके सत्यापन से अधिक गणना लगे। इससे साइट तक पहुँच की लागत का बड़ा हिस्सा स्वचालित क्लाइंट उठाते हैं।

गणना में ऊर्जा भी लगती है, लेकिन उसकी मात्रा हार्डवेयर और सेटिंग्स पर निर्भर करती है। proof of work प्रवेश की एक लागत जोड़ता है। यह न तो सिद्ध करता है कि आगंतुक मनुष्य है, न हर हमले को रोकता है। हस्ताक्षरित सत्र स्वीकृत क्लाइंट को हर अनुरोध पर नई पहेली हल किए बिना लौटने देता है। ये क्लाइंट बाद में क्या माँग सकते हैं, इसे पहुँच के नियमों और स्थानीय रेट लिमिट से नियंत्रित करें।

<a id="features"></a>

## सुविधाएँ

- **एक ही बाइनरी:** इंजन, एम्बेडेड SQLite स्टोरेज, ब्राउज़र सॉल्वर और कंसोल की फ़ाइलें।
- **नेटिव पैकेज:** Linux, macOS, Windows, FreeBSD और OpenBSD। ब्राउज़र सॉल्वर WebAssembly का उपयोग करता है।
- **ब्राउज़र चैलेंज:** अनुक्रमिक कार्य का प्रमाण (डिफ़ॉल्ट) या Hashcash, जिसके बाद हस्ताक्षरित सत्र मिलता है।
- **पहुँच नीतियाँ:** पते, पाथ, हेडर और User-Agent के आधार पर अनुरोधों को allow, challenge, weigh या deny करें।
- **TLS फ़िंगरप्रिंट:** विश्वसनीय इनग्रेस द्वारा फ़ॉरवर्ड किए गए JA4 फ़िंगरप्रिंट का ठीक-ठीक या प्रीफ़िक्स से मिलान करें।
- **एप्लिकेशन निरीक्षण:** SQL injection, XSS, path traversal और command injection के लिए बिल्ट-इन जाँचें।
- **स्थानीय रेट लिमिट:** बर्स्ट और लगातार ट्रैफ़िक को नियंत्रित करें, वैकल्पिक प्रति-नियम सीमाओं के साथ।
- **ऑपरेटर कंसोल:** ट्रैफ़िक, देशों की सैंपल की गई गतिविधि, दर्ज घटनाएँ और नीति संपादन।
- **क्लस्टर समर्थन:** एक अलग बिल्ड PostgreSQL के ज़रिए नीतियाँ और प्रतिष्ठा साझा करता है।

<a id="quickstart"></a>

## त्वरित शुरुआत

अपने प्लेटफ़ॉर्म के लिए [रिलीज़ डाउनलोड करें](https://github.com/insanai/sibuna/releases/tag/v1.0.0-beta.2)। डिफ़ॉल्ट पैकेज में स्टोरेज और कंसोल का समर्थन शामिल है। कंसोल `--console` के साथ शुरू होता है।

| प्लेटफ़ॉर्म | पैकेज | आवश्यकताएँ |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 या बाद का; स्टैटिक रूप से लिंक किया गया musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 या बाद का; स्टैटिक रूप से लिंक किया गया musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 12 या बाद का |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 12 या बाद का |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2016 या बाद का; नेटिव `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-1.0.0-beta.2-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI पैकेज |
| OpenBSD x86-64 | `sibuna-1.0.0-beta.2.tgz` | OpenBSD 7.9; CLI पैकेज |

यह एक बीटा रिलीज़ है। macOS बिल्ड अहस्ताक्षरित हैं। हर पैकेज में लाइसेंस, स्रोत के लिंक और एक बिल्ड manifest है। उपयोग से पहले आर्काइव को `SHA256SUMS` से सत्यापित करें।

Debian/RPM पैकेज Linux x86-64 और ARM64 के लिए हैं; Arch का `sibuna-bin` x86-64 के लिए है। FreeBSD 15.1 और OpenBSD 7.9 पैकेज x86-64 के लिए हैं और CLI इंस्टॉल करते हैं। Linux पैकेज में एक वैकल्पिक, अक्षम systemd सेवा शामिल है। BSD पैकेज कोई सेवा, खाता या संग्रहीत अवस्था नहीं बनाते। ये upstream डाउनलोड हैं; सामुदायिक रिपॉज़िटरी में स्वीकृति एक अलग विषय है। रिलीज़ में एक Helm chart और एक कंटेनर इमेज, `ghcr.io/insanai/sibuna`, भी है। इंस्टॉलेशन, सत्यापन, निजी अवस्था, अपग्रेड और Kubernetes सेटअप के लिए [पैकेज संचालन गाइड](https://insanai.github.io/sibuna/book/operations.html) देखें।

[Sibuna Homebrew tap](https://github.com/insanai/homebrew-sibuna) एक CLI फ़ॉर्मूला देता है, जो macOS और Linux (Apple Silicon, ARM64 और x86-64) के लिए सत्यापित रिलीज़ आर्काइव इंस्टॉल करता है। tap नवीनतम प्रकाशित रिलीज़ का अनुसरण करता है, इसलिए यह बीटा उसमें पहले से उपलब्ध है। इंस्टॉलेशन कोई सेवा शुरू नहीं करता:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

Linux x86-64 पर, जब आपका ऐप पोर्ट 3000 पर सुन रहा हो:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.2/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.2/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

स्थानीय रूप से आज़माने के लिए `http://127.0.0.1:8080` खोलें। सार्वजनिक साइट के लिए HTTPS को किसी विश्वसनीय इनग्रेस पर टर्मिनेट करें और Sibuna का लिसनर निजी रखें। Caddy या nginx के लिए [डिप्लॉयमेंट गाइड](https://insanai.github.io/sibuna/book/operations.html) का पालन करें।

डिफ़ॉल्ट मोड `reverse_proxy` है। जब आपका इनग्रेस अनुरोधों को आगे भेजता है और Sibuna से पहुँच का निर्णय पूछता है, तब `--mode forward_auth` का उपयोग करें। गाइड में दोनों कॉन्फ़िगरेशन हैं। Shield का बिल्ट-इन निरीक्षण डिफ़ॉल्ट रूप से सक्षम है। उस निरीक्षक के बिना प्रवेश के लिए `--gate` का उपयोग करें। `--policy-file <file>` से पहुँच के नियम चुनें, जिनमें उन API क्लाइंट और health check के नियम भी हों जो ब्राउज़र चैलेंज नहीं चला सकते। `./sibuna --help` सभी विकल्पों की सूची देता है।

Windows पर ZIP को extract करें और PowerShell में `.\sibuna.exe --help` चलाएँ। रोकने के लिए Ctrl+C दबाएँ। सीड, credential और डेटा फ़ाइलों तक पहुँच Windows ACL से सीमित करें।

<a id="build-from-source"></a>

### स्रोत से बिल्ड करें

हम **Rust 1.99** के साथ बिल्ड और परीक्षण करते हैं। ब्राउज़र सॉल्वर और कंसोल इंटरफ़ेस WebAssembly में कंपाइल किया गया Rust कोड हैं; बिल्ड के लिए Node या npm की ज़रूरत नहीं होती।

```sh
git clone https://github.com/insanai/sibuna.git
cd sibuna
rustup target add wasm32-unknown-unknown
cargo build --release -p sibuna
```

बाइनरी `target/release/sibuna` है। `--data-dir` के साथ यह अपनी अवस्था SQLite में संग्रहीत करती है। क्लस्टर बिल्ड `--features postgres-tls` का उपयोग करते हैं और `--database-url-file` तथा `--cluster-node` के ज़रिए एक PostgreSQL डेटाबेस साझा करते हैं। परीक्षण, lint और आकार की जाँच के लिए [CONTRIBUTING.md](CONTRIBUTING.md) देखें।

<a id="console"></a>

## कंसोल

कंसोल उसी बाइनरी में चलता है। डेमन बंद रहते हुए एक एडमिनिस्ट्रेटर बूटस्ट्रैप करें:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

`http://127.0.0.1:19446/console/` खोलें और अस्थायी पासवर्ड बदलें। [संचालन गाइड](https://insanai.github.io/sibuna/book/operations.html) HTTPS पहुँच, GeoIP आयात, उपयोगकर्ता, API टोकन और wall display के बारे में बताता है।

![Sibuna कंसोल ग्लोब, अनुरोध समयरेखा और कवरेज](docs/readme/images/console-globe.png)

ग्लोब पिछले एक मिनट में देशों की सैंपल की गई गतिविधि दिखाता है। मार्कर देशों की अनुमानित स्थिति बताते हैं। तीर सर्वर के कॉन्फ़िगर किए गए स्थान की ओर इशारा करते हैं। वे अलग-अलग लाइव कनेक्शन नहीं दिखाते। GeoIP के लिए अलग से आयात किया गया डेटासेट चाहिए। सर्वर को ग्लोब पर रखने के लिए `--console-location <latitude,longitude>` सेट करें।

<details>
<summary>ट्रैफ़िक अवलोकन, सुरक्षा अवलोकन, नीतियाँ और घटना जाँच</summary>

**ट्रैफ़िक अवलोकन** - अनुरोधों के परिणाम, अवलोकन विंडो और लाइव अपडेट।

![अनुरोध, प्रवेश, चैलेंज और अस्वीकृति के काउंटरों वाला Sibuna कंसोल का ट्रैफ़िक अवलोकन](docs/readme/images/console-traffic.png)

**सुरक्षा अवलोकन** - दर्ज निष्कर्ष, चैलेंज, प्रतिबंध और लाइव इवेंट फ़ीड।

![निरीक्षण, चैलेंज, प्रतिबंध और हनीपॉट निष्कर्षों के साथ Sibuna कंसोल सुरक्षा अवलोकन](docs/readme/images/console-security.png)

**नीतियाँ** - वे नियम जिन्हें कोई नोड क्रम से लागू करता है, उनके दर्ज हिट के साथ।

![लागू कॉन्फ़िगरेशन और एक allow नियम वाला Sibuna कंसोल का नीतियाँ पेज](docs/readme/images/console-policies.png)

**इवेंट** - दर्ज घटनाएँ, मॉड्यूल, देश, पते, पाथ और समय के अनुसार फ़िल्टर के साथ।

![घटना फ़िल्टर और दर्ज SQL injection निष्कर्षों वाला Sibuna कंसोल का इवेंट पेज](docs/readme/images/console-events.png)

</details>

ये एक स्थानीय परीक्षण नोड पर v1.0.0-beta.1 के headless Chromium कैप्चर हैं। ट्रैफ़िक और GeoIP मैपिंग परीक्षण डेटा हैं। दिखाई गई संख्याएँ बेंचमार्क परिणाम नहीं हैं।

<a id="how-it-works"></a>

## यह कैसे काम करता है

अनुरोध को प्रवेश दिया जा सकता है, चैलेंज किया जा सकता है या अस्वीकार किया जा सकता है। चैलेंज हल करने वाले आगंतुक को एक हस्ताक्षरित सत्र मिलता है। बाद के अनुरोध भी लागू नीति और रेट की जाँचों से गुज़रते हैं।

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="पहेली हल करें, हस्ताक्षरित सत्र पाएँ, और बाद के अनुरोधों पर नियम जाँचे जाते हैं">
</picture>

Gate पहुँच के नियमों, सत्रों और स्थानीय रेट लिमिट की जाँच करता है। Shield बिल्ट-इन आक्रमण-निरीक्षक जोड़ता है। Shield डिफ़ॉल्ट है; `--gate` स्टार्टअप पर Gate चुनता है।

<details>
<summary>Gate, Shield और Sibuna के भीतर के क्रेट</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate और Shield के अनुरोध-निर्णय: allow, challenge या block">
</picture>

यह आरेख Gate और Shield की बिल्ट-इन जाँचें दिखाता है। वैध सत्र लागू आक्रमण-जाँचों या अनुरोध सीमाओं को बायपास नहीं करता।

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna के भीतर के क्रेट और उनके काम">
</picture>

क्रेट नेटवर्किंग, प्रमाण, नीतियों, स्थानीय अवस्था, स्टोरेज और प्रबंधन को अलग रखते हैं। [पुस्तक](https://insanai.github.io/sibuna/book/) उनकी ज़िम्मेदारियाँ समझाती है।

</details>

<a id="deployment-limits"></a>

### डिप्लॉयमेंट की सीमाएँ

Sibuna अपने निजी लिसनर पर HTTP/1.1 का उपयोग करता है। सार्वजनिक TLS और HTTP/2 आपका इनग्रेस संभालता है। Forward-auth इनग्रेस द्वारा दिए गए मेटाडेटा का निरीक्षण करता है। रिवर्स-प्रॉक्सी मोड में बिल्ट-इन निरीक्षक बॉडी के पहले 8 KiB को ढकता है। अपलोड आपके ऐप तक स्ट्रीम होते हैं। WebSocket संदेश बिना निरीक्षण के रिले किए जाते हैं। निरीक्षक एक ह्यूरिस्टिक है, भाषा का पूरा पार्सर नहीं।

रेट लिमिट हर नोड पर स्थानीय हैं। Sibuna वॉल्यूमेट्रिक नेटवर्क हमलों से सुरक्षा नहीं देता। चैलेंज उन्हें जारी करने वाले नोड से बँधे हैं; चैलेंज और उसके समाधान को एक ही नोड तक रूट करें। कंसोल का सख़्त प्रदर्शन लक्ष्य अभी औपचारिक रूप से पूरा नहीं हुआ है। प्रोडक्शन ऐप के साथ कंसोल सक्षम करने से पहले [डिप्लॉयमेंट की सीमाएँ और मापन](https://insanai.github.io/sibuna/book/operations.html) देखें।

<a id="benchmarks"></a>

## बेंचमार्क

पुस्तक हर रन के लिए स्रोत revision, कॉन्फ़िगरेशन और होस्ट दर्ज करती है। ये मापन एक मशीन पर कुछ वर्कलोड के तहत अनुरोध की लागत दिखाते हैं। ये समान सुरक्षा या बॉट पहचान की सटीकता नहीं मापते।

<a id="sibuna-on-one-host"></a>

### एक होस्ट पर Sibuna

इन रन में AMD Ryzen 9 5950X का उपयोग हुआ। डेमन को चार CPU मिले और वह मेमोरी में चला; लोड जनरेटर और एक स्टब ऑरिजिन आठ अन्य CPU पर चले। `wrk` ने loopback पर 64 कनेक्शन उपयोग किए। आँकड़े तीन रन की माध्यिका हैं।

- forward-auth मोड में हर वर्कलोड प्रति सेकंड 197,532 से 211,636 अनुरोधों पर चला, 305 से 327 us के p99 और प्रति अनुरोध 11.7 से 13.8 us CPU के साथ। सीमा लोड जनरेटर की थी।
- प्रॉक्सी किए गए अनुरोध प्रति सेकंड 138,965 से 147,303 पर चले। पीक मेमोरी लगभग 16 MiB थी।
- प्रति सेकंड 100,000 स्वीकृत अनुरोधों के समान प्रस्तावित लोड पर p99.9 लेटेंसी forward-auth मोड में 62 us और रिवर्स-प्रॉक्सी मोड में 150 us थी।

<a id="beside-anubis"></a>

### Anubis के साथ

हमने Anubis 1.27.0 की आधिकारिक रिलीज़ बाइनरी को उन्हीं वर्कलोड, CPU और लोड जनरेटर के साथ मापा। Hashcash कार्य बराबर रखा गया: Sibuna के लिए 8 शून्य बिट, Anubis के लिए 2 शून्य हेक्स अंक। ऑरिजिन `caddy respond` था। तालिका सत्र वाले स्वीकृत अनुरोध दिखाती है।

| स्वीकृत अनुरोध | Sibuna Gate | Sibuna Shield | Anubis 1.27.0 |
| --- | ---: | ---: | ---: |
| Forward auth, req/s | 210,682 | 208,635 | 36,509 |
| Forward auth, p99 | 305 us | 308 us | 7,477 us |
| Forward auth, प्रति अनुरोध CPU | 12.1 us | 13.2 us | 106.3 us |
| रिवर्स प्रॉक्सी, req/s | 106,376 | 103,298 | 19,398 |
| रिवर्स प्रॉक्सी, p99 | 3,331 us | 3,321 us | 11,062 us |

दूसरे रन में प्रवेश ऑपरेशनों का समय मापा गया, हर उत्पाद दो CPU पर। Anubis एक बार अपने डिफ़ॉल्ट Ed25519 टोकन के साथ और एक बार HS512 टोकन के साथ चला।

| प्रति सेकंड ऑपरेशन | Sibuna (कुंजी-युक्त BLAKE3) | Anubis (Ed25519) | Anubis (HS512) |
| --- | ---: | ---: | ---: |
| वैध सत्र जाँच | 88,104 | 10,951 | 16,976 |
| अप्रमाणित जाँच | 78,997 | 28,619 | 27,785 |
| चैलेंज बूटस्ट्रैप | 42,664 | 7,893 | 7,952 |
| प्रमाण सत्यापन | 57,924 | 12,668 | 19,261 |

Sibuna की पीक मेमोरी लगभग 16 MiB रही। Anubis ने forward-auth मोड में लगभग 33 MiB और रिवर्स-प्रॉक्सी मोड में लगभग 600 MiB तक मेमोरी उपयोग की। Anubis एक व्यापक रूप से उपयोग होने वाला और सक्षम उपकरण है, और ये पंक्तियाँ कोई रैंकिंग नहीं हैं। कई पंक्तियाँ एक जैसी स्थितियों की तुलना नहीं करतीं: forward-auth मोड में Anubis कुछ पाथ का उत्तर स्वयं देता है, वह पेलोड का निरीक्षण नहीं करता, और चैलेंज पेज अलग हैं। रन loopback पर चले, बिना TLS, वास्तविक ब्राउज़र या स्टोरेज के।

विधि, श्रेणियों और दोबारा चलाने के कमांड के लिए [बेंचमार्क रिकॉर्ड](benchmarks/results/README.md) देखें: [product-latest.md](benchmarks/results/product-latest.md), [latency-latest.md](benchmarks/results/latency-latest.md), [comparison-latest.md](benchmarks/results/comparison-latest.md) और [admission-latest.md](benchmarks/results/admission-latest.md)। पुस्तक का भाग VIII हर अंतर पर चर्चा करता है।

<a id="documentation"></a>

## दस्तावेज़

- [पुस्तक](https://insanai.github.io/sibuna/book/): अवधारणाएँ, एल्गोरिदम, उदाहरण और मापन।
- [व्हाइटपेपर](https://insanai.github.io/sibuna/whitepaper/): आर्किटेक्चर, प्रमाण और डिज़ाइन का विवरण।
- [संचालन गाइड](https://insanai.github.io/sibuna/book/operations.html): इंस्टॉलेशन और डिप्लॉयमेंट।
- [संदर्भ](https://insanai.github.io/sibuna/book/reference.html): CLI और प्रोटोकॉल का विवरण।
- [डिज़ाइन चर्चाएँ](https://insanai.github.io/sibuna/sid/) (अंग्रेज़ी में): निर्णय और इंजीनियरिंग अनुबंध।
- [योगदान](CONTRIBUTING.md): स्रोत से बिल्ड और जाँचें।

<a id="other-software-to-consider"></a>

## अन्य विचारणीय सॉफ़्टवेयर

- [Anubis](https://github.com/TecharoHQ/anubis): क्रॉलर ट्रैफ़िक कम करने के लिए ब्राउज़र चैलेंज।
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS और बॉट चैलेंज।
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): connector के ज़रिए उपयोग होने वाला WAF इंजन।
- [Coraza](https://github.com/corazawaf/coraza): ModSecurity नियमों और CRS का समर्थन करने वाली Go WAF लाइब्रेरी।
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): WAF इंजनों के लिए आक्रमण-पहचान नियम।

ये प्रोजेक्ट वेब सुरक्षा के अलग-अलग हिस्से संभालते हैं। Sibuna का निरीक्षक बिल्ट-इन है; वह CRS या ModSecurity के अन्य नियम-समुच्चय नहीं चलाता। जब आपके ऐप को व्यापक नियम-कवरेज चाहिए, तब Sibuna को किसी पूर्ण WAF के साथ उपयोग करें।

<a id="license"></a>

## लाइसेंस

Sibuna **LGPL 3.0 या बाद के संस्करण** के तहत है। यह लाइसेंस इंजन, लाइब्रेरी, ब्राउज़र सॉल्वर और कंसोल को, उसके WebAssembly इंटरफ़ेस सहित, कवर करता है।

[LICENSE](LICENSE) उसका दायरा बताता है। [LICENSES](LICENSES) में पूरी शर्तें हैं। [NOTICE](NOTICE) निर्भरताओं की सूची देता है। स्रोत और बिल्ड स्क्रिप्ट हर रिलीज़ टैग के तहत उपलब्ध हैं।

Sibuna को Vikrant Rathore ने Ronak Rathore और Kanak Rathore के सहयोग से लिखा है। अलग लाइसेंस शर्तें चाहने वाली कंपनियाँ Vikrant Rathore से संपर्क कर सकती हैं। तृतीय-पक्ष लाइब्रेरी और सामग्री अपने-अपने लाइसेंस बनाए रखती हैं।
