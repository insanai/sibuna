<!-- English source SHA-256: 62c6798d23bbb862a79f760fa8c8937390e9903a501c23d01b52db33b47d4374 -->
<h1 align="center">sibuna</h1>
<p align="center">ब्राउज़र Proof of Work और वैकल्पिक कंसोल के साथ वेब सुरक्षा।</p>
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

**Sibuna वेबसाइटों और APIs को अनचाहे बॉट ट्रैफ़िक से बचाने में मदद करता है।** यह आपके ऐप तक अनुरोध फ़ॉरवर्ड कर सकता है या Caddy, nginx अथवा Traefik जैसे मौजूदा प्रॉक्सी के साथ मिलकर काम कर सकता है।

अनुरोध (Requests) भेजना अक्सर सस्ता होता है, लेकिन उन्हें प्रोसेस करने में आपके ऐप को अधिक काम करना पड़ सकता है। Sibuna ऐक्सेस देने से पहले क्लाइंट्स से एक पहेली (Challenge puzzle) हल करवाता है। पहेली को इस तरह डिज़ाइन किया गया है कि प्रूफ़ बनाने में उसे वेरिफ़ाई करने की तुलना में अधिक गणना (Computation) लगे। इससे ऑटोमेटेड क्लाइंट्स साइट ऐक्सेस करने की लागत का अधिक हिस्सा उठाते हैं।

कंप्यूटेशन में ऊर्जा भी लगती है, लेकिन इसकी मात्रा हार्डवेयर और सेटिंग्स पर निर्भर करती है। Proof of work केवल प्रवेश की लागत जोड़ता है। यह आगंतुक के इंसान होने का प्रमाण नहीं है और न ही हर हमले को रोकता है। एक हस्ताक्षरित सत्र (Signed session) स्वीकृत क्लाइंट्स को हर अनुरोध पर नई पहेली हल किए बिना लौटने की अनुमति देता है। बाद में वे क्या अनुरोध कर सकते हैं, इसे एक्सेस नियमों और स्थानीय रेट लिमिट्स से नियंत्रित करें।

<a id="features"></a>

## सुविधाएँ

- **एकल निष्पादन योग्य फ़ाइल (Single executable):** इंजन, एम्बेडेड स्टोरेज, ब्राउज़र सॉल्वर और कंसोल एसेट्स।
- **नेटिव पैकेज:** Linux, macOS और Windows। ब्राउज़र सॉल्वर WebAssembly का उपयोग करता है।
- **ब्राउज़र चैलेंज:** कॉन्फ़िगर करने योग्य Hashcash या सीक्वेंशियल वर्क, जिसके बाद हस्ताक्षरित सत्र (Signed session)।
- **एक्सेस नीतियाँ:** IP पते, पाथ, हेडर और User-Agent के आधार पर अनुरोधों को अनुमति (Allow), चैलेंज (Challenge) या अस्वीकार (Deny) करें।
- **एप्लिकेशन निरीक्षण:** SQL इंजेक्शन, XSS और पाथ ट्रैवर्सल के लिए इन-बिल्ट जाँच।
- **वैकल्पिक OWASP CRS:** हस्ताक्षरित नियम अपडेट, Audit और Enforce मोड, निजी परीक्षण और रोलबैक।
- **स्थानीय रेट लिमिट्स:** अचानक बढ़ने वाले (Burst) और निरंतर ट्रैफ़िक को नियंत्रित करें, नियम-वार वैकल्पिक सीमाओं के साथ।
- **ऑपरेटर कंसोल:** ट्रैफ़िक, देश-वार नमूना गतिविधि, दर्ज की गई घटनाएँ और नीति संपादन।
- **क्लस्टर समर्थन:** एक अलग सोर्स बिल्ड Zaxonlite के माध्यम से नीतियों और प्रतिष्ठा (Reputation) डेटा को रेप्लिकेट करता है।

<a id="quickstart"></a>

## त्वरित शुरुआत (Quickstart)

अपने प्लेटफ़ॉर्म के लिए [रिलीज़ डाउनलोड करें](https://github.com/insanai/sibuna/releases/tag/v0.3.5)। डिफ़ॉल्ट पैकेज में स्टोरेज और कंसोल समर्थन शामिल है। कंसोल `--console` के साथ शुरू होता है।

| प्लेटफ़ॉर्म | पैकेज | आवश्यकताएँ |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 या बाद का; statically linked musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 या बाद का; statically linked musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 या बाद का |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 या बाद का |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 या बाद का; नेटिव `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-0.3.5-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI पैकेज |
| OpenBSD x86-64 | `sibuna-0.3.5.tgz` | OpenBSD 7.9; CLI पैकेज |

macOS बिल्ड बिना हस्ताक्षर वाले (Unsigned) हैं। प्रत्येक पैकेज में लाइसेंस, सोर्स लिंक और बिल्ड मैनिफ़ेस्ट शामिल हैं। उपयोग करने से पहले `SHA256SUMS` के विरुद्ध आर्काइव को सत्यापित (Verify) करें।

Debian/RPM पैकेज Linux x86-64 और ARM64 के लिए हैं; Arch `sibuna-bin` x86-64 के लिए है। FreeBSD 15.1 और OpenBSD 7.9 पैकेज x86-64 पर CLI स्थापित करते हैं। Linux पैकेज में वैकल्पिक, निष्क्रिय systemd सेवा है। BSD पैकेज सेवा, खाता या स्थिति नहीं बनाते। ये upstream डाउनलोड हैं; सामुदायिक रिपॉज़िटरी की स्वीकृति अलग प्रक्रिया है। रिलीज़ में Homebrew स्रोत formula और Helm chart भी हैं। स्थापना, सत्यापन, निजी स्थिति, अपग्रेड और Kubernetes सेटअप के लिए [पैकेज संचालन मार्गदर्शिका](https://insanai.github.io/sibuna/hi/book/operations.html) देखें।

[Sibuna Homebrew tap](https://github.com/insanai/homebrew-sibuna) स्रोत से बनायी जाने वाली CLI formula प्रदान करता है। स्थापना से कोई सेवा शुरू नहीं होती:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

Linux x86-64 के लिए, यदि आपका ऐप पोर्ट 3000 पर सुन रहा है:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

स्थानीय रूप से आज़माने के लिए `http://127.0.0.1:8080` खोलें। सार्वजनिक साइट के लिए, विश्वसनीय इनग्रेस (Trusted ingress) पर HTTPS समाप्त (Terminate) करें और Sibuna के लिसनर को निजी रखें। Caddy या nginx के लिए [डिप्लॉयमेंट गाइड](https://insanai.github.io/sibuna/hi/book/operations.html) का पालन करें।

डिफ़ॉल्ट मोड `reverse_proxy` है। यदि आपका इनग्रेस अनुरोधों को फ़ॉरवर्ड करता है और Sibuna से केवल एक्सेस निर्णय पूछता है, तो `--mode forward_auth` का उपयोग करें। गाइड में दोनों कॉन्फ़िगरेशन शामिल हैं। Shield का इन-बिल्ट निरीक्षण डिफ़ॉल्ट रूप से सक्षम है। उस इंस्पेक्टर के बिना केवल प्रवेश नियंत्रण (Admission) के लिए `--gate` का उपयोग करें। `--policy-file <file>` से एक्सेस नियम चुनें, जिनमें ऐसे API क्लाइंट्स और हेल्थ चेक्स के नियम भी शामिल हों जो ब्राउज़र चैलेंज नहीं चला सकते।

Windows पर, ZIP एक्सट्रैक्ट करें और PowerShell में `.\sibuna.exe --help` चलाएँ। इसे रोकने के लिए Ctrl+C दबाएँ। Windows ACLs का उपयोग करके सीड (Seed), क्रेडेंशियल और डेटा फ़ाइलों तक पहुँच को सीमित करें।

<a id="build-from-source"></a>

### सोर्स कोड से बिल्ड करें

**Zig 0.17.0** का उपयोग करें। पिन किए गए टूलचेन चेकसम और निर्भरता स्रोत (Dependencies) रिपॉजिटरी में उपलब्ध हैं।

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

निष्पादन योग्य फ़ाइल (Executable) `zig-out/bin/sibuna` है। क्लस्टर बिल्ड `-Dcluster=true` का उपयोग करते हैं और उन्हें OpenSSL 3 की आवश्यकता होती है। बिल्ड सत्यापन के लिए [CONTRIBUTING.md](CONTRIBUTING.md) देखें।

<a id="enable-owasp-crs"></a>

### OWASP CRS सक्षम करें

CRS डिफ़ॉल्ट रूप से अक्षम (Disabled) रहता है। एक समर्थित हस्ताक्षरित रिलीज़ डाउनलोड और सत्यापित करें, फिर CRS के आधार पर अनुरोध अस्वीकार किए बिना निष्कर्षों (Findings) की समीक्षा के लिए Audit मोड में शुरू करें:

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

एक नई कैंडिडेट डायरेक्टरी का उपयोग करें। किसी कैंडिडेट की जाँच करने से चल रहा डेमन (Running daemon) नहीं बदलता। CLI और कंसोल अपडेट तैयार कर सकते हैं, परिवर्तनों की समीक्षा कर सकते हैं और एक सत्यापित कैंडिडेट चुन सकते हैं। अपने एप्लिकेशन के सामान्य ट्रैफ़िक का परीक्षण करने और बहिष्करणों (Exclusions) की समीक्षा के बाद Enforce शुरू करें। अपडेट, रोलबैक, बॉडी सीमाएँ और अपूर्ण निरीक्षण के लिए [CRS गाइड](https://insanai.github.io/sibuna/hi/book/operations.html) देखें। Forward-auth के लिए `--crs-profile headers` आवश्यक है; यह एप्लिकेशन की पूरी बॉडी नहीं देख पाता।

<a id="console"></a>

## कंसोल

कंसोल उसी निष्पादन योग्य फ़ाइल में चलता है। जब डेमन बंद हो, तब एडमिनिस्ट्रेटर को बूटस्ट्रैप करें:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

`http://127.0.0.1:19446/console/` खोलें और अस्थायी पासवर्ड बदलें। [ऑपरेशन्स गाइड](https://insanai.github.io/sibuna/hi/book/operations.html) में HTTPS एक्सेस, GeoIP आयात और CRS अपडेट के बारे में बताया गया है। कंसोल के साथ निरीक्षण सक्षम करने के लिए ऊपर दिए गए उदाहरण के CRS फ़्लैग जोड़ें।

![Sibuna कंसोल ग्लोब, अनुरोध समयरेखा और कवरेज](docs/readme/images/console-globe.jpg)

ग्लोब पिछले एक मिनट में देश-वार नमूना गतिविधि दिखाता है। मार्कर देशों की अनुमानित स्थिति दर्शाते हैं। तीर सर्वर के कॉन्फ़िगर किए गए स्थान की ओर इशारा करते हैं। वे व्यक्तिगत लाइव कनेक्शन नहीं दिखाते हैं। GeoIP के लिए अलग से आयातित डेटासेट की आवश्यकता होती है। सर्वर को ग्लोब पर स्थापित करने के लिए `--console-location <latitude,longitude>` सेट करें।

<details>
<summary>ट्रैफ़िक अवलोकन, नीति संपादक और घटना जाँच</summary>

**ट्रैफ़िक अवलोकन** — अनुरोध परिणाम, अवलोकन विंडो और लाइव अपडेट।

![स्वीकृत, चैलेंज पाने वाले और अस्वीकृत अनुरोध काउंटरों के साथ Sibuna कंसोल ट्रैफ़िक अवलोकन](docs/readme/images/console-dashboard.jpg)

**नीति संपादक (Policy editor)** — चेकआउट चैलेंज नियम का एक उदाहरण, स्पष्ट मैचर्स और सेटिंग्स के साथ।

![चेकआउट के लिए ड्राफ़्ट चैलेंज नियम के साथ Sibuna कंसोल नीति संपादक](docs/readme/images/console-policy-editor.jpg)

**घटना जाँच (Incident investigation)** — दर्ज किए गए साक्ष्य और सीमित, संवेदनशील जानकारी हटाए गए (Redacted) अनुरोध हेडर।

![संवेदनशील जानकारी हटाए गए हेडर और प्रतिक्रिया स्थिति के साथ Sibuna कंसोल घटना साक्ष्य](docs/readme/images/console-incident.jpg)

</details>

ये एक समीक्षा नोड पर v0.2.0 के Chrome स्क्रीनशॉट हैं। ट्रैफ़िक और GeoIP मैपिंग परीक्षण डेटा हैं। प्रदर्शित संख्याएँ बेंचमार्क परिणाम नहीं हैं।

<a id="how-it-works"></a>

## यह कैसे काम करता है

अनुरोध को स्वीकार (Admit), चुनौती (Challenge) या अस्वीकार (Deny) किया जा सकता है। जो आगंतुक चुनौती हल करता है उसे एक हस्ताक्षरित सत्र प्राप्त होता है। बाद के अनुरोध भी लागू नीति और दर जाँच से गुजरते हैं।

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="पहेली हल करें, हस्ताक्षरित सत्र प्राप्त करें और बाद के अनुरोधों पर नियम जाँचें">
</picture>

Gate एक्सेस नियमों, सत्रों और स्थानीय रेट लिमिट्स की जाँच करता है। Shield इन-बिल्ट आक्रमण निरीक्षक जोड़ता है। नेटिव CRS को अलग से कॉन्फ़िगर किया जाता है। Enforce सक्षम करने से पहले परिणामों की समीक्षा के लिए इसे Audit में शुरू करें।

<details>
<summary>Gate, Shield और Sibuna के आंतरिक मॉड्यूल</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate और Shield अनुरोध निर्णय: अनुमति, चुनौती या ब्लॉक">
</picture>

यह आरेख इन-बिल्ट Gate और Shield जाँचों को दिखाता है। वैकल्पिक CRS अपना स्वयं का निरीक्षण जोड़ता है। एक वैध सत्र लागू आक्रमण जाँचों या अनुरोध सीमाओं को बायपास नहीं करता है।

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna के आंतरिक मॉड्यूल के कार्य">
</picture>

मॉड्यूल नेटवर्किंग, प्रूफ़, नीतियों, स्थानीय स्थिति और प्रबंधन को अलग रखते हैं। [पुस्तक](https://insanai.github.io/sibuna/hi/book/) उनकी ज़िम्मेदारियों की व्याख्या करती है।

</details>

<a id="deployment-limits"></a>

### डिप्लॉयमेंट सीमाएँ

Sibuna अपने निजी लिसनर पर HTTP/1.1 का उपयोग करता है। आपका इनग्रेस सार्वजनिक TLS और HTTP/2 को संभालता है। Forward-auth इनग्रेस द्वारा प्रदान किए गए मेटाडेटा का निरीक्षण करता है। पूर्ण रिवर्स-प्रॉक्सी CRS निरीक्षण कॉन्फ़िगर की गई बॉडी और कार्य सीमाओं का उपयोग करता है। इन-बिल्ट इंस्पेक्टर पहले 8 KiB को कवर करता है। CRS अक्षम होने पर अपलोड स्ट्रीम होते हैं। WebSocket संदेश बिना निरीक्षण के रिले किए जाते हैं।
पूर्ण CRS डिफ़ॉल्ट रूप से 4 MiB अनुरोध सीमा और 1 MiB प्रतिक्रिया सीमा रखता है और निरीक्षण के लिए बॉडी को बफ़र करता है। Enforce अपूर्ण निरीक्षण को अस्वीकार करता है; इसे सक्षम करने से पहले अपने एप्लिकेशन की सीमाओं और स्ट्रीमिंग अपवादों की समीक्षा करें।

रेट लिमिट्स प्रत्येक नोड के लिए स्थानीय होती हैं। Sibuna वॉल्यूमेट्रिक नेटवर्क शमन (Volumetric network mitigation) प्रदान नहीं करता है। कंसोल का सख्त प्रदर्शन लक्ष्य औपचारिक रूप से पास नहीं हुआ है। प्रोडक्शन ऐप के साथ कंसोल सक्षम करने से पहले [डिप्लॉयमेंट सीमाएँ और मापन](https://insanai.github.io/sibuna/hi/book/operations.html) की समीक्षा करें।

<a id="benchmarks"></a>

## बेंचमार्क

पुस्तक प्रत्येक रन के लिए सोर्स रिविज़न, कॉन्फ़िगरेशन और होस्ट दर्ज करती है। ये मापन एक वर्कलोड के तहत अनुरोध लागत दिखाते हैं। वे समान सुरक्षा या बॉट सटीकता को नहीं मापते हैं।

<a id="three-product-comparison"></a>

### तीन उत्पादों की तुलना

इस रन ने 4 अक्टूबर 2026 को **Sibuna v0.2.0**, Anubis 1.27.0 और BunkerWeb 1.6.15 की तुलना की। सर्वर और अनुरोध जनरेटर अलग-अलग भौतिक होस्ट पर चले। प्रत्येक उत्पाद को चार CPU, 64 कनेक्शन और समान Caddy ओरिजिन मिला। चुनौतियाँ और प्रबंधन इंटरफ़ेस निष्क्रिय थे। तालिका पाँच रनों के माध्यिका (Median) मान दिखाती है।

| प्रोफ़ाइल | सामान्य GET (req/s) | p99 (ms) | 8 KiB JSON POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| सीधे ओरिजिन | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS बंद | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS चालू | 2,730 | 32.73 | 797 | 98.42 |

इस तालिका में BunkerWeb की CRS प्रोफ़ाइल v0.2.0 Shield प्रोफ़ाइल से अधिक निरीक्षण करती है। Sibuna v0.3.0 नेटिव CRS जोड़ता है; यह तुलना उस इंजन से पहले की है। दोनों होस्ट साझा कंटेनर हैं। CPU फ़्रीक्वेंसी और असंबंधित होस्ट गतिविधि को नियंत्रित नहीं किया गया था।

<a id="native-crs-in-v030"></a>

### v0.3.0 में नेटिव CRS

इस अलग रन में आठ डैशबोर्ड, उत्पाद के लिए चार CPU और दूसरे होस्ट से 16 कनेक्शन का उपयोग किया गया। तालिका पाँच राउंड में माध्यिका दरों (Median rates) को दर्शाती है। इन-बिल्ट इंस्पेक्टर अक्षम था।

| वर्कलोड | CRS बंद (req/s) | Audit, paranoia 1 (req/s) | Audit, paranoia 2 (req/s) |
| --- | ---: | ---: | ---: |
| छोटा GET | 47,311 | 10,787 | 7,423 |
| 8 KiB JSON POST | 13,726 | 1,151 | 799 |
| 16 KiB मल्टीपार्ट अपलोड | 6,704 | 4,248 | 2,887 |

Paranoia स्तर 1 पर, इन वर्कलोड्स के लिए p99 लेटेंसी 2.34 ms, 23.43 ms और 6.34 ms थी। CRS प्रोफ़ाइल्स में पीक प्रोसेस RSS 133.8–140.5 MiB था। कोई भी मापा गया अनुरोध कार्य सीमा तक नहीं पहुँचा। इस रन में क्लीन रिविज़न `d461e7f` का उपयोग किया गया था। इसके पेलोड और समवर्तीता (Concurrency) तीन-उत्पाद तुलना से भिन्न हैं, इसलिए दोनों तालिकाएँ प्रत्यक्ष तुलना नहीं बनाती हैं।

मापों के न्यूनतम–अधिकतम मानों, CPU, मेमोरी, Enforce परिणामों और पुनः चलाने के कमांड के लिए [बेंचमार्क रिकॉर्ड](benchmarks/results/README.md) देखें। ये आंकड़े अलग कंसोल-प्रभाव मानदंड को पास नहीं करते हैं।

<a id="documentation"></a>

## दस्तावेज़

- [पुस्तक](https://insanai.github.io/sibuna/hi/book/): अवधारणाएँ, एल्गोरिदम, उदाहरण और मापन।
- [व्हाइटपेपर — अंग्रेज़ी](https://insanai.github.io/sibuna/whitepaper/): आर्किटेक्चर, प्रूफ़ और डिज़ाइन विवरण।
- [ऑपरेशन्स गाइड](https://insanai.github.io/sibuna/hi/book/operations.html): इंस्टॉलेशन और डिप्लॉयमेंट।
- [रेफ़रेंस](https://insanai.github.io/sibuna/hi/book/reference.html): CLI और प्रोटोकॉल विवरण।
- [डिज़ाइन चर्चाएँ — अंग्रेज़ी](https://insanai.github.io/sibuna/sid/): निर्णय और इंजीनियरिंग अनुबंध।
- [योगदान — अंग्रेज़ी](CONTRIBUTING.md): सोर्स बिल्ड और जाँच।

<a id="other-software-to-consider"></a>

## अन्य विचारणीय सॉफ़्टवेयर

- [Anubis](https://github.com/TecharoHQ/anubis): क्रॉलर ट्रैफ़िक कम करने के लिए ब्राउज़र चैलेंज।
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS और बॉट चैलेंज।
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): कनेक्टर्स के माध्यम से उपयोग किया जाने वाला WAF इंजन।
- [Coraza](https://github.com/corazawaf/coraza): ModSecurity नियमों और CRS का समर्थन करने वाली Go WAF लाइब्रेरी।
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): WAF इंजनों के लिए आक्रमण-पहचान नियम।

ये प्रोजेक्ट वेब सुरक्षा के विभिन्न पहलुओं को संभालते हैं। Sibuna हस्ताक्षरित मानक CRS रिलीज़ का मूल्यांकन करता है। प्लगइन्स, Lua और अन्य ModSecurity नियम सेट इसके दायरे से बाहर हैं।

<a id="license"></a>

## लाइसेंस

इंजन **LGPL 3.0** के तहत है। कंसोल, इसके WebAssembly इंटरफ़ेस सहित, **AGPL 3.0** के तहत है। डिफ़ॉल्ट निष्पादन योग्य फ़ाइल दोनों को जोड़ती है और AGPL 3.0 के तहत वितरित की जाती है। कंसोल के बिना इंजन बनाने के लिए `-Dconsole=false` का उपयोग करें।

[LICENSE](LICENSE) इसके दायरे का वर्णन करता है। [LICENSES](LICENSES) में पूर्ण शर्तें शामिल हैं। [NOTICE](NOTICE) निर्भरताएँ सूचीबद्ध करता है। सोर्स और बिल्ड स्क्रिप्ट प्रत्येक रिलीज़ टैग के तहत उपलब्ध हैं।

अन्य लाइसेंस शर्तों की तलाश करने वाली कंपनियाँ Vikrant Rathore और Ronak Rathore से संपर्क कर सकती हैं। तृतीय-पक्ष लाइब्रेरी और सामग्रियाँ अपने संबंधित लाइसेंस बनाए रखती हैं।
