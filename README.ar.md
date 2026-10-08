<!-- English source SHA-256: 48d28acad3b10231e32c88bcf3d43e324be89f143fe1bea1ee6492a32e5a1c0e -->
<div dir="rtl">

<h1 align="center">sibuna</h1>
<p align="center">حماية للويب بإثبات عمل في المتصفح ووحدة تحكم اختيارية.</p>
<p align="center">
  <a href="#features">الميزات</a> ·
  <a href="#quickstart">بدء سريع</a> ·
  <a href="#console">وحدة التحكم</a> ·
  <a href="#how-it-works">كيف يعمل</a> ·
  <a href="#documentation">الوثائق</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**يساعد Sibuna على حماية المواقع وواجهات API من حركة الروبوتات غير المرغوب فيها.** يمكنه تمرير الطلبات إلى تطبيقك، أو العمل إلى جانب وكيل موجود مثل Caddy أو nginx أو Traefik.

غالبًا ما يكون إرسال الطلبات قليل التكلفة. وقد تكلف معالجتها تطبيقك عملًا أكبر. يطلب Sibuna من العملاء حل لغز قبل منح الوصول. صُمم اللغز ليكلف إنشاء الإثبات حسابًا أكثر من التحقق منه. ويتحمل العملاء الآليون حصة أكبر من تكلفة الوصول إلى الموقع.

تستهلك الحوسبة طاقة أيضًا، لكن المقدار يعتمد على العتاد والإعدادات. يضيف إثبات العمل تكلفة للدخول. لا يثبت أن الزائر إنسان، ولا يوقف كل هجوم. تتيح جلسة موقعة للعملاء المقبولين العودة بلا لغز جديد لكل طلب. استخدم قواعد الوصول والحدود المحلية للمعدل لضبط ما يمكنهم طلبه بعد ذلك.

<a id="features"></a>

## الميزات

- **ملف تنفيذي واحد:** المحرك، والتخزين المدمج، وبرنامج حلّ الألغاز في المتصفح، وموارد وحدة التحكم.
- **حزم أصلية:** Linux وmacOS وWindows. يستخدم برنامج حلّ الألغاز في المتصفح WebAssembly.
- **تحديات المتصفح:** Hashcash أو عمل متسلسل قابل للضبط، يتبعهما جلسة موقعة.
- **سياسات الوصول:** اسمح بالطلبات أو تحدها أو ارفضها وفق العنوان والمسار والترويسات وUser-Agent.
- **فحص التطبيق:** فحوص مدمجة لحقن SQL وXSS واجتياز المسارات.
- **OWASP CRS اختياري:** تحديثات قواعد موقعة، ووضعا Audit وEnforce، واختبارات خاصة، وتراجع.
- **حدود محلية للمعدل:** ضبط الدفعات والحركة المستمرة، مع حدود اختيارية لكل قاعدة.
- **وحدة تحكم للمشغل:** حركة المرور، وعينات نشاط البلدان، والحوادث المسجلة، وتحرير السياسة.
- **دعم العناقيد:** يكرر بناء مستقل من المصدر السياسة والسمعة عبر Zaxonlite.

<a id="quickstart"></a>

## بدء سريع

[نزل إصدارًا](https://github.com/insanai/sibuna/releases/tag/v0.3.3) لمنصتك. تشمل الحزمة الافتراضية دعم التخزين ووحدة التحكم. تبدأ وحدة التحكم مع `--console`.

| المنصة | الحزمة | المتطلبات |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 أو أحدث؛ musl مرتبط ثابتًا |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 أو أحدث؛ musl مرتبط ثابتًا |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 أو أحدث |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 أو أحدث |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 أو أحدث؛ `sibuna.exe` أصلي |

بناءات macOS غير موقعة. تتضمن كل حزمة الرخص، وروابط المصدر، وبيان البناء. تحقق من الأرشيف مقابل `SHA256SUMS` قبل استخدامه.

على Linux x86-64، مع تطبيقك يستمع على المنفذ 3000:

<div dir="ltr">

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

</div>

افتح `http://127.0.0.1:8080` لتجربته محليًا. لموقع عام، أنهِ HTTPS عند وكيل دخول موثوق، وأبقِ مستمع Sibuna خاصًا. اتبع [دليل النشر](https://insanai.github.io/sibuna/ar/book/operations.html) لإعداد Caddy أو nginx.

الوضع الافتراضي هو `reverse_proxy`. استخدم `--mode forward_auth` عندما يمرر وكيل الدخول الطلبات ويسأل Sibuna عن قرار الوصول. يتضمن الدليل الإعدادين. فحص Shield المدمج مفعل افتراضيًا. استخدم `--gate` للدخول من دون ذلك الفاحص. اختر قواعد الوصول بـ `--policy-file <file>`، بما فيها قواعد عملاء API وفحوص الصحة التي لا تستطيع تشغيل تحدي متصفح.

على Windows، فك ZIP وشغل `.\sibuna.exe --help` في PowerShell. استخدم Ctrl+C لإيقافه. قيد الوصول إلى ملفات بذور التشفير (Seed files) وبيانات الاعتماد والبيانات باستخدام Windows ACLs.

<a id="build-from-source"></a>

### البناء من المصدر

استخدم **Zig 0.17.0**. توجد مجاميع تحقق سلسلة الأدوات المثبتة ومصادر الاعتمادات في المستودع.

<div dir="ltr">

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

</div>

الملف التنفيذي هو `zig-out/bin/sibuna`. تستخدم بناءات العنقود `-Dcluster=true` وتحتاج إلى OpenSSL 3. راجع [CONTRIBUTING.md](CONTRIBUTING.md) لفحوص البناء.

<a id="enable-owasp-crs"></a>

### تمكين OWASP CRS

CRS معطل افتراضيًا. نزل إصدارًا موقعًا مدعومًا وتحقق منه، ثم ابدأ بوضع Audit لمراجعة النتائج بلا تطبيق رفض CRS:

<div dir="ltr">

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

</div>

استخدم دليل مرشح جديدًا. فحص المرشح لا يغير برنامجًا يعمل. يمكن لسطر الأوامر ووحدة التحكم إعداد تحديثات ومراجعة التغييرات واختيار مرشح موثق. ابدأ Enforce بعد اختبار حركة تطبيقك العادية ومراجعة الاستثناءات. راجع [دليل CRS](https://insanai.github.io/sibuna/ar/book/operations.html) للتحديثات والتراجع وحدود الأجسام والفحص غير المكتمل. يتطلب forward-auth الإعداد `--crs-profile headers`؛ ولا يرى أجسام التطبيق كاملة.

<a id="console"></a>

## وحدة التحكم

تعمل وحدة التحكم في الملف التنفيذي نفسه. أنشئ مسؤولًا أوليًا أثناء توقف البرنامج:

<div dir="ltr">

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

</div>

افتح `http://127.0.0.1:19446/console/` وغير كلمة المرور المؤقتة. يشرح [دليل التشغيل](https://insanai.github.io/sibuna/ar/book/operations.html) الوصول عبر HTTPS، واستيراد GeoIP، وتحديثات CRS. أضف خيارات CRS من المثال السابق لتمكين الفحص إلى جانب وحدة التحكم.

![كرة Sibuna Console الأرضية وخط الطلبات الزمني والتغطية](docs/readme/images/console-globe.jpg)

تعرض الكرة الأرضية عينات نشاط البلدان خلال الدقيقة الأخيرة. تحدد العلامات مواقع تقريبية للبلدان. تشير الأسهم إلى موقع الخادم المعد. ولا تعرض اتصالات حية منفردة. يحتاج GeoIP إلى مجموعة بيانات مستوردة بصورة مستقلة. اضبط `--console-location <latitude,longitude>` لوضع الخادم على الكرة الأرضية.

<details>
<summary>نظرة عامة على الحركة ومحرر السياسة والتحقيق في الحوادث</summary>

**نظرة عامة على الحركة** — نتائج الطلبات ونوافذ الرصد والتحديثات الحية.

![نظرة عامة على حركة Sibuna Console مع عدادات الطلبات المقبولة والمتحداة والمرفوضة](docs/readme/images/console-dashboard.jpg)

**محرر السياسة** — مثال لقاعدة تحدٍّ للدفع، بمعايير مطابقة وإعدادات صريحة.

![محرر سياسة Sibuna Console مع مسودة قاعدة تحدٍّ للدفع](docs/readme/images/console-policy-editor.jpg)

**التحقيق في الحوادث** — أدلة مسجلة ورؤوس طلبات محدودة ومنقحة.

![أدلة حادث في Sibuna Console بترويسات منقحة وحالة الاستجابة](docs/readme/images/console-incident.jpg)

</details>

هذه لقطات Chrome للإصدار v0.2.0 على عقدة مراجعة. الحركة وربط GeoIP بيانات اختبار. الأعداد المعروضة ليست نتائج قياس أداء.

<a id="how-it-works"></a>

## كيف يعمل

قد يُقبل طلب أو تُفرض عليه تحديات أو يُرفض. يحصل الزائر الذي يحل تحديًا على جلسة موقعة. تمر الطلبات اللاحقة أيضًا بفحوص السياسة والمعدل المطبقة.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="حل لغزًا واحصل على جلسة موقعة وافحص القواعد في الطلبات اللاحقة">
</picture>

يفحص Gate قواعد الوصول والجلسات والحدود المحلية للمعدل. يضيف Shield فاحص الهجمات المدمج. يُعد CRS الأصلي بصورة مستقلة. ابدأ به في Audit لمراجعة النتائج قبل تمكين Enforce.

<details>
<summary>Gate وShield والوحدات داخل Sibuna</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="قرارات الطلب في Gate وShield: السماح أو التحدي أو الحظر">
</picture>

يوضح الرسم فحوص Gate وShield المدمجة. يضيف CRS الاختياري فحصه الخاص. لا تتجاوز الجلسة الصالحة فحوص الهجمات أو حدود الطلب المطبقة.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="مهام الوحدات داخل Sibuna">
</picture>

تفصل الوحدات الشبكات والإثباتات والسياسات والحالة المحلية والإدارة. يشرح [الكتاب](https://insanai.github.io/sibuna/ar/book/) مسؤولياتها.

</details>

<a id="deployment-limits"></a>

### حدود النشر

يستخدم Sibuna HTTP/1.1 على مستمعه الخاص. يتولى وكيل الدخول TLS العام وHTTP/2. يفحص forward-auth البيانات الوصفية التي يوفرها وكيل الدخول. يستخدم فحص CRS الكامل في الوكيل العكسي حدود الجسم والعمل المعدة. يغطي الفاحص المدمج أول 8 KiB. تتدفق عمليات الرفع (streaming) عندما يكون CRS معطلًا. وتُرحل رسائل WebSocket بلا فحص. يفترض CRS الكامل حد طلب 4 MiB وحد استجابة 1 MiB. ويخزن الأجسام للفحص. يرفض Enforce الفحص غير المكتمل؛ راجع الحدود واستثناءات التدفق لتطبيقك قبل تمكينه.

الحدود المحلية للمعدل تخص كل عقدة. لا يوفر Sibuna الحماية من الهجمات التي تُغرق الشبكة بحجم كبير من حركة المرور. لم يجتز هدف أداء وحدة التحكم الصارم قبولًا رسميًا. راجع [حدود النشر والقياسات](https://insanai.github.io/sibuna/ar/book/operations.html) قبل تمكين وحدة التحكم بجانب تطبيق إنتاجي.

<a id="benchmarks"></a>

## قياسات الأداء

يسجل الكتاب مراجعة المصدر والإعداد والمضيف لكل تشغيل. تبين هذه القياسات تكلفة الطلب تحت عبء عمل واحد. ولا تقيس حماية متكافئة أو دقة كشف الروبوتات.

<a id="three-product-comparison"></a>

### مقارنة ثلاثة منتجات

قارن هذا التشغيل **Sibuna v0.2.0** وAnubis 1.27.0 وBunkerWeb 1.6.15 في 4 أكتوبر 2026. عمل الخادم ومولد الطلبات على مضيفين فعليين منفصلين. حصل كل منتج على أربعة CPUs و64 اتصالًا والخادم الأصلي Caddy نفسه. كانت التحديات وواجهات الإدارة غير نشطة. يعرض الجدول الوسيط لخمس تشغيلات.

| الملف | GET سليم (req/s) | p99 (ms) | 8 KiB JSON POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| الخادم الأصلي مباشرة | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb، CRS معطل | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb، CRS مفعل | 2,730 | 32.73 | 797 | 98.42 |

يفحص ملف CRS لدى BunkerWeb أكثر من ملف Shield في v0.2.0 ضمن هذا الجدول. يضيف Sibuna v0.3.0 CRS أصليًا؛ تسبق هذه المقارنة ذلك المحرك. المضيفان حاويتان مشتركتان. لم يُتحكم بتردد CPU أو بنشاط المضيف غير المرتبط بالاختبار.

<a id="native-crs-in-v030"></a>

### CRS الأصلي في v0.3.0

استخدم هذا التشغيل المنفصل ثماني لوحات، وأربعة CPUs للمنتج، و16 اتصالًا من مضيف آخر. يعرض الجدول معدلات الوسيط لخمس جولات. كان الفاحص المدمج معطلًا.

| عبء العمل | CRS معطل (req/s) | Audit، paranoia 1 (req/s) | Audit، paranoia 2 (req/s) |
| --- | ---: | ---: | ---: |
| GET صغير | 47,311 | 10,787 | 7,423 |
| 8 KiB JSON POST | 13,726 | 1,151 | 799 |
| رفع multipart من 16 KiB | 6,704 | 4,248 | 2,887 |

عند paranoia واحد، كانت أزمنة p99 لهذه الأعباء 2.34 ms و23.43 ms و6.34 ms. تراوح RSS الأقصى للعملية بين 133.8–140.5 MiB عبر ملفات CRS. لم يبلغ أي طلب مقاس حد العمل. استخدم التشغيل المراجعة النظيفة `d461e7f`. تختلف حمولاته وتزامنه عن مقارنة المنتجات الثلاثة، فلا يشكل الجدولان مقارنة متطابقة.

راجع [سجلات القياس](benchmarks/results/README.md) للمجالات وCPU والذاكرة ونتائج Enforce وأوامر الإعادة. لا تجتاز هذه الأرقام بوابة console-impact المستقلة.

<a id="documentation"></a>

## الوثائق

- [الكتاب](https://insanai.github.io/sibuna/ar/book/): المفاهيم والخوارزميات والأمثلة والقياسات.
- [الورقة البيضاء — بالإنجليزية](https://insanai.github.io/sibuna/whitepaper/): المعمارية والبراهين وتفاصيل التصميم.
- [دليل التشغيل](https://insanai.github.io/sibuna/ar/book/operations.html): التثبيت والنشر.
- [المرجع](https://insanai.github.io/sibuna/ar/book/reference.html): تفاصيل CLI والبروتوكول.
- [نقاشات التصميم — بالإنجليزية](https://insanai.github.io/sibuna/sid/): القرارات والعقود الهندسية.
- [المساهمة](CONTRIBUTING.md): البناء من المصدر والفحوص.

<a id="other-software-to-consider"></a>

## برامج أخرى تستحق النظر

- [Anubis](https://github.com/TecharoHQ/anubis): تحديات متصفح لتقليل حركة الزواحف.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx وModSecurity وCRS وتحديات الروبوتات.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): محرك WAF يُستخدم عبر موصلات.
- [Coraza](https://github.com/corazawaf/coraza): مكتبة WAF بلغة Go تدعم قواعد ModSecurity وCRS.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): قواعد كشف هجمات لمحركات WAF.

تغطي هذه المشاريع أجزاء مختلفة من حماية الويب. يقيم Sibuna إصدارات CRS القياسية الموقعة. تقع الإضافات وLua ومجموعات ModSecurity الأخرى خارج نطاقه.

<a id="license"></a>

## الرخصة

المحرك مرخص وفق **LGPL 3.0**. وحدة التحكم، بما فيها واجهة WebAssembly، مرخصة وفق **AGPL 3.0**. يجمع الملف التنفيذي الافتراضي كليهما ويُوزع وفق AGPL 3.0. استخدم `-Dconsole=false` لبناء المحرك بلا وحدة التحكم.

يوضح [LICENSE](LICENSE) النطاق. يتضمن [LICENSES](LICENSES) الشروط الكاملة. يسرد [NOTICE](NOTICE) الاعتمادات. تتوفر المصادر ونصوص البناء تحت وسم كل إصدار.

يمكن للشركات الراغبة في شروط ترخيص أخرى الاتصال بـ Vikrant Rathore وRonak Rathore. تحتفظ مكتبات ومواد الأطراف الثالثة برخصها الخاصة.

</div>
