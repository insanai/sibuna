// The PDF template of the Sibuna whitepaper. Guidedog calls it as
//
//   #show: book.with(title: ..., author: ..., version: ..., ...)
//
// followed by the paper. The design is in whitepaper.typ; this file names the title
// block, the running header and footer, and the colophon, in each language the paper is
// translated into.
#import "whitepaper.typ": wp-paper, wp-language

// The words of the title block, the header, the footer and the colophon in each
// language, by language code. A language missing here, or a word missing from its
// entry, is English. The paper's other words come from elsewhere: its title from the
// title of index.rst in the language's catalog (docs/site/build.py passes it as
// -D project), and the date and the copyright from the language's phrase map in
// docs/site/i18n (-D today and -D copyright).
//
//   subtitle       the line under SIBUNA
//   tagline        the small line under the subtitle
//   assistance     the line under the author's name
//   release        the word before the version, as in "Release 1.0.0"
//   running-title  the left side of the running header
//   paper          the word before the date on the right side of the running header
//   footer         the left side of the running footer, after "Insan AI |"
//   page-count     the right side of the running footer, {page} of {total}
//   name           the paper's name in the colophon
//   sources        the words before the repository's address in the colophon
#let words = (
  en: (
    subtitle: [A Zero-Allocation, Work-Bound Web Defense Engine],
    tagline: [Work-Bound Admission, Linear-Time Inspection, Bounded State, and Storage
      Through SQL],
    assistance: [With assistance from Ronak Rathore and Kanak Rathore],
    release: [Release],
    running-title: [SIBUNA: ARCHITECTURE, ALGORITHMS & EMPIRICAL FOUNDATIONS],
    paper: [Whitepaper],
    footer: [Zero-Allocation Web Defense],
    page-count: "{page} of {total}",
    name: [Sibuna Whitepaper],
    sources: [Specification, source code, and benchmarks:],
  ),  zh: (
    subtitle: [零分配、工作量约束型 Web 防御引擎],
    tagline: [工作量准入、线性时间检查、有界状态与基于 SQL 的存储],
    assistance: [Ronak Rathore 与 Kanak Rathore 协助],
    release: [版本],
    running-title: [SIBUNA：架构、算法与实证基础],
    paper: [白皮书],
    footer: [零分配 Web 防御],
    page-count: "第 {page} 页，共 {total} 页",
    name: [Sibuna 白皮书],
    sources: [规范、源代码与基准测试：],
  ),
  ko: (
    subtitle: [무할당, 작업 증명 기반 웹 방어 엔진],
    tagline: [작업 증명 기반 요청 허용, 선형 시간 검사, 제한된 상태, SQL 기반 저장소],
    assistance: [Ronak Rathore·Kanak Rathore 도움],
    release: [릴리스],
    running-title: [SIBUNA: 아키텍처, 알고리즘, 실증적 기반],
    paper: [백서],
    footer: [무할당 웹 방어],
    page-count: "{page} / {total}",
    name: [Sibuna 백서],
    sources: [명세, 소스 코드, 벤치마크:],
  ),
  ja: (
    subtitle: [ゼロアロケーションで作業に基づくWeb防御エンジン],
    tagline: [作業に基づく許可、線形時間の検査、有界な状態、SQLによるストレージ],
    assistance: [協力：Ronak Rathore、Kanak Rathore],
    release: [リリース],
    running-title: [SIBUNA：アーキテクチャ、アルゴリズム、実証的基盤],
    paper: [ホワイトペーパー],
    footer: [ゼロアロケーションのWeb防御],
    page-count: "{page} / {total}",
    name: [Sibunaホワイトペーパー],
    sources: [仕様、ソースコード、ベンチマーク：],
  ),
  es: (
    subtitle: [Un motor de defensa web sin asignaciones y condicionado al trabajo],
    tagline: [Admisión condicionada al trabajo, inspección en tiempo lineal, estado acotado y almacenamiento mediante SQL],
    assistance: [Con la colaboración de Ronak Rathore y Kanak Rathore],
    release: [Versión],
    running-title: [SIBUNA: ARQUITECTURA, ALGORITMOS Y FUNDAMENTOS EMPÍRICOS],
    paper: [Documento técnico],
    footer: [Defensa web sin asignaciones],
    page-count: "{page} de {total}",
    name: [Documento técnico de Sibuna],
    sources: [Especificación, código fuente y pruebas de rendimiento:],
  ),
  de: (
    subtitle: [Eine allokationsfreie Engine zur Webabwehr durch Rechenarbeit],
    tagline: [Zulassung gegen Rechenarbeit, Prüfung in linearer Zeit, begrenzter Zustand und Speicherung über SQL],
    assistance: [Mit Unterstützung von Ronak Rathore und Kanak Rathore],
    release: [Release],
    running-title: [SIBUNA: ARCHITEKTUR, ALGORITHMEN & EMPIRISCHE GRUNDLAGEN],
    paper: [Whitepaper],
    footer: [Allokationsfreie Webabwehr],
    page-count: "{page} von {total}",
    name: [Sibuna-Whitepaper],
    sources: [Spezifikation, Quellcode und Benchmarks:],
  ),
  hi: (
    subtitle: [शून्य-आवंटन वाला, कार्य-आधारित वेब सुरक्षा इंजन],
    tagline: [कार्य-आधारित प्रवेश, रैखिक-समय निरीक्षण, सीमित अवस्था और SQL के ज़रिए स्टोरेज],
    assistance: [Ronak Rathore और Kanak Rathore के सहयोग से],
    release: [रिलीज़],
    running-title: [SIBUNA: आर्किटेक्चर, एल्गोरिदम और प्रायोगिक आधार],
    paper: [व्हाइटपेपर],
    footer: [शून्य-आवंटन वेब सुरक्षा],
    page-count: "{total} में से {page}",
    name: [Sibuna व्हाइटपेपर],
    sources: [विनिर्देश, स्रोत कोड और बेंचमार्क:],
  ),
  ar: (
    subtitle: [محرك لحماية الويب مشروط بالعمل وبلا تخصيص للذاكرة],
    tagline: [قبول مشروط بالعمل، وفحص في زمن خطي، وحالة محدودة، وتخزين عبر SQL],
    assistance: [بمساعدة Ronak Rathore وKanak Rathore],
    release: [الإصدار],
    running-title: [SIBUNA: البنية والخوارزميات والأسس التجريبية],
    paper: [الورقة التقنية],
    footer: [حماية الويب بلا تخصيص للذاكرة],
    page-count: "{page} من {total}",
    name: [الورقة التقنية لـ Sibuna],
    sources: [المواصفات والشيفرة المصدرية وقياسات الأداء:],
  ),
)

#let book(
  title: "",
  author: "",
  version: "",
  date: "",
  lang: "en",
  paper: "a4",
  numbering: false, // The build numbers headings itself; this says whether it did.
  logo: none,
  copyright: "",
  version-label: "Version", // "Version" in the document language.
  // Follow cross-references to other pages with their page: n => [p. #n].
  page-ref: none,
  body,
) = {
  let w = words.en + words.at(wp-language(lang).at(0), default: (:))
  wp-paper(
    title: title,
    author: author,
    version: version,
    date: date,
    lang: lang,
    paper: paper,
    numbering: numbering,
    logo: logo,
    copyright: copyright,
    version-label: version-label,
    page-ref: page-ref,
    headline: [SIBUNA],
    subtitle: w.subtitle,
    tagline: w.tagline,
    affiliation: [#w.assistance \ Insan AI | #w.release #version],
    running-title: w.running-title,
    date-line: [#w.paper | #date],
    footer-left: [Insan AI | #w.footer],
    page-count: w.page-count,
    keywords: ("WAF", "Proof of Work", "Proof of Sequential Work",
      "Zero-Allocation", "GCRA", "Aho-Corasick", "SQLite", "PostgreSQL"),
    colophon: [
      #w.name | #date | #w.release #version \
      #w.sources #link("https://github.com/insanai/sibuna")
    ],
    body,
  )
}
