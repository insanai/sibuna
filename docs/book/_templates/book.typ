// The PDF template of The Sibuna Book. Guidedog calls it as
//
//   #show: book.with(title: ..., author: ..., version: ..., ...)
//
// followed by the chapters. The design itself is in sibuna.typ, the theme every Sibuna
// guidedog project shares; this file only names the words of the book's cover and
// contents, in each language the book is translated into. A new book (such as the
// manual) copies this file, sibuna.typ and preamble.typ, sets pdf_preamble =
// "_templates/preamble.typ" in its conf.toml, and changes the words below. See the
// comment at the top of sibuna.typ.
#import "sibuna.typ": sibuna-book, sibuna-language, sibuna-part-pattern

// The words of the cover and the contents in each language of the book, by language
// code. A language missing here, or a word missing from its entry, is English. The
// book's other words come from elsewhere: its title from the title of index.rst in the
// language's catalog (docs/site/build.py passes it as -D project), the credit line and
// the copyright from the language's phrase map in docs/site/home/locales (-D author and
// -D copyright), and "Version" from guidedog's interface catalog.
//
//   kicker    the small capitals above SIBUNA
//   subtitle  the line under SIBUNA
//   contents  the heading of the contents
//   part      how the catalog translates a part's title, such as "Part VI: Automata":
//             a regular expression whose first group is the label set above the title
//             ("Part VI") and whose second is the title ("Automata")
//
// Arabic and Hindi are set without the cover's letter spacing, which would break their
// joined letters apart; sibuna.typ does that for them (sibuna-joined-scripts).
#let cover-dot = [#h(0.4em) \u{00B7} #h(0.4em)]
#let covers = (
  en: (kicker: [THE BOOK OF], subtitle: [Distributed load balancer and web application firewall],
    contents: [Contents], part: sibuna-part-pattern),
  zh: (kicker: [技术手册], subtitle: [分布式负载均衡器和 Web 应用防火墙],
    contents: [目录],
    part: regex("^(第\s*[IVXLCDM0-9]+\s*部分)\s*[:：]?\s*(.*)$")),
  ko: (kicker: [기술 안내서], subtitle: [분산 로드 밸런서와 웹 애플리케이션 방화벽],
    contents: [목차],
    part: regex("^(제\s*[IVXLCDM0-9]+\s*부)\s*[:.]?\s*(.*)$")),
  ja: (kicker: [技術ガイド], subtitle: [分散ロードバランサーとWebアプリケーションファイアウォール],
    contents: [目次],
    part: regex("^(第\s*[IVXLCDM0-9]+\s*部)\s*[:：]?\s*(.*)$")),
  es: (kicker: [EL LIBRO DE], subtitle: [Balanceador de carga distribuido y cortafuegos de aplicaciones web],
    contents: [Índice],
    part: regex("^(Parte\s+[IVXLCDM0-9]+)\s*[:.]?\s*(.*)$")),
  de: (kicker: [DAS HANDBUCH ZU], subtitle: [Verteilter Lastverteiler und Web Application Firewall],
    contents: [Inhalt],
    part: regex("^(Teil\s+[IVXLCDM0-9]+)\s*[:.]?\s*(.*)$")),
  hi: (kicker: [तकनीकी मार्गदर्शिका], subtitle: [वितरित लोड बैलेंसर और वेब एप्लिकेशन फ़ायरवॉल],
    contents: [विषय-सूची],
    part: regex("^(भाग\s+[IVXLCDM0-9]+)\s*[:.]?\s*(.*)$")),
  ar: (kicker: [كتاب], subtitle: [موازن حمل موزع وجدار حماية لتطبيقات الويب],
    contents: [المحتويات],
    part: regex("^(الجزء\s+[^:]+?)\s*:\s*(.*)$")),
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
  let cover = covers.en + covers.at(sibuna-language(lang).at(0), default: (:))
  sibuna-book(
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
    kicker: cover.kicker,
    headline: [SIBUNA],
    subtitle: cover.subtitle,
    motto: [TCP#cover-dot;UDP#cover-dot;HTTP],
    contents-title: cover.contents,
    part-pattern: cover.part,
    body,
  )
}
