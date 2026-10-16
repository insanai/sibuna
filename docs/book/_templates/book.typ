// The PDF template of The Sibuna Book. Guidedog calls it as
//
//   #show: book.with(title: ..., author: ..., version: ..., ...)
//
// followed by the chapters. The design itself is in sibuna.typ, the theme every Sibuna
// guidedog project shares; this file only names the book's cover, in each language the
// book is translated into. A new book (such as the manual) copies this file, sibuna.typ
// and preamble.typ, sets pdf_preamble = "_templates/preamble.typ" in its conf.toml, and
// changes the cover text below. See the comment at the top of sibuna.typ.
#import "sibuna.typ": sibuna-book, sibuna-language

// The cover's words in each language of the book, by language code; a language missing
// here gets the English cover. Hindi and Arabic are set without letter spacing, which
// would break their joined letters apart.
#let cover-dot = [#h(0.4em) \u{00B7} #h(0.4em)]
#let covers = (
  en: (kicker: [THE BOOK OF], subtitle: [The mathematics and engineering of web defense],
    motto: [WORK #h(0.4em) \u{00B7} #h(0.4em) TRUST #h(0.4em) \u{00B7} #h(0.4em) BOUNDED STATE]),
  zh: (kicker: [技术手册], subtitle: [Web 防御的数学与工程],
    motto: [工作量#cover-dot;信任#cover-dot;有界状态]),
  ko: (kicker: [기술 안내서], subtitle: [웹 방어의 수학과 공학],
    motto: [작업#cover-dot;신뢰#cover-dot;제한된 상태]),
  ja: (kicker: [技術ガイド], subtitle: [Web 防御の数学とエンジニアリング],
    motto: [計算#cover-dot;信頼#cover-dot;有界な状態]),
  es: (kicker: [EL LIBRO DE], subtitle: [Las matemáticas y la ingeniería de la defensa web],
    motto: [TRABAJO#cover-dot;CONFIANZA#cover-dot;ESTADO ACOTADO]),
  de: (kicker: [DAS HANDBUCH ZU], subtitle: [Mathematik und Technik des Webschutzes],
    motto: [ARBEIT#cover-dot;VERTRAUEN#cover-dot;BEGRENZTER ZUSTAND]),
  hi: (kicker: text(tracking: 0pt)[तकनीकी मार्गदर्शिका],
    subtitle: [वेब सुरक्षा का गणित और इंजीनियरिंग],
    motto: text(tracking: 0pt)[कार्य#cover-dot;विश्वास#cover-dot;सीमित अवस्था]),
  ar: (kicker: text(tracking: 0pt)[الدليل التقني], subtitle: [رياضيات حماية الويب وهندستها],
    motto: text(tracking: 0pt)[إثبات العمل#cover-dot;الثقة#cover-dot;الحالة المحدودة]),
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
  let cover = covers.at(sibuna-language(lang).at(0), default: covers.en)
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
    motto: cover.motto,
    body,
  )
}
