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
