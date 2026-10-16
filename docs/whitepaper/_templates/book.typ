// The PDF template of the Sibuna whitepaper. Guidedog calls it as
//
//   #show: book.with(title: ..., author: ..., version: ..., ...)
//
// followed by the paper. The design is in whitepaper.typ; this file names the title
// block, the running header and footer, and the colophon.
#import "whitepaper.typ": wp-paper

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
) = wp-paper(
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
  subtitle: [A Zero-Allocation, Work-Bound Web Defense Engine],
  tagline: [Work-Bound Admission, Linear-Time Inspection, Bounded State, and Storage Through SQL],
  affiliation: [Insan AI Systems & Architecture Lab | Release #version],
  running-title: [SIBUNA: ARCHITECTURE, ALGORITHMS & EMPIRICAL FOUNDATIONS],
  footer-left: [Insan AI Systems Research | Zero-Allocation Web Defense],
  keywords: ("WAF", "Proof of Work", "Proof of Sequential Work",
    "Zero-Allocation", "GCRA", "Aho-Corasick", "SQLite", "PostgreSQL"),
  colophon: [
    Sibuna Whitepaper | #date | Release #version \
    Specification, source code, and benchmarks: #link("https://github.com/insanai/sibuna")
  ],
  body,
)
