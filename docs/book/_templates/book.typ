// The PDF template of The Sibuna Book. Guidedog calls it as
//
//   #show: book.with(title: ..., author: ..., version: ..., ...)
//
// followed by the chapters. The design itself is in sibuna.typ, the theme every Sibuna
// guidedog project shares; this file only names the book's cover. A new book (such as
// the manual) copies this file, sibuna.typ and preamble.typ, sets
// pdf_preamble = "_templates/preamble.typ" in its conf.toml, and changes the cover
// text below. See the comment at the top of sibuna.typ.
#import "sibuna.typ": sibuna-book

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
) = sibuna-book(
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
  kicker: [THE BOOK OF],
  headline: [SIBUNA],
  subtitle: [The mathematics and engineering of web defense],
  motto: [WORK #h(0.4em) \u{00B7} #h(0.4em) TRUST #h(0.4em) \u{00B7} #h(0.4em) BOUNDED STATE],
  body,
)
