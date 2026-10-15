// The PDF template of a Sibuna Discussion record. guidedog dsc build makes one book per
// record and calls this as
//
//   #show: book.with(title: ..., author: ..., version: ..., ...)
//
// followed by the record, which opens with its field list. The design is in sibuna.typ,
// the theme every Sibuna guidedog project shares (see the comment at its top); it turns
// the field list into the SID frame. This file only names the frame's text.
#import "sibuna.typ": sibuna-sid

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
) = sibuna-sid(
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
  prefix: "SID",
  group: [Sibuna Working Group],
  series: [Request for Discussion and Implementation Record],
  memo: [This document is an internal Sibuna discussion record, written in reStructuredText, managed with guidedog, and tracked in git. It intentionally follows RFC-style structure so the design scope, rationale, trade-offs, and operational constraints remain explicit. Documents that still use the placeholder number #raw("XXXXX") are provisional drafts. Numbered SID documents are part of the permanent project record.],
  body,
)
