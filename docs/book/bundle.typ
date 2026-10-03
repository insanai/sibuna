#import "theme.typ": *
#import "figures.typ": *
#import "../shared/html.typ": preserve-figures

#document(
  "index.html",
  title: [The Book of Sibuna],
  author: ("Vikrant Rathore", "Ronak Rathore"),
)[
  #show: preserve-figures
  #include "../book.typ"
]

#document("operations.html", title: [Sibuna Operations Guide])[
  #show: preserve-figures
  #show: book
  #include "09_operations.typ"
]

#document("reference.html", title: [Sibuna Reference])[
  #show: preserve-figures
  #show: book
  #include "10_reference.typ"
]
