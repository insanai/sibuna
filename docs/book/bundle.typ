#import "theme.typ": *
#import "figures.typ": *

#document(
  "index.html",
  title: [The Book of Sibuna],
  author: ("Vikrant Rathore", "Ronak Rathore"),
)[
  #include "../book.typ"
]

#document("operations.html", title: [Sibuna Operations Guide])[
  #show: book
  #include "09_operations.typ"
]

#document("reference.html", title: [Sibuna Reference])[
  #show: book
  #include "10_reference.typ"
]
