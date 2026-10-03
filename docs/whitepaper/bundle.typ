#import "../shared/html.typ": preserve-figures

#document(
  "index.html",
  title: [Sibuna: A Zero-Allocation, Distributed Web Defense Engine],
  author: ("Vikrant Rathore", "Ronak Rathore"),
  description: [Whitepaper on Sibuna's architecture, thermodynamic proof of work, zero-allocation pipeline, and embedded Multi-Paxos consensus via zaxonlite.],
)[
  #show: preserve-figures
  #include "whitepaper.typ"
]
