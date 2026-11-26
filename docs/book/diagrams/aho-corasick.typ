// algorithms.rst: trie states and failure edges for two signatures.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let goto(from, to, letters) = edge(from, to, "-|>", text(font: mono, size: 8.5pt,
  fill: green, weight: "bold", letters), label-side: left)
#let fail(from, to, bend) = edge(from, to, "-|>", stroke: thin + gold-deep, dash: "dashed",
  bend: bend, say-in("wait", "fail"))

#flow(
  spacing: (13mm, 8mm),
  state((0, 1), "Root (0)", name: <root>),
  step((1, 0), "G", name: <g>),
  step((2, 0), "GP", name: <gp>),
  outcome((3, 0), "GPTBot", "match", kind: "stop", name: <gptbot>),
  step((1, 2), "C", name: <c>),
  step((2, 2), "Cl", name: <cl>),
  outcome((3, 2), "ClaudeBot", "match", kind: "stop", name: <claudebot>),
  goto(<root>, <g>, "g"),
  goto(<g>, <gp>, "p"),
  goto(<gp>, <gptbot>, "tbot"),
  goto(<root>, <c>, "c"),
  goto(<c>, <cl>, "l"),
  goto(<cl>, <claudebot>, "audebot"),
  fail(<gp>, <root>, 12deg),
  fail(<cl>, <root>, -12deg),
)
