// prior-art.rst: the lineage of the ideas Sibuna combines. Three columns, time running
// downward; the filled boxes are the ideas Sibuna takes directly.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let idea(at, title, year, name, taken: false) = step(at, title, year,
  kind: if taken { "accent" } else { "step" }, width: 34mm, name: name)

#flow(
  spacing: (7mm, 4.5mm),
  caption-node((0, -1), "Client puzzles and\nsequential work"),
  caption-node((1, -1), "Products in\nthe same space"),
  caption-node((2, -1), "Algorithms and\nsystems"),
  idea((0, 0), "Dwork-Naor", "1992", <dwork>),
  idea((0, 1), "Hashcash", "1997", <hashcash>, taken: true),
  idea((0, 2), "Juels-Brainard", "1999", <juels>),
  idea((0, 3), "Mahmoody et al.", "2013", <mahmoody>),
  idea((0, 4), "Cohen-Pietrzak", "2018", <cohen>, taken: true),
  idea((0, 5), "Blocki-Lee-Zhou", "2021", <blocki>, taken: true),
  idea((1, 2), "Anubis", "interstitial", <anubis>, taken: true),
  idea((1, 3), "Cloudflare", "hosted edge", <cloudflare>, taken: true),
  idea((1, 4), "SafeLine", "semantic WAF", <safeline>, taken: true),
  idea((2, 0), "Aho-Corasick", "1975", <aho>, taken: true),
  idea((2, 1), "GCRA", "ATM Forum 1996", <gcra>, taken: true),
  idea((2, 2), "ModSecurity, CRS", "2002", <modsec>),
  idea((2, 3), "libinjection", "2012", <libinj>, taken: true),
  idea((2, 4), "Hyperscan", "2019", <hyperscan>),
  group((<dwork>, <blocki>), name: <puzzles>),
  group((<anubis>, <safeline>), name: <products>),
  group((<aho>, <hyperscan>), name: <systems>),
  sibuna((1, 6.6), text(weight: "semibold", "Sibuna"), "Gate, Shield, Edge", width: 46mm,
    stroke: bold + green, name: <sibuna>),
  edge(<dwork>, <hashcash>, "-|>"),
  edge(<hashcash>, <juels>, "-|>"),
  edge(<juels>, <mahmoody>, "-|>"),
  edge(<mahmoody>, <cohen>, "-|>"),
  edge(<cohen>, <blocki>, "-|>"),
  edge(<modsec>, <libinj>, "-|>"),
  edge(<aho>, (2.8, 0), (2.8, 4), <hyperscan>, "-|>", corner-radius: 4pt),
  edge(<hashcash>, <anubis>, "-|>"),
  edge(<libinj>, <safeline>, "-|>"),
  main-edge(<puzzles>, <sibuna>, "-|>"),
  main-edge(<products>, <sibuna>, "-|>"),
  main-edge(<systems>, <sibuna>, "-|>"),
)
