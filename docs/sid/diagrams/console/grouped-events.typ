#import "wireframe.typ": *
#set text(font: "Noto Sans")

#detail-wire("Attack events", [Attack events · By source / Raw], [Source groups], [
  Node: all ▾ · Category: all ▾\
  Address: ​──────── · Country: all ▾\
  Path: ​──────── · Period: last 24 h ▾

  *Show 12 new events* · Live paused\
  Address / incidents / first / last\
  198.51.100.7 / 18 / 12:00 / 12:41\
  192.0.2.44 / 9 / 11:30 / 12:39

  Select source → filtered raw events\
  Country: Unknown for these example IPs

  Previous / Page 1 / Next · Export CSV\
  Export respects filters and size limits.
], [Source detail], [
  *198.51.100.7* · nodes 1, 2\
  18 recorded incidents · 2 categories

  Timeline / categories / campaign candidates\
  Open raw event → retained evidence\
  Similarity is heuristic, not attribution.

  Ban 24 h / Allow 1 h / Add to group\
  Preview overlap and effective precedence\
  Confirm → applied per-node revision

  Undo 30 s → new audited mutation\
  Export omits credentials and redacted data.
], [Empty: adjust filters. Retention gap, dropped incidents and stale replica state are shown above the list.])
