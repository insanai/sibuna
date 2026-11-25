#import "wireframe.typ": *
#set text(font: "Noto Sans")

#detail-wire("Audit", [Audit · activity and policy history], [Activity], [
  Actor: all ▾ · Action: all ▾ · Period: 24 h ▾\
  Subject: ​──────── · Node: all ▾

  Time / actor / action / subject / result\
  12:41 / alice / policy edit / p1 / committed\
  12:40 / admin / drain / node 2 / completed\
  12:38 / ci / export / events / completed

  Previous / Page 1 / Next · Export\
  Retention: 365 days · old records expire\
  Append-only for users, not tamper-proof.
], [Selected change], [
  Actor: alice · operator · address recorded\
  Policy p1 · revision 17 → 18

  Before: action challenge; difficulty 16\
  After: action deny\
  Reason: operator description

  Applied: node 1 ✓ · node 2 ✓ · node 3 pending\
  Review policy revision / Revert this change

  Revert restores the document recorded before revision 18 as revision 19 with a fresh audit.\
  Rejected if revision 18 is no longer current; Policy history offers compare and rebase.\
  Secrets and full token values never displayed.
], [Local action detail: request id, intent, target acknowledgment and failure reason; no false atomicity claim.])
