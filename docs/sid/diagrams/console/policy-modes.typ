#import "wireframe.typ": *
#set text(font: "Noto Sans")

#detail-wire("Policy", [Policy · Rules / Inspection / Limits / IP groups], [Inspection and limits], [
  Category / mode\
  SQL injection / Enforce ▾\
  XSS / Audit ▾\
  Path traversal / Enforce ▾\
  RCE / Disabled ▾

  Audit logs a finding then continues evaluation.\
  Another enforcing rule can still deny.

  *Limits* · target node: node 2 ▾\
  Current GCRA: rate / window / ban duration\
  Terminal rules own additional node-local quotas.

  Review changes → Save expected revision 17
], [IP groups and country action], [
  Prefix / action / expiry / provenance\
  192.0.2.0/24 / deny / 1 h / operator\
  Add prefix / edit / remove

  *Country builder*\
  Country: select ▾ · GeoIP generation: current\
  Action: Deny ▾ · Duration: 24 h ▾\
  Preview CIDRs / overlaps / trie-node usage

  Reject if full; never silently truncate.\
  Challenge needs explicit supported rules.

  Confirm / Cancel · Conflict? reload and diff\
  Committed revision ≠ applied on every node.
], [Viewer: edits disabled. Invalid input: inline error. Full engine: reject. Concurrent edit: show conflict before retry.])
