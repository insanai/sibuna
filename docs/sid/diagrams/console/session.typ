// SID 0007: one browser session, from the login to the policy rebuild on every node.
// Storage arrows are mailbox requests; dashed arrows are responses and effects.
#import "../style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("browser", "Browser", kind: "party"),
    actor("console", "Console", kind: "accent"),
    actor("zaxonlite", "Zaxonlite", kind: "store"),
    actor("storage", "Storage thread (every node)"),
  ),
  (
    msg("browser", "console", "`POST /console/api/login`"),
    msg("console", "zaxonlite", "Read the user; verify off the owner; store the session"),
    msg("console", "browser", "200, session cookie, CSRF token", reply: true),
    msg("browser", "console", "`GET /console/ws`, then subscribe to `stats`"),
    msg("console", "browser", "Snapshot, then deltas at 1 Hz", reply: true),
    msg("browser", "console", "`POST /console/api/policies/edit` with CSRF", accent: true),
    msg("console", "zaxonlite", "Expected revision; policy and audit in one transaction",
      accent: true),
    msg("zaxonlite", "storage", "Replicated commit; the revision changed", accent: true),
    act("storage", "Tick: rebuild a spare engine, publish", accent: true),
    msg("storage", "console", "`policy` topic: rule p1 active on node n", reply: true),
  ),
  spacing: 46,
)
