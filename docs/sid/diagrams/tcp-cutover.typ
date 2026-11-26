// SID 0015: the proposed cutover. Tier 1 reloads a snapshot in the process; tier 2
// replaces the binary and passes the TCP listeners, while the old workers drain.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("op", "Operator or database", kind: "party"),
    actor("control", "Control plane, gen k", kind: "accent"),
    actor("workers", "Pinned workers, gen k"),
    actor("new", "New process, gen k+1", kind: "accent"),
    actor("clients", "Live clients", kind: "party"),
  ),
  (
    begin-frame("Tier 1: snapshot reload in the process"),
    msg("op", "control", "SIGHUP or `NOTIFY`"),
    act("control", "Evaluate, build Maglev"),
    msg("control", "workers", "Publish snapshot k+1", accent: true),
    msg("clients", "workers", "Old flows keep their backend; new flows use the revision"),
    msg("control", "op", "OK: revision, SHA-256", reply: true),
    end-frame(),
    begin-frame("Tier 2: binary upgrade, listeners passed with SCM_RIGHTS"),
    msg("op", "control", "SIGUSR2: spawn"),
    msg("control", "new", "Pass the TCP listener descriptors"),
    msg("new", "control", "`READY`: new workers prepared", reply: true, accent: true),
    msg("control", "workers", "Detach, drain"),
    msg("clients", "new", "New TCP connections", accent: true),
    msg("workers", "clients", "Old workers drain TCP to the deadline", reply: true),
    msg("workers", "control", "Drained or deadline", reply: true),
    end-frame(),
  ),
  spacing: 31,
  box-width: 0.9,
)
