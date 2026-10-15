//! The console in the daemon (feature `console`; SID 0007): the `--console*` options,
//! the composition of `sibuna-console` with the storage thread and the request path, the
//! console's [`Node`](sibuna_console::Node), `init-admin`, and the request-path seams.
//!
//! - [`options`]: splits the console's flags off the command line before the data plane
//!   parses it (Zig's `console_start.zig` parser).
//! - [`start`]: telemetry, incident feed and GeoIP slot ([`start::Seams`]), the storage
//!   hooks, keys and the console server's start and banner.
//! - [`node`]: drain flag, ban gauge and clear, rule-hit readings.
//! - [`hits`]: rule-hit counters published with each engine and their generation identity.
//! - [`init`]: the offline `init-admin` bootstrap.
//! - `seams`: the request path's telemetry, behind [`crate::telemetry`].
//!
//! # Changes from the Zig version
//!
//! - `--console` needs `--data-dir` or `--database-url` (Zig: `--data-dir`); the check is
//!   `CONSOLE001` with Zig's hint.
//! - Rule-hit counters are allocated with each published engine instead of being reset in
//!   a spare slot, and the console's collector reads them through the `Node` (Zig sampled
//!   and journaled them on the storage owner's tick). The engine slot keeps the counters of
//!   the generation the collector last read until its next sample has read their final
//!   values, so a publication loses no hit counted before it.
//! - The embedded GeoIP snapshot is the file the environment variable `SIBUNA_GEOIP_DATA`
//!   names at build time (Zig's `-Dgeoip-data` option), decoded by `build.rs` (decision 7);
//!   a build without the console refuses it, as Zig did.
//! - The console's node id is `--cluster-node`, or 1 without it, as the storage thread
//!   numbers the node (Zig's owner did the same).
//! - The ban gauge is the ban table's lock-free approximate count (decision 5); Zig counted
//!   under the writer lock.
//! - The temporary `init-admin` password is printed on standard error, as Zig did, and its
//!   Argon2id workspace is wiped after hashing.

pub mod hits;
pub mod init;
pub mod node;
pub mod options;
pub(crate) mod seams;
pub mod start;

/// The console part of `--help`, printed before the data plane's options.
pub const HELP: &str = "\
Local bootstrap: sibuna init-admin <username> (--data-dir <path> | --database-url <url>)
Console: --console <host:port> (requires --data-dir or --database-url); \
--console-query-steps <n> (SQLite steps per Security aggregate, 100000-50000000, default \
4000000); --console-capture-heads (store redacted request and origin response heads per \
incident; off by default); --console-capture-header <name> (repeatable, up to 16: keep this \
header's value in stored heads; credential names stay redacted); --console-key-file <path> \
(64 hex characters, owner-only permissions); --console-origin <https-origin>; \
--console-behind-proxy; --console-trusted-proxy <CIDR> (repeatable); --console-advertise \
<origin> (link peers show for this console); --console-location <latitude,longitude> \
(declared server position on globe); --console-peer <node-id>=<https://origin> (repeatable \
management peer); --console-peer-key-file <path> (independent owner-only 64-hex key); \
--console-peer-ca-file <path> (optional PEM management trust anchors); --console-probe \
<node-id>=<http://ip:port> (repeatable peer data-plane listeners to health-probe).
Account CLI: sibuna console users [--after <id>]
  sibuna console add-user <name> [--role viewer|operator|admin]
  sibuna console set-user <id> --revision <n> --role <role> --disabled true|false
  sibuna console reset-password|revoke-sessions <id> --revision <n>
GeoIP CLI: sibuna console geoip status
  sibuna console geoip update --version <YYYY-MM-DD|YYYY-MM> [--provider user-country|dbip] \
[--month <YYYY-MM>, DB-IP alias]
    [--checksum <sha256>] [--timeout <seconds, default 1200>]
Policy CLI: sibuna console policies export (JSON array to stdout)
  sibuna console policies import --file <exported.json> (replaces every managed rule \
atomically)
Token CLI: sibuna console tokens [--after <id>]
  sibuna console mint-token <label> --scope <scope> (repeatable) [--role <role>] \
[--expires <unix-seconds>]
  sibuna console revoke-token|remove-token <id> --revision <n>
  Scopes: stats_read, events_read, policy_read, policy_write, geoip_read, geoip_write, \
users_read, users_write.
  Required: --origin <origin>; --username <name> --password-file <path>;
  or --token-file <path> for account/GeoIP operations only.
  optional --factor-file <path>. Credential files must be private regular files.
  HTTPS is required except for literal loopback HTTP; redirects are refused.
";
