# Storage dependencies

These library snapshots come from Zaxonlite 0.7.0 and Paxos 0.7.0. Their MIT
licenses remain beside the sources. `provenance.json` records the original release
archives, archive digests, Zig package hashes and original file digests.

Sibuna uses local package paths until upstream releases support Zig 0.17. Compiler
and standard-library adaptations cover type reflection, array initialization and
renamed APIs. Paxos also has a bounded election correction: chosen-history replay
does not replace a ballot-bearing leader hint or reset the election timer, because
any member can serve catch-up commits. Prepare, accept and matching heartbeat
messages retain their leader-contact behavior; chosen-value and durability rules
are unchanged. This correction and its regression tests are recorded in
`provenance.json`. The build entry points expose the embedded
library and preserve its SQLite, sqlite-vec and optional OpenSSL configuration.
The unused Zaxon terminal application and its Vaxis dependency are not built.

The snapshots are tested through Sibuna's storage and cluster integration tests;
these are not standalone Zaxon or Paxos distributions. Compare modified files
with the original file digests before replacing either snapshot. Never modify a
compiler package cache to make a release build work.
