# GeoIP country lookup

`libs/geoip` maps an IP address to an ISO 3166-1 alpha-2 country code. It loads the
`start,end,country` CSV rows that open datasets publish, validates every row, keeps one
immutable sorted generation, and answers lookups with a binary search. It uses only the
standard library and never touches storage, sockets or the request path; the console
imports it, and the daemon's data plane never consults it.

```zig
const geoip = @import("geoip");

var db = try geoip.fromCsv(allocator, .user_country, "2026-09-09", csv_bytes);
defer db.deinit();
const country = db.lookupText("8.8.8.8"); // ?[2]u8, null for Unknown
```

For large downloads, a `Loader` accepts bytes in bounded chunks and ends each source file
explicitly, so a two-file provider becomes one generation with one digest:

```zig
var loader = try geoip.Loader.init(allocator);
errdefer loader.abandon();
try loader.feed(ipv4_chunk); // repeat per chunk
try loader.endFile();
try loader.feed(ipv6_chunk);
try loader.endFile();
var db = try loader.finish(.user_country, "2026-09-09");
```

## Providers

| Provider | Licence | Attribution | Version | Files |
|---|---|---|---|---|
| `user-country` (default) | PDDL 1.0, public domain | none | `YYYY-MM-DD` | `user-country-ipv4.csv`, `user-country-ipv6.csv`, uncompressed |
| `dbip` | CC BY 4.0 | "IP Geolocation by DB-IP" with a link to https://db-ip.com | `YYYY-MM` | `dbip-country-lite-YYYY-MM.csv.gz` |

`user-country` comes from [sapics/ip-location-db](https://github.com/sapics/ip-location-db),
compiled daily from RIR delegated statistics, public BGP archives and RFC 8805 geofeeds.
The publisher ships a `.sha256` file per CSV; `Provider.checksumUrl` names it and
`parseChecksumFile` verifies it. Release downloads redirect once to a fixed GitHub asset
host; `Provider.redirectAllowed` lists the only hosts a caller may follow.

`Provider` owns names, titles, licences, attribution, URL templates, version syntax and
file counts. Callers must not embed those facts elsewhere.

## Generation digest

`Database.digest` is the SHA-256 of the source bytes in provider file order: for
`user-country` the IPv4 file followed by the IPv6 file; for `dbip` the compressed
archive exactly as downloaded. Per-file digests are kept in `file_digests`.

## Rows and bounds

- A row is `start,end,CC` in dotted or colon notation; quoted columns and CR are accepted.
- Each family must be strictly ascending in the source. `ZZ` rows are validated for order
  and then omitted. IPv4 is normalized into `::ffff:0:0/96` before both families are
  merged and checked for overlap.
- Country codes are the assigned ISO list plus the transitionally reserved `AN` and `FX`
  that RIR-derived data still carries. Anything else fails the whole import.
- Bounds: 1,048,576 ranges, 128 MiB of CSV, 128-byte lines, 16 MiB compressed input.
- Lookups return null for private, reserved, documentation and transition space even
  when a publisher row covers it.

## Snapshot format

`snapshot.encode` writes a `SBGEOIP1` file: a 160-byte header (provider, version, row
count, payload length, generation digest, per-file digests, payload SHA-256) followed by
one row per range. Each row has a tag byte selecting a width class (IPv4, /64-aligned
IPv6, or full 16-byte) and an adjacency flag that omits `start` when it equals the
previous `end + 1`. Encoding is canonical: the decoder rejects any row that could have
been written shorter, any unordered or overlapping row, and any payload whose digest
does not match. Real `user-country` data encodes to roughly 5.8 MB.

`embedded.load` decodes such a snapshot from bytes a build embedded with `@embedFile`;
empty bytes mean no snapshot. `zig build geoip-snapshot` creates one from source files
and `zig build console-geoip-check` validates downloads and snapshots offline.

## Storage rows

`wire` encodes fixed 34-byte rows (two normalized addresses and the country) for the
console's chunked, replicated generation storage. The importer and the storage owner
validate the same bytes with the same function.
