#import "wireframe.typ": *
#set text(font: "Noto Sans")

#detail-wire("GeoIP", [GeoIP · country enrichment], [Current database], [
  Provider: ip-location-db user-country ▾\
  Source version: 2026-09-09 (example, daily)\
  Active generation: 7 · Loaded: 12:00 UTC\
  IPv4 / IPv6 ranges: counts from loader\
  SHA-256: copy digest\
  Licence: PDDL 1.0 · Attribution: none (DB-IP: CC BY 4.0)

  Country only; no individual coordinates.\
  Private/reserved/unmapped addresses: Unknown

  Lookup address: ​────────  [Look up]\
  Result: country / unknown / generation
], [Update database], [
  Download → validate → stage → activate\
  Progress: 2 of 4 stages · Cancel\
  Bounded bytes and rows; one import at a time

  Preview source, licence, checksum, range count\
  Errors keep the prior generation active.\
  Retry / View diagnostic

  Publisher SHA-256 files verified per source file\
  One HTTPS redirect hop to the fixed asset host

  Update data / Review affected country policies\
  Policy prefixes stay pinned until approved.
], [No database: “GeoIP unavailable”; dashboard globe shows only outline and Unknown totals. No invented locations.])
