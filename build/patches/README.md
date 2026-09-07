# Zaxonlite 0.6.1 sealed journal iterator correction

The full GeoIP browser fixture crossed a journal rotation boundary and then failed to
restart with `CorruptJournal`. Its manifest, sealed-segment digest, record checksums,
sequence continuity and active-segment ancestry were valid.

`Journal.Iterator.next` knows that a manifest-listed segment is sealed, but 0.6.1 calls
`segment.Reader.open`, whose record boundary is the file length. Iteration therefore reads
the sealed trailer as a record. The one-line patch uses `Reader.openSealed`, which verifies
the digest and sets the record boundary before the trailer. It neither skips validation
nor rewrites stored data.

`tools/patch_zaxonlite.py` verifies the original source SHA-256 and the exact reviewed diff.
`build/storage.zig` applies it to a generated source tree while retaining the pinned 0.6.1
package and its C, TLS and module configuration. The downloaded package is never modified.
The deterministic storage test lowers the rotation threshold, writes sessions across
multiple sealed segments, closes storage and verifies authorization after reopening.

Remove this patch only after a separately reviewed dependency update includes the fix
and the rotation/restart regression still passes. This patch changes no on-disk format.
