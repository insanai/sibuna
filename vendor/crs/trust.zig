//! First-party LGPL-3.0 trust facade; upstream key bytes retain their provenance.
//! Rotation is a reviewed source change, never trust-on-first-download.
pub const key = @embedFile("security.asc");
pub const signature = @embedFile("release.tar.gz.asc");
pub const key_sha256 = "b3ea4d3014e9386b61a12cadd986360b358996624b26f9fb6be0fc8a219873ca";
pub const fingerprint = "36006F0E0BA167832158821138EEACA1AB8A6E72";
