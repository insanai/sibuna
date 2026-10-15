//! The console's HTTP/1.1 client (unit U2; Zig's `console_client.zig`), used by the CLI
//! and by GeoIP downloads: a bounded request writer and response reader over TCP or a
//! `sibuna_tls::TlsStream`, `Content-Length` or chunked bodies with a byte bound, plain
//! HTTP only to loopback literals.
