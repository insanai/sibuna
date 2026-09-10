//! Compatibility namespace; the archive codec is shared with the Wasm history reader.
const codec = @import("console_protocol").rankings_archive;
pub const max_bytes = codec.max_bytes;
pub const Error = codec.Error;
pub const Identity = codec.Identity;
pub const Archive = codec.Archive;
pub const encode = codec.encode;
pub const decode = codec.decode;

pub const decodeInto = codec.decodeInto;
