//! Shared native/Wasm protocol decoding, with no application or transport imports.
const shared = @import("console_protocol").json_value;
pub const Error = shared.Error;
pub const decode = shared.decode;
pub const decodeFixed = shared.decodeFixed;
pub const into = shared.into;
pub const unsignedOrZero = shared.unsignedOrZero;

test {
    _ = shared;
}
