//! Disassembly gate probe (ZDS 0009): exports the SIMD cosine kernel so
//! release verification can inspect generated object code for packed
//! float multiply/add instructions. A benchmark alone is not accepted as
//! proof of SIMD. Not part of the product binary.

const vector = @import("vector.zig");

export fn zaxon_probe_cosine_simd(
    a: [*]const u8,
    b: [*]const u8,
    len: usize,
) f64 {
    return vector.cosineDistanceSimd(a[0..len], b[0..len]) catch -1.0;
}
