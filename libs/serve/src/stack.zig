//! Thread stack sizes that survive static thread-local storage and unoptimised frames.
//!
//! glibc carves a thread's static TLS out of the stack it is given, and Zig's standard
//! library keeps the per-thread alternative signal stack (`std.options.signal_stack_size`,
//! 256 KiB by default) in TLS, so a thread asked for exactly N bytes cannot hold its own TLS
//! and glibc refuses it with EINVAL. Every service thread therefore reserves its usable size
//! plus that TLS. Darwin allocates TLS separately; there the extra reservation is virtual.
//!
//! Debug builds keep every temporary in its own stack slot (the self-hosted x86_64 backend
//! especially), so the same code needs several times the optimised frame depth; the usable
//! request is scaled in Debug so test binaries exercise the same paths without overflowing.
//! The documented bound (256 KiB usable per service thread) is the optimised one.
const shared = @import("socket").stack;
pub const debug_scale = shared.debug_scale;
pub const bytes = shared.bytes;
