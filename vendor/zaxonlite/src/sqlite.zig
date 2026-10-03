//! Stable SQLite facade: the import path the rest of the product uses.
//!
//! The translated C header is confined to `src/sqlite/`; this facade
//! re-exports the narrow wrapper so product code never sees translated C
//! declarations. The subsystem split (ZDS 0009): `sqlite/core.zig` owns the
//! connection and statement lifecycle, `sqlite/search_extension.zig` owns
//! the search SQL function registration and sqlite-vec glue.

pub const core = @import("sqlite/core.zig");
pub const search_extension = @import("sqlite/search_extension.zig");

pub const Error = core.Error;
pub const Db = core.Db;
pub const Stmt = core.Stmt;
pub const ColumnType = core.ColumnType;
pub const formatReal = core.formatReal;
pub const OpenOptions = core.OpenOptions;
pub const max_mmap_bytes = core.max_mmap_bytes;
pub const WalHook = core.WalHook;
pub const Authorizer = core.Authorizer;
pub const ProgressHandler = core.ProgressHandler;
pub const auth = core.auth;
pub const compileOptionUsed = core.compileOptionUsed;
pub const libversionNumber = core.libversionNumber;
pub const vecVersion = core.vecVersion;
pub const memoryHighwater = core.memoryHighwater;

test {
    _ = core;
    _ = search_extension;
}
