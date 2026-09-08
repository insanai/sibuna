//! Native/Wasm current-minute ranking contract. Decoders must enforce max_rows/key bytes.
pub const max_rows = 12;
pub const Encoding = enum { utf8, hex };
pub const Inventory = struct {
    available: bool = false,
    archives: u64 = 0,
    first_minute: ?u64 = null,
    last_minute: ?u64 = null,
    reserved_bytes: u64 = 0,
    observed_at: u64 = 0,
};
pub const ArchiveStatus = struct {
    stored: Inventory = .{},
    pending: u32 = 0,
    saved_since_boot: u64 = 0,
    unconfirmed_since_boot: u64 = 0,
    maintenance_failures_since_boot: u64 = 0,
    last_saved_minute: ?u64 = null,
};
pub const Row = struct {
    key: []const u8,
    encoding: Encoding,
    estimate: u64,
    error_bound: u64,
};
pub const Page = struct {
    archive: ArchiveStatus = .{},
    kind: []const u8 = "path_prefix",
    minute_start: u64,
    snapshot_at: u64,
    first_sample: ?u64,
    last_sample: ?u64,
    retained_samples: u64,
    sampling_probability: []const u8 = "1/64",
    truncated_records: u64,
    rejected_records: u64,
    queue_loss_since_boot: u64,
    counter_capacity: u16 = 256,
    missing_key_bound: u64,
    rows: []const Row,
};
