//! Native/Wasm current-minute ranking contract. Decoders must enforce max_rows/key bytes.
pub const max_rows = 12;
pub const Encoding = enum { utf8, hex };
pub const Row = struct {
    key: []const u8,
    encoding: Encoding,
    estimate: u64,
    error_bound: u64,
};
pub const Page = struct {
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
