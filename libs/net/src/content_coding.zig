//! Compatibility exports; pure HTTP representation decoding belongs below networking.
const coding = @import("compression").content_coding;
pub const Error = coding.Error;
pub const Storage = coding.Storage;
pub const Plan = coding.Plan;
