//! Compatibility facade. MIME syntax belongs to the pure text library and is
//! shared by prefix inspection and complete CRS body acquisition.
const mime = @import("text").mime;
pub const Error = mime.Error;
pub const Parameter = mime.Parameter;
pub const Value = mime.Value;
pub const token = mime.token;
pub const binary = mime.binary;
pub const mediaType = mime.mediaType;
