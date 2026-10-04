//! Only canonical stock release destinations are constructed. Release metadata is
//! a version hint, never permission to fetch an arbitrary asset URL or signing key.
const std = @import("std");
const versions = @import("release_version.zig");
pub const latest = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest";
pub const metadata_capacity = 128 * 1024;
pub const signature_capacity = 16 * 1024;
pub const archive_capacity = 8 * 1024 * 1024;
pub const maximum_url = 256;
pub const Asset = enum { archive, signature };
pub const Error = versions.Error || error{ ReleaseUrlLimit, UnstableRelease, InvalidReleaseTag };

pub fn url(version: versions.Version, asset: Asset, output: []u8) Error![]const u8 {
    var version_buffer: [17]u8 = undefined;
    const text = try version.write(&version_buffer);
    return std.fmt.bufPrint(
        output,
        "https://github.com/coreruleset/coreruleset/releases/download/v{s}/" ++
            "coreruleset-{s}-minimal.tar.gz{s}",
        .{ text, text, if (asset == .signature) ".asc" else "" },
    ) catch error.ReleaseUrlLimit;
}

/// The management caller performs bounded JSON decoding. Repeated or missing
/// fields fail there; this function refuses drafts, prereleases and noncanonical tags.
pub fn fromMetadata(tag: []const u8, draft: bool, prerelease: bool) Error!versions.Version {
    if (draft or prerelease) return error.UnstableRelease;
    if (tag.len < 2 or tag[0] != 'v') return error.InvalidReleaseTag;
    return versions.Version.parse(tag[1..]);
}

test "stock URLs cannot inherit destinations from release metadata" {
    var output: [maximum_url]u8 = undefined;
    const version = try fromMetadata("v4.30.0", false, false);
    const archive = "https://github.com/coreruleset/coreruleset/releases/download/" ++
        "v4.30.0/coreruleset-4.30.0-minimal.tar.gz";
    try std.testing.expectEqualStrings(archive, try url(version, .archive, &output));
    try std.testing.expectEqualStrings(archive ++ ".asc", try url(version, .signature, &output));
    try std.testing.expectError(error.ReleaseUrlLimit, url(version, .archive, output[0..1]));
    try std.testing.expectError(error.UnstableRelease, fromMetadata("v4.30.0", true, false));
    try std.testing.expectError(error.UnstableRelease, fromMetadata("v4.30.0", false, true));
    try std.testing.expectError(error.InvalidReleaseTag, fromMetadata("4.30.0", false, false));
    try std.testing.expectError(
        error.InvalidReleaseVersion,
        fromMetadata("v4.30.0/../x", false, false),
    );
}
