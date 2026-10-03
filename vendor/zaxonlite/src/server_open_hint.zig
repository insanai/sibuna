pub fn forError(err: anyerror) []const u8 {
    if (err == error.StateUnavailable) {
        return "The image or anchor no longer reaches retained history. " ++
            "v1 repairs a damaged voter by replacement: enroll a new " ++
            "node and replace this one (ZDS 0008); the frozen " ++
            "conservative trim keeps every slot the successor needs.";
    }
    if (err == error.JoinDescriptorRequired) {
        return "This fresh voter belongs to a later configuration but has no " ++
            "JOIN descriptor. Re-enroll it from the decided replacement; do " ++
            "not copy or synthesize membership files (ZDS 0008).";
    }
    if (err == error.JoinRequiresDataVoter) {
        return "A JOIN descriptor is valid only for an enrolled replacement " ++
            "data-voter. Remove this data directory and enroll the decided " ++
            "replacement again with role data-voter (ZDS 0008).";
    }
    if (err == error.UnsupportedIdentityVersion or
        err == error.UnsupportedManifestVersion or
        err == error.UnsupportedSegmentVersion or
        err == error.UnsupportedTrimVersion)
    {
        return "This data directory was written by zaxonlite 0.6.x. 0.7.0 " ++
            "changed the journal, manifest, TRIM, and identity formats " ++
            "with no migration; stop every member, delete each member's " ++
            "data directory, and recreate the cluster together.";
    }
    return "Check the role-pinned identity and durable files before retrying.";
}

test "a later-configuration voter without JOIN gets a recovery hint" {
    const std = @import("std");
    try std.testing.expect(std.mem.indexOf(
        u8,
        forError(error.JoinDescriptorRequired),
        "Re-enroll",
    ) != null);
}

test "a JOIN descriptor on another role gets a recovery hint" {
    const std = @import("std");
    try std.testing.expect(std.mem.indexOf(
        u8,
        forError(error.JoinRequiresDataVoter),
        "data-voter",
    ) != null);
}
