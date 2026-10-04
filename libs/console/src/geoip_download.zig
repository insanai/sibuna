//! Only fixed publisher URLs are reachable. No browser-supplied destination, credentials or
//! proxy headers enter a download request. A redirect is followed once, over HTTPS only, to
//! the provider's allowlisted asset host; anything else fails closed.
const App = @import("app.zig").App;
const geoip = @import("geoip");
pub const max_source_bytes = 32 * 1024 * 1024;
pub const checksum_bytes = 256;
/// Downloads one provider file into `output` and returns the received bytes.
pub fn fetch(
    app: *App,
    provider: geoip.Provider,
    file: u8,
    version: []const u8,
    output: []u8,
) ![]const u8 {
    var url_buffer: [geoip.provider.max_url]u8 = undefined;
    const url = try provider.url(file, version, &url_buffer);
    return fetchUrl(app, provider, url, output);
}

/// Fetches and parses the publisher's digest file for one provider file.
pub fn fetchChecksum(app: *App, provider: geoip.Provider, file: u8, version: []const u8) ![32]u8 {
    var url_buffer: [geoip.provider.max_url]u8 = undefined;
    const url = (try provider.checksumUrl(file, version, &url_buffer)) orelse
        return error.NoChecksum;
    var name_buffer: [64]u8 = undefined;
    const name = try provider.fileName(file, version, &name_buffer);
    var text: [checksum_bytes]u8 = undefined;
    const received = try fetchUrl(app, provider, url, &text);
    return geoip.provider.parseChecksumFile(received, name);
}

pub fn fetchUrl(app: *App, provider: geoip.Provider, url: []const u8, output: []u8) ![]const u8 {
    if (output.len == 0 or output.len > max_source_bytes) return error.InvalidInput;
    const initial: []const []const u8 = switch (provider) {
        .user_country => &.{"github.com"},
        .dbip => &.{"download.db-ip.com"},
    };
    const redirects: []const []const u8 = switch (provider) {
        .user_country => &.{
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
        },
        .dbip => &.{},
    };
    return @import("net").fetch.fetch(.{
        .allocator = app.gpa,
        .io = app.io,
        .stopping = &app.stopping,
        .initial_hosts = initial,
        .redirect_hosts = redirects,
    }, url, output);
}
