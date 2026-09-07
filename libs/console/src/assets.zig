const std = @import("std");
const Context = @import("http.zig").Context;
const wasm = @embedFile("console_wasm");
comptime {
    if (wasm.len > 300 * 1024) @compileError("console Wasm exceeds the 300 KiB budget");
}

pub fn serve(context: *Context, path: []const u8) Context.Error!bool {
    if (context.request.head.method != .GET and context.request.head.method != .HEAD) return false;
    const assets = .{
        .{ "/console/assets/console.wasm", "application/wasm", wasm },
        .{ "/console/assets/glue.js", "text/javascript", @embedFile("console_glue") },
        .{ "/console/assets/console.css", "text/css", @embedFile("console_css") },
    };
    inline for (assets) |asset| {
        if (std.mem.eql(u8, path, asset[0])) {
            try context.respond(.ok, asset[1], asset[2], &.{});
            return true;
        }
    }
    return false;
}
