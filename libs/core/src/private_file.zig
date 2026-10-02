//! Credentials must be private on the opened file, not merely on a path checked earlier.
//! POSIX mode checks and Windows DACL checks share one fail-closed application contract.
const std = @import("std");
const w = std.os.windows;
pub const Error = error{InsecurePermissions};

pub fn check(io: std.Io, file: std.Io.File) Error!void {
    if (@import("builtin").os.tag == .windows) return checkWindows(file.handle);
    const stat = file.stat(io) catch return error.InsecurePermissions;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
}

const Acl = extern struct {
    revision: u8,
    reserved: u8,
    size: u16,
    count: u16,
    reserved2: u16,
};
const Ace = extern struct { kind: u8, flags: u8, size: u16, mask: u32, sid: u32 };

extern "advapi32" fn GetSecurityInfo(
    w.HANDLE,
    u32,
    u32,
    *?*anyopaque,
    ?*?*anyopaque,
    *?*Acl,
    ?*?*Acl,
    *?*anyopaque,
) callconv(.winapi) u32;
extern "advapi32" fn GetAce(*Acl, u32, *?*anyopaque) callconv(.winapi) i32;
extern "advapi32" fn EqualSid(*anyopaque, *anyopaque) callconv(.winapi) i32;
extern "advapi32" fn IsWellKnownSid(*anyopaque, u32) callconv(.winapi) i32;
extern "kernel32" fn LocalFree(*anyopaque) callconv(.winapi) ?*anyopaque;

fn checkWindows(handle: w.HANDLE) Error!void {
    var owner: ?*anyopaque = null;
    var acl: ?*Acl = null;
    var descriptor: ?*anyopaque = null;
    // SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION.
    if (GetSecurityInfo(handle, 1, 1 | 4, &owner, null, &acl, null, &descriptor) != 0)
        return error.InsecurePermissions;
    defer {
        if (descriptor) |value| _ = LocalFree(value);
    }
    const identity = owner orelse return error.InsecurePermissions;
    const permissions = acl orelse return error.InsecurePermissions; // Null DACL grants everyone.
    if (permissions.count == 0) return error.InsecurePermissions;
    for (0..permissions.count) |index| {
        var pointer: ?*anyopaque = null;
        if (GetAce(permissions, @intCast(index), &pointer) == 0)
            return error.InsecurePermissions;
        const ace: *const Ace = @ptrCast(@alignCast(pointer orelse
            return error.InsecurePermissions));
        if (ace.flags & 8 != 0 or ace.kind == 1) continue; // Inherit-only and deny entries.
        // Only simple allow ACEs are accepted. Unknown grant forms fail closed.
        if (ace.kind != 0 or ace.size < @sizeOf(Ace)) return error.InsecurePermissions;
        const principal: *anyopaque = @ptrCast(@constCast(&ace.sid));
        // WinLocalSystemSid (22) and WinBuiltinAdministratorsSid (26) are trusted OS owners.
        if (EqualSid(principal, identity) == 0 and IsWellKnownSid(principal, 22) == 0 and
            IsWellKnownSid(principal, 26) == 0) return error.InsecurePermissions;
    }
}
