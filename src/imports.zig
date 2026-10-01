// import blocker
const std = @import("std");

const BOOL = i32;
const DWORD = u32;
const HANDLE = ?*anyopaque;
const HMODULE = ?*anyopaque;

extern "kernel32" fn LoadLibraryA(name: [*:0]const u8) callconv(.winapi) HMODULE;
extern "kernel32" fn LoadLibraryW(name: [*:0]const u16) callconv(.winapi) HMODULE;
extern "kernel32" fn LoadLibraryExA(name: [*:0]const u8, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE;
extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE;
extern "kernel32" fn GetProcAddress(module: HMODULE, name: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FreeLibrary(module: HMODULE) callconv(.winapi) BOOL;

const blocked: []const []const u8 = &.{
    "ACE-Base64.dll",
    // Add other DLLs to block through restored LoadLibrary imports, e.g. PerfSight.dll.
};

var self: HMODULE = null;

pub fn initialize(module: HMODULE) void {
    self = module;
}

fn isBlockedAscii(path: []const u8) bool {
    for (blocked) |name| {
        if (!std.ascii.endsWithIgnoreCase(path, name)) continue;
        const start = path.len - name.len;
        if (start == 0 or path[start - 1] == '\\' or path[start - 1] == '/') return true;
    }
    return false;
}

fn isBlockedWide(path: []const u16) bool {
    for (blocked) |name| {
        if (path.len < name.len) continue;
        const start = path.len - name.len;
        if (start != 0 and path[start - 1] != '\\' and path[start - 1] != '/') continue;
        for (path[start..], name) |wide, ascii| {
            if (wide > 0x7f or std.ascii.toLower(@intCast(wide)) != std.ascii.toLower(ascii)) break;
        } else return true;
    }
    return false;
}

test "ACE load matching" {
    try std.testing.expect(isBlockedAscii("ACE-Base64.dll"));
    try std.testing.expect(isBlockedAscii("C:\\Game\\AntiCheatExpert\\ace-base64.DLL"));
    try std.testing.expect(!isBlockedAscii("not-ACE-Base64.dll"));
    try std.testing.expect(!isBlockedAscii("ACE-Base64.dll.old"));
    try std.testing.expect(!isBlockedAscii("PerfSight.dll"));
    const ace_wide = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Game\\ACE-Base64.dll");
    const perfsight_wide = std.unicode.utf8ToUtf16LeStringLiteral("PerfSight.dll");
    try std.testing.expect(isBlockedWide(ace_wide[0..ace_wide.len]));
    try std.testing.expect(!isBlockedWide(perfsight_wide[0..perfsight_wide.len]));
}

pub fn loadLibraryA(name: [*:0]const u8) callconv(.winapi) HMODULE {
    if (isBlockedAscii(std.mem.span(name))) return self;
    return LoadLibraryA(name);
}

pub fn loadLibraryW(name: [*:0]const u16) callconv(.winapi) HMODULE {
    if (isBlockedWide(std.mem.span(name))) return self;
    return LoadLibraryW(name);
}

pub fn loadLibraryExA(name: [*:0]const u8, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE {
    if (isBlockedAscii(std.mem.span(name))) return self;
    return LoadLibraryExA(name, file, flags);
}

pub fn loadLibraryExW(name: [*:0]const u16, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE {
    if (isBlockedWide(std.mem.span(name))) return self;
    return LoadLibraryExW(name, file, flags);
}

pub fn getProcAddress(module: HMODULE, name: [*:0]const u8) callconv(.winapi) ?*anyopaque {
    if (module == self) return null;
    return GetProcAddress(module, name);
}

pub fn freeLibrary(module: HMODULE) callconv(.winapi) BOOL {
    if (module == self) return 1;
    return FreeLibrary(module);
}
