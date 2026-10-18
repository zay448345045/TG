// library loader hooks
const std = @import("std");
const fragments = @import("fragments.zig");

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
extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(.winapi) HMODULE;
extern "kernel32" fn VirtualProtect(address: ?*anyopaque, size: usize, protection: DWORD, old: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn K32EnumProcessModules(process: HANDLE, modules: [*]HMODULE, bytes: DWORD, needed: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

fn patchDependencies(module: HMODULE) HMODULE {
    if (module == null or module == self or isSystemLoader(module)) return module;
    patchLoaded() catch |err| {
        std.log.err("loaded module patch failed: {s}", .{@errorName(err)});
        _ = FreeLibrary(module);
        return null;
    };
    return module;
}

pub fn patchLoaded() !void {
    var stack: [1024]HMODULE = undefined;
    var owned: ?[]HMODULE = null;
    defer if (owned) |buffer| std.heap.page_allocator.free(buffer);
    var modules: []HMODULE = &stack;
    while (true) {
        var needed: DWORD = 0;
        if (K32EnumProcessModules(@ptrFromInt(std.math.maxInt(usize)), modules.ptr, @intCast(modules.len * @sizeOf(HMODULE)), &needed) == 0) {
            std.log.err("module enumeration failed: Win32 {d}", .{GetLastError()});
            return error.ModuleEnumerationFailed;
        }
        if (needed <= modules.len * @sizeOf(HMODULE)) {
            for (modules[0 .. needed / @sizeOf(HMODULE)]) |loaded| try patch(loaded);
            return;
        }
        const count = (@as(usize, needed) + @sizeOf(HMODULE) - 1) / @sizeOf(HMODULE);
        const larger = try std.heap.page_allocator.alloc(HMODULE, count);
        if (owned) |buffer| std.heap.page_allocator.free(buffer);
        owned = larger;
        modules = larger;
    }
}

const blocked: []const []const u8 = &.{
    "ACE-Base64.dll",
    // add DLL basenames to block such as PerfSight.dll
};

var self: HMODULE = null;
const load_names = .{ "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "FreeLibrary" };
var original_addresses: [2][load_names.len]usize = undefined;
var loader_modules: [3]HMODULE = undefined;

pub fn initialize(module: HMODULE) void {
    self = module;
    inline for (.{ "kernel32.dll", "kernelbase.dll", "ntdll.dll" }, 0..) |library, library_index| {
        const handle = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral(library));
        loader_modules[library_index] = handle;
        if (handle == null) std.log.err("loader module {s} not present", .{library});
        if (library_index < original_addresses.len) {
            inline for (load_names, 0..) |name, index| {
                original_addresses[library_index][index] = if (handle) |loaded|
                    if (GetProcAddress(loaded, name)) |address| @intFromPtr(address) else 0
                else
                    0;
            }
        }
    }
}

pub fn redirect(address: usize) usize {
    if (address == 0) return 0;
    const replacements = .{ loadLibraryA, loadLibraryW, loadLibraryExA, loadLibraryExW, getProcAddress, freeLibrary };
    inline for (replacements, 0..) |replacement, index| {
        for (original_addresses) |library| {
            if (address == library[index]) return @intFromPtr(&replacement);
        }
    }
    return address;
}

fn isSystemLoader(module: HMODULE) bool {
    return std.mem.indexOfScalar(HMODULE, &loader_modules, module) != null;
}

// resolved import slots
fn patch(module: HMODULE) !void {
    if (module == null or module == self or isSystemLoader(module)) return;
    const base = @intFromPtr(module);
    const pe = base + @as(*align(1) const u32, @ptrFromInt(base + 0x3c)).*;
    const import_rva = @as(*align(1) const u32, @ptrFromInt(pe + 0x90)).*;
    if (import_rva != 0) {
        var descriptor = base + import_rva;
        while (@as(*align(1) const u32, @ptrFromInt(descriptor + 12)).* != 0) : (descriptor += 20) {
            const thunk_rva = @as(*align(1) const u32, @ptrFromInt(descriptor + 16)).*;
            if (thunk_rva == 0) continue;
            var slot: *align(1) usize = @ptrFromInt(base + thunk_rva);
            while (slot.* != 0) {
                const replacement = redirect(slot.*);
                if (replacement != slot.*) {
                    var old: DWORD = 0;
                    if (VirtualProtect(slot, @sizeOf(usize), 0x04, &old) == 0) {
                        std.log.err("hook slot 0x{x} protection failed: Win32 {d}", .{ @intFromPtr(slot), GetLastError() });
                        return error.HookProtectionFailed;
                    }
                    slot.* = replacement;
                    var ignored: DWORD = 0;
                    if (VirtualProtect(slot, @sizeOf(usize), old, &ignored) == 0) {
                        std.log.warn("hook slot 0x{x} protection restore failed: Win32 {d}", .{ @intFromPtr(slot), GetLastError() });
                    }
                }
                slot = @ptrFromInt(@intFromPtr(slot) + @sizeOf(usize));
            }
        }
    }
    fragments.restore(module) catch |err| {
        std.log.err("native fragment restore failed in module 0x{x}: {s}", .{ base, @errorName(err) });
        return err;
    };
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
    return patchDependencies(LoadLibraryA(name));
}

pub fn loadLibraryW(name: [*:0]const u16) callconv(.winapi) HMODULE {
    if (isBlockedWide(std.mem.span(name))) return self;
    return patchDependencies(LoadLibraryW(name));
}

pub fn loadLibraryExA(name: [*:0]const u8, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE {
    if (isBlockedAscii(std.mem.span(name))) return self;
    return patchDependencies(LoadLibraryExA(name, file, flags));
}

pub fn loadLibraryExW(name: [*:0]const u16, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE {
    if (isBlockedWide(std.mem.span(name))) return self;
    return patchDependencies(LoadLibraryExW(name, file, flags));
}

pub fn getProcAddress(module: HMODULE, name: [*:0]const u8) callconv(.winapi) ?*anyopaque {
    if (module == self) return null;
    const address = GetProcAddress(module, name) orelse return null;
    return @ptrFromInt(redirect(@intFromPtr(address)));
}

pub fn freeLibrary(module: HMODULE) callconv(.winapi) BOOL {
    if (module == self) return 1;
    return FreeLibrary(module);
}
