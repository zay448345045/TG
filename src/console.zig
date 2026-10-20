// optional bootstrap console

const std = @import("std");

const DWORD = u32;
const BOOL = i32;
const HANDLE = ?*anyopaque;
const std_error_handle: DWORD = @bitCast(@as(i32, -12));

extern "kernel32" fn AllocConsole() callconv(.winapi) BOOL;
extern "kernel32" fn GetConsoleWindow() callconv(.winapi) HANDLE;
extern "kernel32" fn SetConsoleOutputCP(code_page: DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn GetStdHandle(kind: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn WriteFile(handle: HANDLE, data: [*]const u8, length: DWORD, written: *DWORD, overlap: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

var active = false;

pub fn open() void {
    if (GetConsoleWindow() == null and AllocConsole() == 0) {
        std.log.err("console creation failed: Win32 {d}", .{GetLastError()});
        return;
    }
    if (SetConsoleOutputCP(65001) == 0) std.log.warn("console UTF-8 setup failed: Win32 {d}", .{GetLastError()});
    @atomicStore(bool, &active, true, .release);
}

pub fn write(message: []const u8) void {
    if (!@atomicLoad(bool, &active, .acquire) or message.len == 0) return;
    const handle = GetStdHandle(std_error_handle);
    if (handle == null or @intFromPtr(handle.?) == std.math.maxInt(usize)) {
        @atomicStore(bool, &active, false, .release);
        std.log.warn("console output handle unavailable", .{});
        return;
    }
    var remaining = message;
    while (remaining.len != 0) {
        const count: DWORD = @intCast(@min(remaining.len, std.math.maxInt(DWORD)));
        var written: DWORD = 0;
        if (WriteFile(handle, remaining.ptr, count, &written, null) == 0) {
            @atomicStore(bool, &active, false, .release);
            std.log.warn("console write failed: Win32 {d}", .{GetLastError()});
            return;
        }
        if (written == 0) {
            @atomicStore(bool, &active, false, .release);
            std.log.warn("console write stopped", .{});
            return;
        }
        remaining = remaining[written..];
    }
}
