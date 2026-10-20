// console and standard handles

const std = @import("std");
const build_options = @import("build_options");

const DWORD = u32;
const BOOL = i32;
const HANDLE = ?*anyopaque;

extern "kernel32" fn AllocConsole() callconv(.winapi) BOOL;
extern "kernel32" fn GetConsoleWindow() callconv(.winapi) HANDLE;
extern "kernel32" fn SetConsoleOutputCP(code_page: DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn WriteFile(handle: HANDLE, data: [*]const u8, length: DWORD, written: *DWORD, overlap: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn CreateFileA(name: [*:0]const u8, access: DWORD, share: DWORD, security: ?*anyopaque, disposition: DWORD, attributes: DWORD, template: HANDLE) callconv(.winapi) HANDLE;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

fn stdoutSlot() *HANDLE {
    return @ptrCast(&std.os.windows.peb().ProcessParameters.hStdOutput);
}

fn stderrSlot() *HANDLE {
    return @ptrCast(&std.os.windows.peb().ProcessParameters.hStdError);
}

var active = false;
var log_handle: HANDLE = null;

pub fn open() void {
    if (GetConsoleWindow() == null and AllocConsole() == 0) {
        std.log.err("console creation failed: Win32 {d}", .{GetLastError()});
        return;
    }
    if (SetConsoleOutputCP(65001) == 0) std.log.warn("console UTF-8 setup failed: Win32 {d}", .{GetLastError()});
    if (comptime build_options.mute_output) log_handle = stderrSlot().*;
    @atomicStore(bool, &active, true, .release);
}

pub fn write(message: []const u8) void {
    if (!@atomicLoad(bool, &active, .acquire) or message.len == 0) return;
    const handle = if (comptime build_options.mute_output) log_handle else stderrSlot().*;
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

// reconstruction output
pub const MutedOutput = struct {
    output: HANDLE,
    error_output: HANDLE,

    pub fn restore(self: MutedOutput) void {
        stdoutSlot().* = self.output;
        stderrSlot().* = self.error_output;
    }
};

pub fn mute() ?MutedOutput {
    const generic_write = 0x40000000;
    const file_share_read_write = 3;
    const open_existing = 3;
    const file_attribute_normal = 0x80;
    const sink = CreateFileA("NUL", generic_write, file_share_read_write, null, open_existing, file_attribute_normal, null);
    if (sink == null or @intFromPtr(sink.?) == std.math.maxInt(usize)) {
        std.log.warn("output sink creation failed: Win32 {d}", .{GetLastError()});
        return null;
    }
    const output = stdoutSlot().*;
    const error_output = stderrSlot().*;
    // loaded code may retain this handle after standard handles are restored
    stdoutSlot().* = sink;
    stderrSlot().* = sink;
    return .{ .output = output, .error_output = error_output };
}
