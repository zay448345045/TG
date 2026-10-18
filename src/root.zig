// tpshell entry bootstrap
const std = @import("std");
const interceptor = @import("interceptor.zig");
const restore = @import("restore.zig");

const windows = std.os.windows;

pub const std_options: std.Options = .{ .logFn = logFn, .log_level = .info };

extern "kernel32" fn OutputDebugStringA(message: [*:0]const u8) callconv(.winapi) void;

fn logFn(comptime level: std.log.Level, comptime _: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    var buffer: [512]u8 = undefined;
    const message = std.fmt.bufPrint(buffer[0 .. buffer.len - 1], "TPGate " ++ level.asText() ++ ": " ++ format, args) catch {
        OutputDebugStringA("TPGate: log message too long");
        return;
    };
    buffer[message.len] = 0;
    OutputDebugStringA(buffer[0..message.len :0].ptr);
}

var protected_entry: usize = 0;
var self_module: windows.HINSTANCE = undefined;

fn entryBootstrap() callconv(.winapi) windows.DWORD {
    std.log.info("entry bootstrap", .{});
    const target = restore.apply(@ptrCast(self_module), protected_entry, interceptor.replacement_size, .std) catch |err| {
        std.log.err("pre-entry setup failed: {s}", .{@errorName(err)});
        return 0;
    };
    std.log.info("reconstruction complete", .{});
    const entry: *const fn () callconv(.winapi) windows.DWORD = @ptrFromInt(target);
    return entry();
}

fn tp6Bootstrap(_: usize, _: usize) callconv(.winapi) windows.DWORD {
    std.log.info("TP6 entry bootstrap", .{});
    const target = restore.apply(@ptrCast(self_module), protected_entry, interceptor.replacement_size, .tp6) catch |err| {
        std.log.err("TP6 pre-entry setup failed: {s}", .{@errorName(err)});
        return 1;
    };
    std.log.info("TP6 reconstruction complete", .{});
    const entry: *const fn (usize, usize) callconv(.winapi) windows.DWORD = @ptrFromInt(target);
    return @call(.always_tail, entry, .{ 0, 0 });
}

pub export fn TpShellEntry() callconv(.winapi) windows.BOOL {
    std.log.info("ordinal 1 called", .{});
    return .TRUE;
}

pub export fn DllMain(module: windows.HINSTANCE, reason: windows.DWORD, _: windows.LPVOID) callconv(.winapi) windows.BOOL {
    if (reason == 1) {
        self_module = module;
        std.log.info("process attach", .{});
        restore.disableTlsCallbacks() catch |err| {
            std.log.err("TLS setup failed: {s}", .{@errorName(err)});
            return .FALSE;
        };
        protected_entry = restore.protectedEntry() catch |err| {
            std.log.err("protected entry lookup failed: {s}", .{@errorName(err)});
            return .FALSE;
        };
        if (restore.protectionMode() == .tp6) {
            interceptor.replace(protected_entry, tp6Bootstrap) catch |err| {
                std.log.err("TP6 entry patch failed: {s}", .{@errorName(err)});
                return .FALSE;
            };
        } else {
            interceptor.replace(protected_entry, entryBootstrap) catch |err| {
                std.log.err("entry patch failed: {s}", .{@errorName(err)});
                return .FALSE;
            };
        }
    }
    return .TRUE;
}
