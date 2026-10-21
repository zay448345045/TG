// tpshell entry bootstrap
const std = @import("std");
const build_options = @import("build_options");
const interceptor = @import("interceptor.zig");
const restore = @import("restore.zig");

const windows = std.os.windows;

pub const std_options: std.Options = .{ .logFn = logFn, .log_level = .info };

extern "kernel32" fn OutputDebugStringA(message: [*:0]const u8) callconv(.winapi) void;

const LogWriter = struct {
    buffer: [512]u8 = undefined,
    writer: std.Io.Writer = undefined,

    fn init(self: *LogWriter) void {
        self.writer = .{ .buffer = self.buffer[0 .. self.buffer.len - 1], .vtable = &.{ .drain = drain } };
    }

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *LogWriter = @alignCast(@fieldParentPtr("writer", writer));
        if (writer.end != 0) {
            self.buffer[writer.end] = 0;
            OutputDebugStringA(self.buffer[0..writer.end :0].ptr);
            if (comptime build_options.console) @import("console.zig").write(self.buffer[0..writer.end]);
            writer.end = 0;
        }
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |part| {
            self.output(part);
            written += part.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            self.output(last);
            written += last.len;
        }
        return written;
    }

    fn finish(self: *LogWriter) void {
        const length = self.writer.end;
        if (length == 0) {
            if (comptime build_options.console) @import("console.zig").write("\n");
            return;
        }
        self.buffer[length] = 0;
        OutputDebugStringA(self.buffer[0..length :0].ptr);
        if (comptime build_options.console) {
            self.buffer[length] = '\n';
            @import("console.zig").write(self.buffer[0 .. length + 1]);
        }
        self.writer.end = 0;
    }

    fn output(self: *LogWriter, bytes: []const u8) void {
        var remaining = bytes;
        while (remaining.len != 0) {
            const length = @min(remaining.len, self.buffer.len - 1);
            @memcpy(self.buffer[0..length], remaining[0..length]);
            self.buffer[length] = 0;
            OutputDebugStringA(self.buffer[0..length :0].ptr);
            if (comptime build_options.console) @import("console.zig").write(self.buffer[0..length]);
            remaining = remaining[length..];
        }
    }
};

fn logFn(comptime level: std.log.Level, comptime _: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    var log: LogWriter = .{};
    log.init();
    log.writer.print("TPGate " ++ level.asText() ++ ": " ++ format, args) catch {};
    log.finish();
}

var protected_entry: usize = 0;
var self_module: windows.HINSTANCE = undefined;

fn entryBootstrap() callconv(.winapi) windows.DWORD {
    const created_console = if (comptime build_options.console) @import("console.zig").open() else false;
    std.log.info("entry bootstrap", .{});
    const target = restore.apply(@ptrCast(self_module), protected_entry, interceptor.replacement_size, .std) catch |err| {
        std.log.err("pre-entry setup failed: {s}", .{@errorName(err)});
        if (comptime build_options.console) {
            if (created_console) @import("console.zig").waitAfterFailure();
        }
        return 1;
    };
    std.log.info("reconstruction complete", .{});
    const entry: *const fn () callconv(.winapi) windows.DWORD = @ptrFromInt(target);
    return entry();
}

fn tp6Bootstrap(_: usize, _: usize) callconv(.winapi) windows.DWORD {
    const created_console = if (comptime build_options.console) @import("console.zig").open() else false;
    std.log.info("TP6 entry bootstrap", .{});
    const target = restore.apply(@ptrCast(self_module), protected_entry, interceptor.replacement_size, .tp6) catch |err| {
        std.log.err("TP6 pre-entry setup failed: {s}", .{@errorName(err)});
        if (comptime build_options.console) {
            if (created_console) @import("console.zig").waitAfterFailure();
        }
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
