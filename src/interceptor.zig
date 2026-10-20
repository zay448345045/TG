// executable memory patches
const std = @import("std");
const windows = std.os.windows;

pub const ReplaceError = error{ProtectionFailed};
pub const replacement_size: usize = 12;

pub fn replace(address: usize, comptime replacement: anytype) ReplaceError!void {
    const replacement_address = &replacement;
    var bytes: [replacement_size]u8 = undefined;
    bytes[0] = 0x48;
    bytes[1] = 0xB8;
    std.mem.writeInt(u64, bytes[2..10], @intFromPtr(replacement_address), .little);
    bytes[10] = 0xFF;
    bytes[11] = 0xE0;
    return write(address, &bytes);
}

fn write(address: usize, bytes: *const [replacement_size]u8) ReplaceError!void {
    const alignment = std.heap.page_size_min;

    const start = std.mem.alignBackward(usize, address, alignment);
    const end = std.mem.alignForward(usize, address + bytes.len, alignment);
    var first: windows.PAGE = undefined;
    const status = protect(start, alignment, .{ .EXECUTE_READWRITE = true }, &first);
    if (status != .SUCCESS) {
        std.log.err("entry protection failed: NTSTATUS 0x{x}", .{@backingInt(status)});
        return error.ProtectionFailed;
    }
    var second: windows.PAGE = undefined;
    if (end > start + alignment) {
        const second_status = protect(start + alignment, alignment, .{ .EXECUTE_READWRITE = true }, &second);
        if (second_status != .SUCCESS) {
            std.log.err("entry protection failed: NTSTATUS 0x{x}", .{@backingInt(second_status)});
            restoreProtection(start, first);
            return error.ProtectionFailed;
        }
    }

    const location: [*]u8 = @ptrFromInt(address);
    @memcpy(location[0..bytes.len], bytes);

    if (end > start + alignment) restoreProtection(start + alignment, second);
    restoreProtection(start, first);
}

fn restoreProtection(address: usize, original: windows.PAGE) void {
    var ignored: windows.PAGE = undefined;
    const restore_status = protect(address, std.heap.page_size_min, original, &ignored);
    if (restore_status != .SUCCESS) {
        std.log.warn("entry protection restore failed: NTSTATUS 0x{x}", .{@backingInt(restore_status)});
    }
}

fn protect(address: usize, length: usize, protection: windows.PAGE, old: *windows.PAGE) windows.NTSTATUS {
    var base: ?*anyopaque = @ptrFromInt(address);
    var size = length;
    const process: windows.HANDLE = @ptrFromInt(std.math.maxInt(usize));
    return windows.ntdll.NtProtectVirtualMemory(process, &base, &size, protection, old);
}
