// native fragment restoration
const std = @import("std");
const coff = std.coff;
const compression = @import("compression.zig");
const interceptor = @import("interceptor.zig");

extern "kernel32" fn VirtualAlloc(address: ?*anyopaque, size: usize, allocation: u32, protection: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn VirtualFree(address: ?*anyopaque, size: usize, operation: u32) callconv(.winapi) i32;
extern "kernel32" fn VirtualProtect(address: ?*anyopaque, size: usize, protection: u32, old: *u32) callconv(.winapi) i32;
extern "kernel32" fn FlushInstructionCache(process: ?*anyopaque, address: ?*const anyopaque, size: usize) callconv(.winapi) i32;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;

fn rd16(address: usize) u16 {
    return @as(*align(1) const u16, @ptrFromInt(address)).*;
}

fn rd32(address: usize) u32 {
    return @as(*align(1) const u32, @ptrFromInt(address)).*;
}

const Layout = struct { base: usize, tail: u32, end: u32 };
const Record = struct {
    thunk: u32,
    slot: u32,
    continuation: u32,
    size: u32,

    fn decode(bytes: []const u8) Record {
        const address = @intFromPtr(bytes.ptr);
        return .{
            .thunk = (rd32(address) ^ 0x64d5e500) +% 0x762105df,
            .slot = (rd32(address + 4) ^ 0x53820949) -% 0x26bb8505,
            .continuation = (rd32(address + 8) ^ 0xbf362745) +% 0x43734d1f,
            .size = (rd32(address + 12) ^ 0x9496cc41) +% 0x3e817d55,
        };
    }

    fn matches(self: Record, layout: Layout, remaining: usize) bool {
        if (self.thunk < layout.tail or @as(u64, self.thunk) + 6 > layout.end or
            self.slot < layout.tail or @as(u64, self.slot) + 8 > layout.end or
            self.size == 0 or self.size > remaining) return false;
        if (self.continuation == 0) return true;
        return self.continuation >= 5 and self.continuation < layout.tail;
    }

    fn referencesCall(self: Record, layout: Layout) bool {
        // the continuation skips junk bytes after the call
        for (5..17) |distance| {
            if (self.continuation < distance) break;
            const call_rva = self.continuation - @as(u32, @intCast(distance));
            const call = layout.base + call_rva;
            if (@as(*const u8, @ptrFromInt(call)).* == 0xe8 and
                call_rva +% 5 +% rd32(call + 1) == self.thunk) return true;
        }
        return false;
    }
};

const Run = struct { start: usize, end: usize, code_size: usize };

fn findRun(data: []const u8, layout: Layout) ?Run {
    var start: usize = 0;
    while (start + 16 <= data.len) : (start += 1) {
        var offset = start;
        var code_size: usize = 0;
        var matched_call = false;
        while (offset + 16 <= data.len) {
            const item = Record.decode(data[offset..]);
            if (!item.matches(layout, data.len - offset - 16)) break;
            matched_call = matched_call or item.referencesCall(layout);
            code_size += item.size + 19;
            offset += 16 + item.size;
        }
        if (matched_call) return .{ .start = start, .end = offset, .code_size = code_size };
    }
    return null;
}

fn restoreRun(data: []const u8, run: Run, layout: Layout) !void {
    const allocation = VirtualAlloc(null, run.code_size, 0x3000, 0x04) orelse {
        std.log.err("native fragment allocation failed: Win32 {d}", .{GetLastError()});
        return error.FragmentAllocationFailed;
    };
    var installed = false;
    defer {
        if (!installed) _ = VirtualFree(allocation, 0, 0x8000);
    }
    const code: [*]u8 = @ptrCast(allocation);
    var offset = run.start;
    var cursor: usize = 0;
    while (offset < run.end) {
        const item = Record.decode(data[offset..]);
        @memcpy(code[cursor..][0..5], "\x48\x8d\x64\x24\x08");
        @memcpy(code[cursor + 5 ..][0..item.size], data[offset + 16 ..][0..item.size]);
        const jump = cursor + 5 + item.size;
        @memcpy(code[jump..][0..6], "\xff\x25\x00\x00\x00\x00");
        std.mem.writeInt(u64, code[jump + 6 ..][0..8], layout.base + item.continuation, .little);
        cursor += item.size + 19;
        offset += 16 + item.size;
    }
    var old: u32 = 0;
    if (VirtualProtect(allocation, run.code_size, 0x20, &old) == 0) {
        std.log.err("native fragment code protection failed: Win32 {d}", .{GetLastError()});
        return error.FragmentCodeProtectionFailed;
    }
    const tail = @as([*]u8, @ptrFromInt(layout.base + layout.tail))[0 .. layout.end - layout.tail];
    if (VirtualProtect(tail.ptr, tail.len, 0x40, &old) == 0) {
        std.log.err("native fragment tail protection failed: Win32 {d}", .{GetLastError()});
        return error.FragmentTailProtectionFailed;
    }
    offset = run.start;
    cursor = 0;
    while (offset < run.end) {
        const item = Record.decode(data[offset..]);
        const thunk = @as([*]u8, @ptrFromInt(layout.base + item.thunk))[0..6];
        @memcpy(thunk[0..2], "\xff\x25");
        std.mem.writeInt(u32, thunk[2..6], item.slot -% (item.thunk + 6), .little);
        @as(*align(1) usize, @ptrFromInt(layout.base + item.slot)).* = @intFromPtr(allocation) + cursor;
        cursor += item.size + 19;
        offset += 16 + item.size;
    }
    installed = true;
    var ignored: u32 = 0;
    if (VirtualProtect(tail.ptr, tail.len, old, &ignored) == 0) {
        std.log.warn("native fragment tail protection restore failed: Win32 {d}", .{GetLastError()});
    }
    const process: *anyopaque = @ptrFromInt(std.math.maxInt(usize));
    if (FlushInstructionCache(process, allocation, run.code_size) == 0) {
        std.log.warn("native fragment code cache flush failed: Win32 {d}", .{GetLastError()});
    }
    if (FlushInstructionCache(process, tail.ptr, tail.len) == 0) {
        std.log.warn("native fragment tail cache flush failed: Win32 {d}", .{GetLastError()});
    }
}

fn restorePayload(layout: Layout, base: usize) !void {
    const pe = base + rd32(base + 0x3c);
    const entry = rd32(pe + 0x28);
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + rd16(pe + 0x14));
    for (sections[0..rd16(pe + 6)]) |section| {
        if (entry < section.virtual_address or @as(u64, entry) >= @as(u64, section.virtual_address) + section.virtual_size) continue;
        const bytes = @as([*]const u8, @ptrFromInt(base + section.virtual_address))[0..section.virtual_size];
        var cursor: usize = 2;
        while (std.mem.indexOfPos(u8, bytes, cursor, compression.magic[2..])) |candidate| {
            cursor = candidate + 1;
            const start = candidate - 2;
            if (bytes.len - start < compression.header_size) continue;
            const address = base + section.virtual_address + start;
            // the entry jump can overwrite the first two magic bytes
            if (!std.mem.startsWith(u8, bytes[start..], compression.magic) and
                !(address >= base + entry and address + 2 <= base + entry + interceptor.replacement_size)) continue;
            const allocator = std.heap.page_allocator;
            const data = compression.decode(allocator, bytes[start..], compression.dictionary_size) catch |err| {
                if (err == error.OutOfMemory) return err;
                continue;
            };
            defer allocator.free(data);
            if (findRun(data, layout)) |run| return restoreRun(data, run, layout);
        }
    }
}

pub fn restore(module: ?*anyopaque, main_base: usize) !void {
    const base = @intFromPtr(module);
    const pe = base + rd32(base + 0x3c);
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + rd16(pe + 0x14));
    for (sections[0..rd16(pe + 6)]) |section| {
        if (!std.mem.eql(u8, section.name[0..5], ".tvm0") or section.virtual_size <= section.size_of_raw_data) continue;
        const layout: Layout = .{
            .base = base,
            .tail = section.virtual_address + section.size_of_raw_data,
            .end = section.virtual_address + section.virtual_size,
        };
        const tail = @as([*]const u8, @ptrFromInt(base + layout.tail))[0 .. layout.end - layout.tail];
        if (std.mem.indexOf(u8, tail, "\xff\x25") != null) continue;
        try restorePayload(layout, main_base);
    }
}

test "fragment run includes call-site junk and unreferenced continuations" {
    var image: [128]u8 = @splat(0);
    image[17] = 0xe8;
    std.mem.writeInt(u32, image[18..22], 80 - 22, .little);
    const layout: Layout = .{ .base = @intFromPtr(&image), .tail = 80, .end = image.len };
    var data: [41]u8 = @splat(0);
    for ([_]Record{
        .{ .thunk = 80, .slot = 100, .continuation = 24, .size = 1 },
        .{ .thunk = 86, .slot = 108, .continuation = 40, .size = 1 },
    }, 0..) |item, index| {
        const start = 7 + index * 17;
        std.mem.writeInt(u32, data[start..][0..4], (item.thunk -% 0x762105df) ^ 0x64d5e500, .little);
        std.mem.writeInt(u32, data[start + 4 ..][0..4], (item.slot +% 0x26bb8505) ^ 0x53820949, .little);
        std.mem.writeInt(u32, data[start + 8 ..][0..4], (item.continuation -% 0x43734d1f) ^ 0xbf362745, .little);
        std.mem.writeInt(u32, data[start + 12 ..][0..4], (item.size -% 0x3e817d55) ^ 0x9496cc41, .little);
        data[start + 16] = 0xc3;
    }
    const run = findRun(&data, layout).?;
    try std.testing.expectEqual(@as(usize, 7), run.start);
    try std.testing.expectEqual(data.len, run.end);
    try std.testing.expectEqual(@as(usize, 40), run.code_size);
    image[17] = 0x90;
    try std.testing.expectEqual(@as(?Run, null), findRun(&data, layout));
    const item = Record.decode(data[7..]);
    try std.testing.expect(!item.matches(.{ .base = layout.base, .tail = 80, .end = 107 }, 1));
    try std.testing.expect(!item.matches(layout, 0));
}
