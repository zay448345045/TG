// reconstruction dump files
const std = @import("std");

const HANDLE = ?*anyopaque;
const generic_write = 0x40000000;
const file_share_all = 0x07;
const create_always = 2;
const file_attribute_normal = 0x80;

extern "kernel32" fn CreateFileA([*:0]const u8, u32, u32, ?*anyopaque, u32, u32, HANDLE) callconv(.winapi) HANDLE;
extern "kernel32" fn WriteFile(HANDLE, [*]const u8, u32, *u32, ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(HANDLE) callconv(.winapi) i32;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;

pub const Import = struct {
    module_hash: u64,
    slot_rva: u32,
    ordinal: u32,
    name_hash: u64 = 0,
    name: ?[*:0]const u8 = null,
    address: ?usize = null,
};

pub fn writeFile(name: [:0]const u8, data: []const u8) void {
    const file = CreateFileA(name.ptr, generic_write, file_share_all, null, create_always, file_attribute_normal, null);
    if (file == null or @intFromPtr(file.?) == std.math.maxInt(usize)) {
        std.log.warn("dump {s} creation failed: Win32 {d}", .{ name, GetLastError() });
        return;
    }
    defer if (CloseHandle(file) == 0) std.log.warn("dump {s} close failed: Win32 {d}", .{ name, GetLastError() });

    var remaining = data;
    while (remaining.len != 0) {
        var written: u32 = 0;
        const count: u32 = @intCast(@min(remaining.len, std.math.maxInt(u32)));
        if (WriteFile(file, remaining.ptr, count, &written, null) == 0) {
            std.log.warn("dump {s} write failed: Win32 {d}", .{ name, GetLastError() });
            return;
        }
        if (written == 0) {
            std.log.warn("dump {s} write stopped", .{name});
            return;
        }
        remaining = remaining[written..];
    }
}

pub fn writeImports(records: []const Import) void {
    var output: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
    defer output.deinit();
    serializeImports(&output.writer, records) catch |err| {
        std.log.warn("dump imports.json serialization failed: {s}", .{@errorName(err)});
        return;
    };
    writeFile("imports.json", output.written());
}

fn serializeImports(writer: *std.Io.Writer, records: []const Import) !void {
    var json: std.json.Stringify = .{ .writer = writer };
    try json.beginArray();
    for (records) |record| {
        try json.beginObject();
        try json.objectField("module_hash");
        var hash_buffer: [18]u8 = undefined;
        try json.write(try std.fmt.bufPrint(&hash_buffer, "0x{x}", .{record.module_hash}));
        try json.objectField("slot_rva");
        try json.write(record.slot_rva);
        if (record.ordinal != 0) {
            try json.objectField("ordinal");
            try json.write(record.ordinal);
        } else {
            try json.objectField("name_hash");
            var name_hash_buffer: [18]u8 = undefined;
            try json.write(try std.fmt.bufPrint(&name_hash_buffer, "0x{x}", .{record.name_hash}));
            if (record.name) |name| {
                try json.objectField("name");
                try json.write(std.mem.span(name));
            }
        }
        if (record.address) |address| {
            try json.objectField("address");
            var address_buffer: [18]u8 = undefined;
            try json.write(try std.fmt.bufPrint(&address_buffer, "0x{x}", .{address}));
        }
        try json.endObject();
    }
    try json.endArray();
}

test "imports dump includes names and ordinals" {
    const records = [_]Import{
        .{ .module_hash = 0x1234, .slot_rva = 64, .ordinal = 0, .name_hash = 0x5678, .name = "LoadLibraryA", .address = 0x9000 },
        .{ .module_hash = 0xabcd, .slot_rva = 72, .ordinal = 7 },
    };
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try serializeImports(&output.writer, &records);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, output.written(), .{});
    defer parsed.deinit();
    const imports = parsed.value.array.items;
    try std.testing.expectEqual(@as(usize, 2), imports.len);
    try std.testing.expectEqualStrings("0x1234", imports[0].object.get("module_hash").?.string);
    try std.testing.expectEqualStrings("0x5678", imports[0].object.get("name_hash").?.string);
    try std.testing.expectEqualStrings("LoadLibraryA", imports[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("0x9000", imports[0].object.get("address").?.string);
    try std.testing.expectEqual(@as(i64, 72), imports[1].object.get("slot_rva").?.integer);
    try std.testing.expectEqual(@as(i64, 7), imports[1].object.get("ordinal").?.integer);
    try std.testing.expect(imports[1].object.get("address") == null);
}
