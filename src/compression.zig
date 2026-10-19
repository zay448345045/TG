// tpshell raw lzma wrappers
const std = @import("std");

pub const magic = "\xf8WWWT";
pub const header_size: usize = 16;
pub const dictionary_size: usize = 1 << 26;

pub const DecodeError = error{ InvalidWrapper, InvalidData, OutOfMemory };

pub fn outputSize(wrapper: []const u8) ?usize {
    if (wrapper.len < header_size) return null;
    return (std.mem.readInt(u32, wrapper[8..12], .little) ^ 0x8a0568c1) +% 0x387c84a4;
}

pub fn decode(allocator: std.mem.Allocator, wrapper: []const u8, limit: usize) DecodeError![]u8 {
    const output_size = outputSize(wrapper) orelse return error.InvalidWrapper;
    const input_size = (std.mem.readInt(u32, wrapper[12..16], .little) ^ 0x91b06540) -% 0x41cf9040;
    if (output_size == 0 or output_size > @min(limit, dictionary_size) or
        input_size < 5 or input_size > wrapper.len - header_size) return error.InvalidWrapper;
    var input = std.Io.Reader.fixed(wrapper[header_size..][0..input_size]);
    var range_decoder = std.compress.lzma.RangeDecoder.init(&input) catch return error.InvalidData;
    var decoder = std.compress.lzma.Decode.init(allocator, .{ .lc = 3, .lp = 0, .pb = 2 }) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.InvalidData;
    };
    defer decoder.deinit(allocator);
    var dictionary = std.compress.lzma2.AccumBuffer.init(dictionary_size);
    defer dictionary.deinit(allocator);
    var sink: std.Io.Writer.Allocating = .init(allocator);
    defer sink.deinit();

    // these streams need not contain an end marker
    while (dictionary.len < output_size) {
        var consumed: u64 = 0;
        const status = decoder.process(&input, &sink, &dictionary, &range_decoder, &consumed) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return error.InvalidData;
        };
        if (status == .finished and dictionary.len < output_size) return error.InvalidData;
    }
    if (dictionary.buf.items.len < output_size) return error.InvalidData;
    dictionary.buf.shrinkRetainingCapacity(output_size);
    return dictionary.buf.toOwnedSlice(allocator);
}

test "bounded wrapper without an end marker" {
    const wrapper = "\xf8\x57\x57\x57\x54\x02\x00\x00\x9d\x15\x86\x4d\x09\xf5\x7f\xd0\x00\x00\x6f\xfd\xfe\xb3\x5f\xa8\x00";
    const output = try decode(std.testing.allocator, wrapper, 512);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqual(512, output.len);
    for (output) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expectError(error.InvalidWrapper, decode(std.testing.allocator, wrapper, 511));
    try std.testing.expectError(error.InvalidWrapper, decode(std.testing.allocator, wrapper[0 .. wrapper.len - 1], 512));
}
