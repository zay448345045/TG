// static import recipe

const std = @import("std");
const coff = std.coff;
const decoder = @import("decoder.zig");
const compression = @import("compression.zig");

const import_ordinal_flag: u64 = @as(u64, 1) << 63;
const wrapper_magic = "WWWT";
const wrapper_size = compression.header_size;
const output_limit: usize = 8 << 20;
const fields_per_record: usize = 8;
const max_sections: usize = 256;

pub const Record = struct {
    name_hash: u64,
    ordinal: u32,
    slot_rva: u32,
    module_hash: u64,
    metadata: u64,
};

pub const Decoded = struct {
    records: []Record,
    module_runs: usize,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        allocator.free(self.records);
        self.* = undefined;
    }
};

pub const DecodeError = error{
    InvalidPe,
    InvalidTable,
    RecipeNotFound,
    OutOfMemory,
};

const Slot = struct {
    rva: u32,
    ordinal: u32,
};

const Table = struct {
    slots: []Slot,
    groups: usize,

    fn deinit(self: *Table, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        self.* = undefined;
    }
};

fn rd16(address: usize) u16 {
    return @as(*align(1) const u16, @ptrFromInt(address)).*;
}

fn rd32(address: usize) u32 {
    return @as(*align(1) const u32, @ptrFromInt(address)).*;
}

fn rd64(address: usize) u64 {
    return @as(*align(1) const u64, @ptrFromInt(address)).*;
}

fn isOrdinal(value: u64) bool {
    return value & import_ordinal_flag != 0 and
        value & ~import_ordinal_flag <= 0xffff;
}

fn isRecordPointer(value: u64, section_rva: u32, section_size: u32) bool {
    return value >= section_rva and
        value < @as(u64, section_rva) + section_size;
}

fn tableShape(
    allocator: std.mem.Allocator,
    base: usize,
    section_rva: u32,
    section_size: u32,
    table_end_rva: u32,
    expected_records: usize,
) DecodeError!Table {
    if (table_end_rva <= section_rva or
        table_end_rva > @as(u64, section_rva) + section_size or
        (table_end_rva - section_rva) & 7 != 0 or
        expected_records == 0) return error.InvalidTable;

    const slots = allocator.alloc(Slot, expected_records) catch return error.OutOfMemory;
    errdefer allocator.free(slots);

    const table_slots = @as(usize, table_end_rva - section_rva) / 8;
    var count: usize = 0;
    var separators: usize = 0;
    for (0..table_slots) |slot| {
        const value = rd64(base + section_rva + slot * 8);
        if (value == 0) {
            separators += 1;
            continue;
        }
        if (count >= expected_records) return error.InvalidTable;
        if (isOrdinal(value)) {
            slots[count].ordinal = @intCast(value & 0xffff);
        } else if (isRecordPointer(value, section_rva, section_size)) {
            slots[count].ordinal = 0;
        } else return error.InvalidTable;
        slots[count].rva = section_rva + @as(u32, @intCast(slot * 8));
        count += 1;
    }
    if (count != expected_records) return error.InvalidTable;
    return .{ .slots = slots, .groups = separators + 1 };
}

fn logicalWord(output: []const u8, recipe_offset: usize, index: usize) u32 {
    const block_offset = recipe_offset + index / decoder.lane_count * decoder.block_size;
    const block: *const [decoder.block_size]u8 = @ptrCast(output[block_offset..][0..decoder.block_size]);
    return decoder.decodeLane(block, @intCast(index & (decoder.lane_count - 1)));
}

fn recordAt(output: []const u8, recipe_offset: usize, word_index: usize) Record {
    const w0 = logicalWord(output, recipe_offset, word_index + 0);
    const w1 = logicalWord(output, recipe_offset, word_index + 1);
    const w2 = logicalWord(output, recipe_offset, word_index + 2);
    const w3 = logicalWord(output, recipe_offset, word_index + 3);
    const w4 = logicalWord(output, recipe_offset, word_index + 4);
    const w5 = logicalWord(output, recipe_offset, word_index + 5);
    const w6 = logicalWord(output, recipe_offset, word_index + 6);
    const w7 = logicalWord(output, recipe_offset, word_index + 7);
    return .{
        .name_hash = @as(u64, w0) | @as(u64, w1) << 32,
        .ordinal = w2,
        .slot_rva = w3,
        .module_hash = @as(u64, w4) | @as(u64, w5) << 32,
        .metadata = @as(u64, w6) | @as(u64, w7) << 32,
    };
}

fn decodeAt(
    allocator: std.mem.Allocator,
    output: []const u8,
    recipe_offset: usize,
    table: Table,
) DecodeError!?Decoded {
    if (recipe_offset + decoder.block_size > output.len) return null;

    var header_dwords: ?usize = null;
    var header: usize = 1;
    while (header < decoder.lane_count) : (header += 1) {
        if (header > table.slots.len) break;
        const first_record_blocks = (header + fields_per_record + decoder.lane_count - 1) / decoder.lane_count;
        if (recipe_offset + first_record_blocks * decoder.block_size > output.len) continue;
        var matches = true;
        for (0..header) |index| {
            if (logicalWord(output, recipe_offset, index) !=
                table.slots[table.slots.len - header + index].rva)
            {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        const first = recordAt(output, recipe_offset, header);
        if (first.slot_rva == table.slots[0].rva and
            first.ordinal == table.slots[0].ordinal)
        {
            header_dwords = header;
            break;
        }
    }
    if (header_dwords == null) {
        const prefix_words: usize = 5;
        const full_header = prefix_words + table.slots.len;
        const first_record_blocks = (full_header + fields_per_record + decoder.lane_count - 1) / decoder.lane_count;
        if (recipe_offset + first_record_blocks * decoder.block_size > output.len or
            logicalWord(output, recipe_offset, prefix_words - 1) != table.slots.len) return null;
        for (table.slots, 0..) |slot, index| {
            if (logicalWord(output, recipe_offset, prefix_words + index) != slot.rva) return null;
        }
        const first = recordAt(output, recipe_offset, full_header);
        if (first.slot_rva != table.slots[0].rva or first.ordinal != table.slots[0].ordinal) return null;
        header_dwords = full_header;
    }
    const header_count = header_dwords orelse return null;
    const word_count = std.math.add(
        usize,
        header_count,
        std.math.mul(usize, table.slots.len, fields_per_record) catch return null,
    ) catch return null;
    const block_count = (word_count + decoder.lane_count - 1) / decoder.lane_count;
    const byte_count = std.math.mul(usize, block_count, decoder.block_size) catch return null;
    if (recipe_offset + byte_count > output.len) return null;

    const records = allocator.alloc(Record, table.slots.len) catch return error.OutOfMemory;
    var records_owned = true;
    defer if (records_owned) allocator.free(records);
    var module_runs: usize = 0;
    var prior_module: u64 = 0;
    var prior_metadata: u64 = 0;
    for (records, 0..) |*record, index| {
        record.* = recordAt(
            output,
            recipe_offset,
            header_count + index * fields_per_record,
        );
        if (record.slot_rva != table.slots[index].rva or
            record.ordinal != table.slots[index].ordinal) return null;

        if (index == 0 or record.module_hash != prior_module or
            record.metadata != prior_metadata)
        {
            if (index != 0) {
                const expected_low = @as(u32, @truncate(prior_metadata)) +%
                    2 *% @as(u32, @truncate(prior_metadata >> 32));
                if (expected_low != @as(u32, @truncate(record.metadata))) return null;
            }
            module_runs += 1;
            prior_module = record.module_hash;
            prior_metadata = record.metadata;
        }
    }
    if (module_runs != table.groups) return null;
    records_owned = false;
    return .{
        .records = records,
        .module_runs = module_runs,
    };
}

fn decodeCandidate(
    allocator: std.mem.Allocator,
    wrapper: []const u8,
    table: Table,
) DecodeError!?Decoded {
    const output = compression.decode(allocator, wrapper, output_limit) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return null;
    };
    defer allocator.free(output);
    if (output.len < decoder.block_size) return null;
    var offset: usize = 0;
    while (offset + decoder.block_size <= output.len) : (offset += decoder.block_size) {
        if (try decodeAt(allocator, output, offset, table)) |decoded| {
            return decoded;
        }
    }
    return null;
}

pub fn decode(
    allocator: std.mem.Allocator,
    base: usize,
    import_section_rva: u32,
    import_section_size: u32,
    table_end_rva: u32,
    expected_records: usize,
) DecodeError!Decoded {
    if (rd16(base) != 0x5a4d) return error.InvalidPe;
    const pe = base + rd32(base + 0x3c);
    if (rd32(pe) != 0x00004550 or rd16(pe + 0x18) != 0x20b) return error.InvalidPe;
    const image_size = rd32(pe + 0x50);
    const entry_rva = rd32(pe + 0x28);
    const section_count = rd16(pe + 6);
    if (section_count == 0 or section_count > max_sections) return error.InvalidPe;
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + rd16(pe + 0x14));

    var entry_section_rva: u32 = 0;
    var entry_section_size: u32 = 0;
    for (sections[0..section_count]) |section| {
        const rva = section.virtual_address;
        if (rva >= image_size) continue;
        const size = @min(section.virtual_size, image_size - rva);
        if (entry_rva >= rva and entry_rva < @as(u64, rva) + size) {
            if (entry_section_size != 0) return error.InvalidPe;
            entry_section_rva = rva;
            entry_section_size = size;
        }
    }
    if (entry_section_size < wrapper_size + 5) return error.InvalidPe;

    var table = try tableShape(
        allocator,
        base,
        import_section_rva,
        import_section_size,
        table_end_rva,
        expected_records,
    );
    defer table.deinit(allocator);

    const section: []const u8 = @as(
        [*]const u8,
        @ptrFromInt(base + entry_section_rva),
    )[0..entry_section_size];
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, section, cursor, wrapper_magic)) |candidate| {
        cursor = candidate + 1;
        if (candidate == 0 or candidate + wrapper_size + 4 > section.len) continue;
        if (try decodeCandidate(
            allocator,
            section[candidate - 1 ..],
            table,
        )) |decoded| return decoded;
    }
    return error.RecipeNotFound;
}

test "suffix and full slot headers across recipe blocks" {
    const Encoder = struct {
        fn put(output: []u8, index: usize, value: u32) void {
            const start = index / decoder.lane_count * decoder.block_size;
            const block: *[decoder.block_size]u8 = @ptrCast(output[start..][0..decoder.block_size]);
            const lane: u6 = @intCast(index % decoder.lane_count);
            const original = decoder.decodeLane(block, lane);
            var offset: usize = 0;
            while (offset < decoder.block_size) : (offset += 4) {
                const word = block[offset..][0..4];
                const saved = std.mem.readInt(u32, word, .little);
                std.mem.writeInt(u32, word, saved ^ 1, .little);
                const changed = decoder.decodeLane(block, lane) != original;
                std.mem.writeInt(u32, word, saved, .little);
                if (changed) break;
            }
            const word = block[offset..][0..4];
            std.mem.writeInt(u32, word, 0, .little);
            // xor and wrapping addition preserve dependence on lower bits
            for (0..32) |bit| {
                const mask = @as(u32, 1) << @as(u5, @intCast(bit));
                if ((decoder.decodeLane(block, lane) ^ value) & mask != 0) {
                    std.mem.writeInt(u32, word, std.mem.readInt(u32, word, .little) ^ mask, .little);
                }
            }
        }
    };
    var slots: [74]Slot = undefined;
    for (&slots, 0..) |*slot, index| slot.* = .{
        .rva = 0x1000 + @as(u32, @intCast(index * 8)),
        .ordinal = if (index == slots.len - 1) 1 else 0,
    };
    const table: Table = .{ .slots = &slots, .groups = 1 };
    for ([_]usize{ 37, 5 + slots.len }) |header| {
        var output: [11 * decoder.block_size]u8 = @splat(0);
        if (header < decoder.lane_count) {
            for (0..header) |index| Encoder.put(&output, index, slots[slots.len - header + index].rva);
        } else {
            for (0..4) |index| Encoder.put(&output, index, 0xaabbccdd);
            Encoder.put(&output, 4, slots.len);
            for (slots, 0..) |slot, index| Encoder.put(&output, 5 + index, slot.rva);
        }
        for (slots, 0..) |slot, index| {
            const record_words = [_]u32{ @intCast(index + 1), 0, slot.ordinal, slot.rva, 11, 0, 77, 14 };
            for (record_words, 0..) |word, field| Encoder.put(&output, header + index * fields_per_record + field, word);
        }
        var decoded = (try decodeAt(std.testing.allocator, &output, 0, table)).?;
        defer decoded.deinit(std.testing.allocator);
        try std.testing.expectEqual(slots.len, decoded.records.len);
        for (decoded.records, slots, 0..) |record, slot, index| {
            try std.testing.expectEqual(@as(u64, index + 1), record.name_hash);
            try std.testing.expectEqual(slot.rva, record.slot_rva);
            try std.testing.expectEqual(slot.ordinal, record.ordinal);
        }
        if (header >= decoder.lane_count) {
            Encoder.put(&output, 4, slots.len - 1);
            try std.testing.expectEqual(@as(?Decoded, null), try decodeAt(std.testing.allocator, &output, 0, table));
        }
    }
}
