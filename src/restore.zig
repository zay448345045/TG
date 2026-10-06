// protected PE restore

const std = @import("std");
const coff = std.coff;
const hooks = @import("hooks.zig");
const recipe = @import("recipe.zig");
const compression = @import("compression.zig");

const BOOL = i32;
const DWORD = u32;
const HANDLE = ?*anyopaque;
const HMODULE = ?*anyopaque;

extern "kernel32" fn GetModuleHandleW(name: ?[*:0]const u16) callconv(.winapi) HMODULE;
extern "kernel32" fn GetModuleFileNameW(module: HMODULE, name: [*]u16, size: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn GetSystemDirectoryW(name: [*]u16, size: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn LoadLibraryW(name: [*:0]const u16) callconv(.winapi) HMODULE;
extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: HANDLE, flags: DWORD) callconv(.winapi) HMODULE;
extern "kernel32" fn FreeLibrary(module: HMODULE) callconv(.winapi) BOOL;
extern "kernel32" fn GetProcAddress(module: HMODULE, name: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FindFirstFileW(name: [*:0]const u16, data: *FindDataW) callconv(.winapi) HANDLE;
extern "kernel32" fn FindNextFileW(handle: HANDLE, data: *FindDataW) callconv(.winapi) BOOL;
extern "kernel32" fn FindClose(handle: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn VirtualProtect(address: ?*anyopaque, size: usize, new_protect: DWORD, old_protect: *DWORD) callconv(.winapi) BOOL;

const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const PAGE_READWRITE: DWORD = 0x04;
const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x10;
const DONT_RESOLVE_DLL_REFERENCES: DWORD = 0x00000001;
const INVALID_HANDLE_VALUE: usize = std.math.maxInt(usize);

const FindDataW = extern struct {
    attributes: DWORD,
    creation_time: std.os.windows.FILETIME,
    last_access_time: std.os.windows.FILETIME,
    last_write_time: std.os.windows.FILETIME,
    file_size_high: DWORD,
    file_size_low: DWORD,
    reserved0: DWORD,
    reserved1: DWORD,
    filename: [260]u16,
    alternate_filename: [14]u16,
};

const IMPORT_ORDINAL_FLAG: u64 = @as(u64, 1) << 63;
const IMPORT_INVALID_RUN_LIMIT: usize = 64;
const IMPORT_SCORE_SLOTS: usize = 2048;
const ProtectedCode = struct {
    rva: u32,
    virtual_size: u32,
};

const TextKey = struct {
    seed: u64,
    step: u64,
};

const ProtectedImports = struct {
    section_rva: u32,
    section_size: u32,
    table_end_rva: u32,
    pointer_slots: usize,
    ordinal_slots: usize,
};

const ModuleCache = struct {
    hash: u64,
    module: HMODULE,
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

// protected code
fn findProtectedCode(base: usize) ?ProtectedCode {
    if (rd16(base) != 0x5A4D) return null;
    const pe = base + rd32(base + 0x3C);
    if (rd32(pe) != 0x00004550) return null;
    const section_count = rd16(pe + 6);
    const optional_size = rd16(pe + 0x14);
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + optional_size);
    const optional = pe + 0x18;
    const image_size = rd32(optional + 0x38);
    const exception_rva = rd32(optional + 0x70 + 3 * 8);
    const exception_size = rd32(optional + 0x70 + 3 * 8 + 4);
    if (!rangeInImage(exception_rva, exception_size, image_size)) return null;

    var result: ?ProtectedCode = null;
    var most_functions: usize = 0;
    for (sections[0..section_count]) |section| {
        const virtual_size = section.virtual_size;
        const is_executable_code = section.flags.CNT_CODE and section.flags.MEM_EXECUTE;
        if (!is_executable_code) continue;
        var functions: usize = 0;
        for (0..exception_size / 12) |index| {
            const entry = base + exception_rva + index * 12;
            const begin = rd32(entry);
            const end = rd32(entry + 4);
            if (begin >= section.virtual_address and begin < end and
                @as(u64, end) <= @as(u64, section.virtual_address) + virtual_size) functions += 1;
        }
        if (functions > most_functions) {
            most_functions = functions;
            result = .{
                .rva = section.virtual_address,
                .virtual_size = virtual_size,
            };
        }
    }
    return result;
}

fn textKeyFromPadding(base: usize, code: ProtectedCode, padding_rva: u32, byte: u8) ?TextKey {
    const word_index = @as(u64, padding_rva - code.rva) / 8;
    if ((word_index & 511) > 510) return null;

    const padding = @as(u64, byte) * 0x0101010101010101;
    const first = rd64(base + padding_rva) ^ padding;
    const second = rd64(base + padding_rva + 8) ^ padding;
    const step = second -% first;
    return .{
        .seed = first -% (step *% ((word_index & 511) + 4096 * (word_index >> 9))),
        .step = step,
    };
}

test "recover text key across cipher blocks" {
    const seed: u64 = 0x46173b4ae4ee35ce;
    const step: u64 = 0x4f6007dcdf78975a;
    const code_rva: u32 = 16;
    const padding_rva: u32 = code_rva + 512 * 8;
    var image: [padding_rva + 24]u8 = @splat(0);
    for (0..3) |index| {
        const pad = seed +% (step *% (4096 + @as(u64, index)));
        std.mem.writeInt(u64, image[padding_rva + index * 8 ..][0..8], pad ^ 0xcccccccccccccccc, .little);
    }

    const key = textKeyFromPadding(
        @intFromPtr(&image),
        .{ .rva = code_rva, .virtual_size = 512 * 8 + 24 },
        padding_rva,
        0xcc,
    ).?;
    try std.testing.expectEqual(seed, key.seed);
    try std.testing.expectEqual(step, key.step);
}

test "two padding words at the end of a cipher block" {
    const seed: u64 = 0x46173b4ae4ee35ce;
    const step: u64 = 0x4f6007dcdf78975a;
    const padding_rva: u32 = 510 * 8;
    var image: [512 * 8]u8 = @splat(0);
    for (0..2) |index| {
        std.mem.writeInt(u64, image[padding_rva + index * 8 ..][0..8],
            (seed +% step *% (510 + index)) ^ 0xcccccccccccccccc, .little);
    }
    const key = textKeyFromPadding(@intFromPtr(&image), .{ .rva = 0, .virtual_size = image.len }, padding_rva, 0xcc).?;
    try std.testing.expectEqual(seed, key.seed);
    try std.testing.expectEqual(step, key.step);
}

test "protected code uses unwind coverage and short padding inside gaps" {
    var image: [0x9000]u8 = @splat(0);
    std.mem.writeInt(u16, image[0..2], 0x5a4d, .little);
    std.mem.writeInt(u32, image[0x3c..0x40], 0x80, .little);
    std.mem.writeInt(u32, image[0x80..0x84], 0x4550, .little);
    std.mem.writeInt(u16, image[0x86..0x88], 2, .little);
    std.mem.writeInt(u16, image[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u32, image[0xd0..0xd4], image.len, .little);
    std.mem.writeInt(u32, image[0x120..0x124], 0x8000, .little);
    std.mem.writeInt(u32, image[0x124..0x128], 36, .little);
    const sections: *align(1) [2]coff.SectionHeader = @ptrCast(image[0x188..][0..80]);
    sections[0].virtual_address = 0x1000;
    sections[0].virtual_size = 0x2000;
    sections[0].flags.CNT_CODE = true;
    sections[0].flags.MEM_EXECUTE = true;
    sections[1].virtual_address = 0x4000;
    sections[1].virtual_size = 0x4000;
    sections[1].flags.CNT_CODE = true;
    sections[1].flags.MEM_EXECUTE = true;
    for ([_][2]u32{ .{ 0x1000, 0x1018 }, .{ 0x1040, 0x1060 }, .{ 0x2030, 0x2040 } }, 0..) |entry, index| {
        std.mem.writeInt(u32, image[0x8000 + index * 12 ..][0..4], entry[0], .little);
        std.mem.writeInt(u32, image[0x8004 + index * 12 ..][0..4], entry[1], .little);
    }
    var random: std.Random.DefaultPrng = .init(0);
    random.random().bytes(image[0x1000..0x3000]);
    @memset(image[0x1028..0x1038], 0xcc);
    @memset(image[0x2018..0x2028], 0xcc);
    const seed: u64 = 0x46173b4ae4ee35ce;
    const step: u64 = 0x4f6007dcdf78975a;
    for (0..0x2000 / 8) |index| {
        const word = image[0x1000 + index * 8 ..][0..8];
        const pad = seed +% step *% ((index & 511) + 4096 * (index >> 9));
        std.mem.writeInt(u64, word, std.mem.readInt(u64, word, .little) ^ pad, .little);
    }
    const code = findProtectedCode(@intFromPtr(&image)).?;
    try std.testing.expectEqual(@as(u32, 0x1000), code.rva);
    const key = findTextKey(@intFromPtr(&image), code).?;
    try std.testing.expectEqual(seed, key.seed);
    try std.testing.expectEqual(step, key.step);
}

fn scanTextKey(base: usize, code: ProtectedCode, corroborate_word: bool) ?TextKey {
    const pe = base + rd32(base + 0x3c);
    const optional = pe + 0x18;
    const image_size = rd32(optional + 0x38);
    const exception_rva = rd32(optional + 0x70 + 3 * 8);
    const exception_size = rd32(optional + 0x70 + 3 * 8 + 4);
    if (!rangeInImage(exception_rva, exception_size, image_size)) return null;

    var previous_end: ?u32 = null;
    var candidates: std.AutoHashMap(TextKey, void) = .init(std.heap.page_allocator);
    defer candidates.deinit();
    for (0..exception_size / 12) |index| {
        const entry = base + exception_rva + index * 12;
        const begin = rd32(entry);
        const end = rd32(entry + 4);
        if (begin < code.rva or begin >= end or
            @as(u64, end) > @as(u64, code.rva) + code.virtual_size) continue;

        if (previous_end) |last_end| {
            var padding_rva = (last_end + 7) & ~@as(u32, 7);
            const sample_size: u32 = if (corroborate_word) 24 else 16;
            while (@as(u64, padding_rva) + sample_size <= begin) : (padding_rva += 8) {
                for ([_]u8{ 0xcc, 0x90, 0 }) |byte| {
                    const key = textKeyFromPadding(base, code, padding_rva, byte) orelse continue;
                    if (corroborate_word) {
                        const pad = @as(u64, byte) * 0x0101010101010101;
                        const first = rd64(base + padding_rva) ^ pad;
                        if (rd64(base + padding_rva + 16) ^ pad != first +% key.step *% 2) continue;
                    }
                    const candidate = candidates.getOrPut(key) catch return null;
                    if (candidate.found_existing) return key;
                }
            }
        }
        previous_end = end;
    }
    return null;
}

fn findTextKey(base: usize, code: ProtectedCode) ?TextKey {
    return scanTextKey(base, code, true) orelse scanTextKey(base, code, false);
}

fn decryptText(base: usize, code: ProtectedCode, preserved_address: usize, preserved_size: usize) bool {
    const key = findTextKey(base, code) orelse return false;
    const text = base + code.rva;
    const e_step = key.step *% 4096;
    var old_protect: DWORD = 0;
    if (VirtualProtect(@ptrFromInt(text), code.virtual_size, PAGE_EXECUTE_READWRITE, &old_protect) == 0) return false;

    const bytes: [*]u8 = @ptrFromInt(text);
    const full_qwords: usize = code.virtual_size / 8;
    var qword_index: usize = 0;
    var block_pad = key.seed;
    while (qword_index < full_qwords) {
        const block_end = @min(qword_index + 512, full_qwords);
        var pad = block_pad;
        while (qword_index < block_end) : (qword_index += 1) {
            const offset = qword_index * 8;
            const word_address = text + offset;
            if (word_address + 8 <= preserved_address or
                word_address >= preserved_address + preserved_size)
            {
                const word: *align(1) u64 = @ptrCast(bytes + offset);
                word.* ^= pad;
            } else {
                for (0..8) |byte_index| {
                    const address = word_address + byte_index;
                    if (address < preserved_address or address >= preserved_address + preserved_size) {
                        bytes[offset + byte_index] ^= @truncate(pad >> @intCast(byte_index * 8));
                    }
                }
            }
            pad +%= key.step;
        }
        block_pad +%= e_step;
    }

    const remainder: usize = code.virtual_size & 7;
    if (remainder != 0) {
        const b: u64 = full_qwords;
        const pad = key.seed +% (e_step *% (b >> 9)) +% (key.step *% (b & 511));
        var i: usize = 0;
        while (i < remainder) : (i += 1) {
            const offset = full_qwords * 8 + i;
            const address = text + offset;
            if (address < preserved_address or address >= preserved_address + preserved_size) {
                bytes[offset] ^= @truncate(pad >> @intCast(i * 8));
            }
        }
    }

    var ignored: DWORD = 0;
    _ = VirtualProtect(@ptrFromInt(text), code.virtual_size, old_protect, &ignored);
    return true;
}

// compressed sections
fn decompressSection(base: usize, rva: u32, raw_size: u32, virtual_size: u32, file_alignment: u32) bool {
    const source: []const u8 = @as([*]const u8, @ptrFromInt(base + rva))[0..raw_size];
    const allocator = std.heap.page_allocator;
    const limit = std.mem.alignForward(usize, virtual_size, file_alignment);
    const output = compression.decode(allocator, source, limit) catch return false;
    defer allocator.free(output);
    const destination = base + rva;
    const restored_size = @max(output.len, virtual_size);
    var old_protect: DWORD = 0;
    if (VirtualProtect(@ptrFromInt(destination), restored_size, PAGE_EXECUTE_READWRITE, &old_protect) == 0) return false;
    const bytes = @as([*]u8, @ptrFromInt(destination))[0..restored_size];
    @memcpy(bytes[0..output.len], output);
    @memset(bytes[output.len..], 0);
    var ignored: DWORD = 0;
    _ = VirtualProtect(@ptrFromInt(destination), restored_size, old_protect, &ignored);
    return true;
}

fn restoreSections(base: usize) bool {
    const pe = base + rd32(base + 0x3C);
    const section_count = rd16(pe + 6);
    const optional_size = rd16(pe + 0x14);
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + optional_size);

    const file_alignment = rd32(pe + 0x3c);

    for (sections[0..section_count]) |section| {
        const virtual_size = section.virtual_size;
        const rva = section.virtual_address;
        const raw_size = section.size_of_raw_data;
        if (raw_size < compression.header_size or rd32(base + rva) != 0x575757f8) continue;
        if (!decompressSection(base, rva, raw_size, virtual_size, file_alignment)) return false;
    }
    return true;
}

// protected imports
fn isImportOrdinal(value: u64) bool {
    return value & IMPORT_ORDINAL_FLAG != 0 and value & ~IMPORT_ORDINAL_FLAG <= 0xFFFF;
}

fn isImportRecordPointer(value: u64, section_rva: u32, section_size: u32) bool {
    const section_end = @as(u64, section_rva) + section_size;
    return value >= section_rva and value < section_end;
}

fn importSectionScore(base: usize, section_rva: u32, section_size: u32) usize {
    const slot_count = @min(@as(usize, section_size) / 8, IMPORT_SCORE_SLOTS);
    var score: usize = 0;
    var slot: usize = 0;
    while (slot < slot_count) : (slot += 1) {
        const value = rd64(base + section_rva + slot * 8);
        if (isImportRecordPointer(value, section_rva, section_size) or isImportOrdinal(value)) {
            score += 1;
        }
    }
    return score;
}

fn findProtectedImports(base: usize) ?ProtectedImports {
    const pe = base + rd32(base + 0x3C);
    const image_size = rd32(pe + 0x50);
    const section_count = rd16(pe + 6);
    const optional_size = rd16(pe + 0x14);
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + optional_size);

    var best_rva: u32 = 0;
    var best_size: u32 = 0;
    var best_score: usize = 0;
    for (sections[0..section_count]) |section| {
        const rva = section.virtual_address;
        if (rva >= image_size) continue;
        const virtual_size = section.virtual_size;
        const raw_size = section.size_of_raw_data;
        const declared_size = @max(virtual_size, raw_size);
        const size = @min(declared_size, image_size - rva);
        if (size < 32 * 8) continue;
        const score = importSectionScore(base, rva, size);
        if (score > best_score) {
            best_rva = rva;
            best_size = size;
            best_score = score;
        }
    }
    if (best_score < 32) return null;

    var pointer_slots: usize = 0;
    var ordinal_slots: usize = 0;
    var invalid_run: usize = 0;
    var table_slots: usize = 0;
    const slot_count = @as(usize, best_size) / 8;
    var slot: usize = 0;
    while (slot < slot_count) : (slot += 1) {
        const value = rd64(base + best_rva + slot * 8);
        const is_pointer = isImportRecordPointer(value, best_rva, best_size);
        const is_ordinal = isImportOrdinal(value);
        if (is_pointer) {
            pointer_slots += 1;
        } else if (is_ordinal) {
            ordinal_slots += 1;
        }

        if (is_pointer or is_ordinal) {
            invalid_run = 0;
            table_slots = slot + 1;
        } else {
            invalid_run += 1;
            if (pointer_slots >= 32 and invalid_run >= IMPORT_INVALID_RUN_LIMIT) break;
        }
    }
    if (pointer_slots < 32) return null;

    return .{
        .section_rva = best_rva,
        .section_size = best_size,
        .table_end_rva = best_rva + @as(u32, @intCast(table_slots * 8)),
        .pointer_slots = pointer_slots,
        .ordinal_slots = ordinal_slots,
    };
}

// import lookup
fn combinedHashAscii(name: []const u8) u64 {
    var fnv: u32 = 0x811c9dc5;
    var polynomial: u32 = 0;
    for (name) |byte| {
        fnv = fnv *% 0x01000193 ^ byte;
        polynomial = polynomial *% 131 +% byte;
    }
    return @as(u64, fnv) << 32 | polynomial;
}

fn combinedHashWideLower(name: []const u16) ?u64 {
    var fnv: u32 = 0x811c9dc5;
    var polynomial: u32 = 0;
    for (name) |unit| {
        if (unit > 0x7f) return null;
        const byte = std.ascii.toLower(@intCast(unit));
        fnv = fnv *% 0x01000193 ^ byte;
        polynomial = polynomial *% 131 +% byte;
    }
    return @as(u64, fnv) << 32 | polynomial;
}

fn findModuleInDirectory(
    directory: []const u16,
    wanted_hash: u64,
    expected_name_length: usize,
) HMODULE {
    var pattern: [4096]u16 = undefined;
    if (directory.len + 3 > pattern.len) return null;
    @memcpy(pattern[0..directory.len], directory);
    pattern[directory.len] = '\\';
    pattern[directory.len + 1] = '*';
    pattern[directory.len + 2] = 0;

    var data: FindDataW = undefined;
    const search = FindFirstFileW(@ptrCast(&pattern), &data);
    if (@intFromPtr(search) == 0 or @intFromPtr(search) == INVALID_HANDLE_VALUE) return null;
    defer _ = FindClose(search);

    while (true) {
        if (data.attributes & FILE_ATTRIBUTE_DIRECTORY == 0) {
            const length = std.mem.indexOfScalar(u16, &data.filename, 0) orelse data.filename.len;
            const filename = data.filename[0..length];
            if ((expected_name_length == 0 or length == expected_name_length) and
                combinedHashWideLower(filename) == wanted_hash)
            {
                var full_path: [4096]u16 = undefined;
                if (directory.len + 1 + filename.len + 1 > full_path.len) return null;
                @memcpy(full_path[0..directory.len], directory);
                full_path[directory.len] = '\\';
                @memcpy(full_path[directory.len + 1 ..][0..filename.len], filename);
                full_path[directory.len + 1 + filename.len] = 0;
                return LoadLibraryW(@ptrCast(&full_path));
            }
        }
        if (FindNextFileW(search, &data) == 0) break;
    }
    return null;
}

fn namespaceRange(offset: u32, length: usize, namespace_size: u32) bool {
    return offset <= namespace_size and length <= @as(usize, namespace_size - offset);
}

fn loadApiSetHost(namespace: usize, namespace_size: u32, value_offset: u32, value_count: u32) HMODULE {
    if (value_count == 0 or value_count > 256 or
        !namespaceRange(value_offset, @as(usize, value_count) * 20, namespace_size)) return null;
    var selected: ?usize = null;
    for (0..value_count) |index| {
        const value = namespace + value_offset + index * 20;
        const alias_length = rd32(value + 8);
        if (selected == null or alias_length == 0) selected = value;
        if (alias_length == 0) break;
    }
    const value = selected orelse return null;
    const host_offset = rd32(value + 12);
    const host_bytes = rd32(value + 16);
    if (host_bytes == 0 or host_bytes & 1 != 0 or
        !namespaceRange(host_offset, host_bytes, namespace_size)) return null;
    const host_length = @as(usize, host_bytes) / 2;
    if (host_length + 1 > 260) return null;
    var host: [260]u16 = undefined;
    const source: [*]const u16 = @ptrFromInt(namespace + host_offset);
    @memcpy(host[0..host_length], source[0..host_length]);
    host[host_length] = 0;
    return LoadLibraryW(@ptrCast(&host));
}

const ApiSetLookup = struct {
    matched: bool = false,
    module: HMODULE = null,
};

fn findApiSetPass(
    namespace: usize,
    namespace_size: u32,
    count: u32,
    entries_offset: u32,
    wanted_hash: u64,
    expected_name_length: usize,
    siblings: bool,
) ApiSetLookup {
    var candidate: [128]u16 = undefined;
    for (0..count) |index| {
        const entry = namespace + entries_offset + index * 24;
        const name_offset = rd32(entry + 4);
        const name_bytes = rd32(entry + 8);
        const value_offset = rd32(entry + 16);
        const value_count = rd32(entry + 20);
        if (name_bytes == 0 or name_bytes & 1 != 0 or
            !namespaceRange(name_offset, name_bytes, namespace_size)) continue;
        const name_length = @as(usize, name_bytes) / 2;
        const dll_length = name_length + 4;
        if (dll_length > candidate.len or
            (expected_name_length != 0 and dll_length != expected_name_length)) continue;
        const name: [*]const u16 = @ptrFromInt(namespace + name_offset);
        @memcpy(candidate[0..name_length], name[0..name_length]);
        candidate[name_length..][0..4].* = .{ '.', 'd', 'l', 'l' };

        if (!siblings) {
            if (combinedHashWideLower(candidate[0..dll_length]) == wanted_hash) {
                return .{
                    .matched = true,
                    .module = loadApiSetHost(namespace, namespace_size, value_offset, value_count),
                };
            }
            continue;
        }

        for (0..name_length) |character_index| {
            const original = candidate[character_index];
            if (original < '0' or original > '9') continue;
            var digit: u16 = '0';
            while (digit <= '9') : (digit += 1) {
                if (digit == original) continue;
                candidate[character_index] = digit;
                if (combinedHashWideLower(candidate[0..dll_length]) == wanted_hash) {
                    return .{
                        .matched = true,
                        .module = loadApiSetHost(namespace, namespace_size, value_offset, value_count),
                    };
                }
            }
            candidate[character_index] = original;
        }
    }
    return .{};
}

fn findApiSetModule(wanted_hash: u64, expected_name_length: usize) HMODULE {
    const schema = LoadLibraryExW(
        std.unicode.utf8ToUtf16LeStringLiteral("apisetschema.dll"),
        null,
        DONT_RESOLVE_DLL_REFERENCES,
    ) orelse return null;
    defer _ = FreeLibrary(schema);
    const base = @intFromPtr(schema);
    if (rd16(base) != 0x5a4d) return null;
    const pe = base + rd32(base + 0x3c);
    if (rd32(pe) != 0x00004550) return null;
    const section_count = rd16(pe + 6);
    const sections: [*]align(1) const coff.SectionHeader = @ptrFromInt(pe + 0x18 + rd16(pe + 0x14));
    var namespace: usize = 0;
    var section_size: u32 = 0;
    for (sections[0..section_count]) |section| {
        if (std.mem.eql(u8, section.name[0..7], ".apiset")) {
            namespace = base + section.virtual_address;
            section_size = section.virtual_size;
            break;
        }
    }
    if (namespace == 0 or section_size < 28 or rd32(namespace) < 6) return null;
    const namespace_size = rd32(namespace + 4);
    const count = rd32(namespace + 12);
    const entries_offset = rd32(namespace + 16);
    if (namespace_size > section_size or count == 0 or count > 4096 or
        !namespaceRange(entries_offset, @as(usize, count) * 24, namespace_size)) return null;

    const exact = findApiSetPass(
        namespace,
        namespace_size,
        count,
        entries_offset,
        wanted_hash,
        expected_name_length,
        false,
    );
    if (exact.matched) return exact.module;
    return findApiSetPass(
        namespace,
        namespace_size,
        count,
        entries_offset,
        wanted_hash,
        expected_name_length,
        true,
    ).module;
}

fn findModule(wanted_hash: u64, expected_name_length: usize) HMODULE {
    if (findApiSetModule(wanted_hash, expected_name_length)) |module| return module;

    var game_path: [4096]u16 = undefined;
    const game_length = GetModuleFileNameW(null, &game_path, @intCast(game_path.len));
    if (game_length != 0 and game_length < game_path.len) {
        if (std.mem.lastIndexOfAny(u16, game_path[0..game_length], &.{ '\\', '/' })) |slash| {
            if (findModuleInDirectory(game_path[0..slash], wanted_hash, expected_name_length)) |module| {
                return module;
            }
        }
    }

    var system_path: [4096]u16 = undefined;
    const system_length = GetSystemDirectoryW(&system_path, @intCast(system_path.len));
    if (system_length != 0 and system_length < system_path.len) {
        if (findModuleInDirectory(system_path[0..system_length], wanted_hash, expected_name_length)) |module| {
            return module;
        }
    }
    return null;
}

fn iosbAssignIdentity(self: ?*anyopaque, other: ?*anyopaque) callconv(.winapi) ?*anyopaque {
    // MSVC's std::_Iosb<int> has no instance state to move.
    _ = other;
    return self;
}

fn rangeInImage(rva: u32, size: usize, image_size: u32) bool {
    return rva < image_size and size <= @as(usize, image_size - rva);
}

fn resolveNamed(module: HMODULE, wanted_hash: u64) ?*anyopaque {
    if (wanted_hash == combinedHashAscii("LoadLibraryA")) return @ptrFromInt(@intFromPtr(&hooks.loadLibraryA));
    if (wanted_hash == combinedHashAscii("LoadLibraryW")) return @ptrFromInt(@intFromPtr(&hooks.loadLibraryW));
    if (wanted_hash == combinedHashAscii("LoadLibraryExA")) return @ptrFromInt(@intFromPtr(&hooks.loadLibraryExA));
    if (wanted_hash == combinedHashAscii("LoadLibraryExW")) return @ptrFromInt(@intFromPtr(&hooks.loadLibraryExW));
    if (wanted_hash == combinedHashAscii("GetProcAddress")) return @ptrFromInt(@intFromPtr(&hooks.getProcAddress));
    if (wanted_hash == combinedHashAscii("FreeLibrary")) return @ptrFromInt(@intFromPtr(&hooks.freeLibrary));
    if (wanted_hash == combinedHashAscii("??4?$_Iosb@H@std@@QEAAAEAV01@$$QEAV01@@Z")) {
        return @ptrFromInt(@intFromPtr(&iosbAssignIdentity));
    }
    if (wanted_hash == combinedHashAscii("NtdllDefWindowProc_A")) {
        const user32 = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("user32.dll")) orelse return null;
        return GetProcAddress(user32, "DefWindowProcA");
    }
    if (wanted_hash == combinedHashAscii("NtdllDefWindowProc_W")) {
        const user32 = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("user32.dll")) orelse return null;
        return GetProcAddress(user32, "DefWindowProcW");
    }
    if (wanted_hash == combinedHashAscii("RtlGetCurrentProcessorNumber")) {
        const ntdll = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("ntdll.dll")) orelse return null;
        return GetProcAddress(ntdll, "NtGetCurrentProcessorNumber");
    }

    const module_base = @intFromPtr(module);
    if (module_base == 0 or rd16(module_base) != 0x5a4d) return null;
    const pe = module_base + rd32(module_base + 0x3c);
    if (rd32(pe) != 0x00004550) return null;
    const optional = pe + 0x18;
    const magic = rd16(optional);
    const export_directory_offset: usize = if (magic == 0x20b) 0x70 else if (magic == 0x10b) 0x60 else return null;
    const image_size = rd32(optional + 0x38);
    const export_rva = rd32(optional + export_directory_offset);
    const export_size = rd32(optional + export_directory_offset + 4);
    if (!rangeInImage(export_rva, @max(@as(usize, export_size), 40), image_size)) return null;

    const exports = module_base + export_rva;
    const name_count = rd32(exports + 24);
    const names_rva = rd32(exports + 32);
    if (name_count > 1 << 20 or
        !rangeInImage(names_rva, @as(usize, name_count) * 4, image_size)) return null;
    for (0..name_count) |index| {
        const name_rva = rd32(module_base + names_rva + index * 4);
        if (!rangeInImage(name_rva, 1, image_size)) continue;
        const maximum = @min(@as(usize, image_size - name_rva), 4096);
        const bytes: [*]const u8 = @ptrFromInt(module_base + name_rva);
        const length = std.mem.indexOfScalar(u8, bytes[0..maximum], 0) orelse continue;
        if (combinedHashAscii(bytes[0..length]) != wanted_hash) continue;
        const name: [*:0]const u8 = @ptrCast(bytes);
        return GetProcAddress(module, name);
    }
    return null;
}

fn writeImport(base: usize, target_rva: u32, address: usize) bool {
    const target = base + target_rva;
    var old_protect: DWORD = 0;
    if (VirtualProtect(@ptrFromInt(target), @sizeOf(usize), PAGE_READWRITE, &old_protect) == 0) return false;
    @as(*align(1) usize, @ptrFromInt(target)).* = address;
    var ignored: DWORD = 0;
    _ = VirtualProtect(@ptrFromInt(target), @sizeOf(usize), old_protect, &ignored);
    return true;
}

// entry-point recovery
fn relativeTarget(next_rva: u32, displacement: i32) ?u32 {
    const result = @as(i64, next_rva) + displacement;
    if (result < 0 or result > std.math.maxInt(u32)) return null;
    return @intCast(result);
}

fn isCodeTarget(target: ?u32, code: ProtectedCode) bool {
    const rva = target orelse return false;
    return rva >= code.rva and rva < @as(u64, code.rva) + code.virtual_size;
}

fn findOriginalEntry(base: usize, code: ProtectedCode) ?u32 {
    const bytes: [*]const u8 = @ptrFromInt(base + code.rva);
    if (code.virtual_size < 20) return null;
    var offset = @as(usize, code.virtual_size) - 20;
    while (true) {
        const candidate = bytes[offset..][0..20];
        if (std.mem.eql(u8, candidate[0..5], "\x48\x83\xec\x28\xe8") and
            std.mem.eql(u8, candidate[9..14], "\x48\x83\xc4\x28\xe9") and
            candidate[18] == 0xcc and candidate[19] == 0xcc)
        {
            const candidate_rva = code.rva + @as(u32, @intCast(offset));
            const call_target = relativeTarget(
                candidate_rva + 9,
                std.mem.readInt(i32, candidate[5..9], .little),
            );
            const jump_target = relativeTarget(
                candidate_rva + 18,
                std.mem.readInt(i32, candidate[14..18], .little),
            );
            if (isCodeTarget(call_target, code) and isCodeTarget(jump_target, code)) {
                return candidate_rva;
            }
        }
        if (offset == 0) break;
        offset -= 1;
    }
    return null;
}

test "original entry uses the last valid candidate" {
    const code_rva: u32 = 16;
    const code_size: u32 = 96;
    const target_rva: u32 = code_rva + 40;
    var image: [code_rva + code_size]u8 = @splat(0);
    const code: ProtectedCode = .{ .rva = code_rva, .virtual_size = code_size };

    try std.testing.expectEqual(@as(?u32, null), findOriginalEntry(@intFromPtr(&image), code));

    for ([_]u32{ code_rva, code_rva + code_size - 20 }) |candidate_rva| {
        const candidate = image[candidate_rva..][0..20];
        @memcpy(candidate[0..5], "\x48\x83\xec\x28\xe8");
        std.mem.writeInt(i32, candidate[5..9], @as(i32, @intCast(target_rva)) - @as(i32, @intCast(candidate_rva + 9)), .little);
        @memcpy(candidate[9..14], "\x48\x83\xc4\x28\xe9");
        std.mem.writeInt(i32, candidate[14..18], @as(i32, @intCast(target_rva)) - @as(i32, @intCast(candidate_rva + 18)), .little);
        @memcpy(candidate[18..20], "\xcc\xcc");
    }
    try std.testing.expectEqual(code_rva + code_size - 20, findOriginalEntry(@intFromPtr(&image), code).?);

    const last = image[code_rva + code_size - 20 ..][0..20];
    std.mem.writeInt(i32, last[14..18], @as(i32, @intCast(code_rva + code_size)) - @as(i32, @intCast(code_rva + code_size - 2)), .little);
    try std.testing.expectEqual(code_rva, findOriginalEntry(@intFromPtr(&image), code).?);
}

fn restoreImports(base: usize, code: ProtectedCode) ?u32 {
    const layout = findProtectedImports(base) orelse return null;
    const allocator = std.heap.page_allocator;
    var decoded = recipe.decode(
        allocator,
        base,
        layout.section_rva,
        layout.section_size,
        layout.table_end_rva,
        layout.pointer_slots + layout.ordinal_slots,
    ) catch return null;
    defer decoded.deinit(allocator);

    const cache = allocator.alloc(ModuleCache, decoded.module_runs) catch return null;
    defer allocator.free(cache);
    var cache_count: usize = 0;

    for (decoded.records) |record| {
        var module: HMODULE = null;
        for (cache[0..cache_count]) |cached| {
            if (cached.hash == record.module_hash) {
                module = cached.module;
                break;
            }
        }
        if (module == null) {
            const encoded_length: u32 = @truncate(record.metadata >> 32);
            const expected_length: usize = if (encoded_length >= 2) encoded_length - 2 else 0;
            module = findModule(record.module_hash, expected_length);
            if (module == null) return null;
            cache[cache_count] = .{ .hash = record.module_hash, .module = module };
            cache_count += 1;
        }

        const address = if (record.ordinal != 0)
            GetProcAddress(module, @ptrFromInt(@as(usize, record.ordinal)))
        else
            resolveNamed(module, record.name_hash);
        const resolved = address orelse return null;
        if (!writeImport(base, record.slot_rva, @intFromPtr(resolved))) return null;
    }

    return findOriginalEntry(base, code);
}

pub fn protectedEntry() ?usize {
    const base = @intFromPtr(GetModuleHandleW(null));
    if (base == 0 or rd16(base) != 0x5A4D) return null;
    const pe = base + rd32(base + 0x3C);
    if (rd32(pe) != 0x00004550) return null;
    const entry_rva = rd32(pe + 0x28);
    return base + entry_rva;
}

pub fn disableTlsCallbacks() bool {
    const base = @intFromPtr(GetModuleHandleW(null));
    if (base == 0 or rd16(base) != 0x5A4D) return false;
    const pe = base + rd32(base + 0x3C);
    if (rd32(pe) != 0x00004550) return false;
    const optional = pe + 0x18;
    const tls_rva = rd32(optional + 112 + 9 * 8);
    if (tls_rva == 0) return true;
    const callbacks = rd64(base + tls_rva + 24);
    if (callbacks == 0) return true;

    var old_protect: DWORD = 0;
    if (VirtualProtect(@ptrFromInt(callbacks), @sizeOf(usize), PAGE_READWRITE, &old_protect) == 0) return false;
    @as(*align(1) usize, @ptrFromInt(callbacks)).* = 0;
    var ignored: DWORD = 0;
    _ = VirtualProtect(@ptrFromInt(callbacks), @sizeOf(usize), old_protect, &ignored);
    return true;
}

pub fn apply(self_module: HMODULE, preserved_address: usize, preserved_size: usize) ?usize {
    hooks.initialize(self_module);
    const base = @intFromPtr(GetModuleHandleW(null));
    if (base == 0) return null;

    const code = findProtectedCode(base) orelse return null;
    if (!decryptText(base, code, preserved_address, preserved_size)) return null;
    if (!restoreSections(base)) return null;

    const original_entry = restoreImports(base, code) orelse return null;
    if (!hooks.patchLoaded()) return null;
    return base + original_entry;
}
