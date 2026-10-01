// import recipe block decoder

const std = @import("std");

pub const block_size: usize = 0x400;
pub const lane_count: usize = 64;

fn read(block: *const [block_size]u8, offset: usize) u32 {
    return std.mem.readInt(u32, block[offset..][0..4], .little);
}

pub fn decodeLane(block: *const [block_size]u8, lane: u6) u32 {
    return switch (lane) {
        0 => (((read(block, 0x18c) ^ 0xd5c31f79) -% 0x0a9099e4) ^ 0xd091bb5c),
        1 => ((((read(block, 0x120) ^ 0xa1e24bba) +% 0x3895afe1) ^ 0xe9d30005) +% 0x07f84821),
        2 => ((((read(block, 0x0fc) -% 0x3039cd1a) ^ 0x474ba8c4) -% 0x73e959db) ^ 0x18f86863),
        3 => ((((read(block, 0x264) ^ 0xf702ef59) -% 0x00e7e91c) ^ 0xf51f2ae7) -% 0x01d287f0),
        4 => ((((read(block, 0x378) ^ 0xfb2a0137) -% 0x07873b4d) ^ 0xb9d09511) +% 0x285954a1),
        5 => ((((read(block, 0x1e0) ^ 0xccdf2e5c) -% 0x33af55a7) ^ 0x7c419418) -% 0x1c1fe652),
        6 => ((read(block, 0x354) -% 0x1cca797a) ^ 0x4e935860),
        7 => ((((read(block, 0x1b8) ^ 0xf5a14bab) +% 0x1f1f2b53) ^ 0xcace1969) +% 0x5c3877f9),
        8 => (((read(block, 0x22c) -% 0x5c7dc380) ^ 0xc5616a35) +% 0x582160b4),
        9 => ((read(block, 0x1f4) +% 0x523e69a5) ^ 0x77371607),
        10 => ((read(block, 0x0a8) -% 0x7989c8ee) ^ 0xc25da2f3),
        11 => ((read(block, 0x1c4) -% 0x2bd2e412) ^ 0xe742fb8d),
        12 => ((((read(block, 0x070) ^ 0x51097330) -% 0x08263282) ^ 0xcc1a8959) +% 0x4b409059),
        13 => ((((read(block, 0x0b8) ^ 0x18dda0c9) -% 0x262c5564) ^ 0x0bd1e364) -% 0x20a8813e),
        14 => ((((read(block, 0x224) ^ 0x200bfa47) -% 0x4e1fb61f) ^ 0xd268409a) +% 0x2d31de37),
        15 => ((((read(block, 0x334) ^ 0x08d17554) -% 0x7d973e48) ^ 0xf341c081) +% 0x3c7ae112),
        16 => ((((read(block, 0x3a4) ^ 0x35d0430c) +% 0x61add0ab) ^ 0x203ac303) +% 0x70518ce6),
        17 => ((((read(block, 0x32c) ^ 0x2fd6e208) -% 0x095436bf) ^ 0xcb92388e) +% 0x0d1c8509),
        18 => ((((read(block, 0x08c) -% 0x7cd15133) ^ 0x7211efea) +% 0x753ec6fc) ^ 0x7d61330b),
        19 => ((((read(block, 0x3b8) ^ 0xc1332568) +% 0x14418cb9) ^ 0xb598eef6) +% 0x34be0e68),
        20 => ((read(block, 0x10c) -% 0x00b8b573) ^ 0x5c04f5e2),
        21 => ((((read(block, 0x04c) ^ 0x1e76a1c5) -% 0x5b255ff0) ^ 0x29a0ec27) +% 0x4a0f4f94),
        22 => (((read(block, 0x0cc) ^ 0x92e195f8) +% 0x442ec989) ^ 0x7f94c950),
        23 => (((read(block, 0x090) ^ 0x394bbd52) -% 0x64b8b22b) ^ 0xe0732c88),
        24 => ((((read(block, 0x078) ^ 0xd2229f23) +% 0x414de9c5) ^ 0xd23d2d63) +% 0x3facf642),
        25 => ((((read(block, 0x2c4) +% 0x1bedc3aa) ^ 0x69a48341) -% 0x4d094ed9) ^ 0xf0a8b109),
        26 => ((read(block, 0x3c8) -% 0x2876763c) ^ 0xed3bddff),
        27 => (((read(block, 0x09c) -% 0x41ec0f84) ^ 0x1cd3a3c8) +% 0x3cff2ee5),
        28 => ((((read(block, 0x0c0) -% 0x551b54a4) ^ 0x4118a30a) -% 0x02f03f96) ^ 0xd7393ee6),
        29 => ((((read(block, 0x2e4) +% 0x121bc76b) ^ 0x03774cda) +% 0x3e57a703) ^ 0x4cc1c54a),
        30 => ((((read(block, 0x0dc) ^ 0xd9352f6a) +% 0x325410e1) ^ 0xe8490ddc) +% 0x59988939),
        31 => ((((read(block, 0x358) ^ 0x79297527) -% 0x389a28e1) ^ 0x9db51a85) +% 0x0b83f7e3),
        32 => ((read(block, 0x0e4) +% 0x34d6c9f6) ^ 0x9ffa9a87),
        33 => ((((read(block, 0x350) ^ 0xeacd3439) -% 0x44674d81) ^ 0x8cbaafb3) -% 0x67ce9d58),
        34 => (((read(block, 0x1f8) ^ 0x646f1d40) -% 0x6fe08b48) ^ 0x492cbef1),
        35 => ((((read(block, 0x348) +% 0x6ea33dad) ^ 0x3543f2bc) +% 0x6164e623) ^ 0x8fc23a81),
        36 => (((read(block, 0x248) -% 0x5a4ea31e) ^ 0x6ab5994e) -% 0x136b2fdd),
        37 => ((((read(block, 0x318) ^ 0xef1b52e6) -% 0x5b396fba) ^ 0xc77780f0) -% 0x683cb1be),
        38 => ((((read(block, 0x290) ^ 0x6518b459) -% 0x6e61929c) ^ 0x278946b0) +% 0x2141888b),
        39 => ((((read(block, 0x1fc) -% 0x564dab75) ^ 0xba19b463) +% 0x030c0399) ^ 0x6325d30e),
        40 => (((read(block, 0x3f8) -% 0x6fa56696) ^ 0x262610f3) -% 0x2984c787),
        41 => ((((read(block, 0x20c) ^ 0x2a67f49f) +% 0x61301610) ^ 0x874df295) -% 0x232785b8),
        42 => (((read(block, 0x338) ^ 0x5718a361) +% 0x43dbc0ca) ^ 0x9a1b7d08),
        43 => (((read(block, 0x3b0) ^ 0xbf86dcd7) -% 0x67c2bcca) ^ 0x87a3b97c),
        44 => ((((read(block, 0x0d4) +% 0x1661524d) ^ 0x1575515d) -% 0x478dbd93) ^ 0x7356b1bb),
        45 => (((read(block, 0x280) ^ 0x27023ee8) -% 0x78bb2db4) ^ 0x8168599c),
        46 => ((((read(block, 0x1e8) ^ 0x8bed7368) +% 0x762f30ba) ^ 0x7664b5a7) -% 0x2c97423e),
        47 => ((((read(block, 0x3dc) ^ 0x71535cf8) +% 0x2542b33c) ^ 0x14034fbb) -% 0x7294e430),
        48 => ((((read(block, 0x0e0) ^ 0xfadc6788) +% 0x09c10c2e) ^ 0x7fa09780) -% 0x1b4d989d),
        49 => ((((read(block, 0x308) ^ 0xd13ac8b8) -% 0x05e331d6) ^ 0xc660883f) -% 0x08c904fa),
        50 => ((((read(block, 0x170) ^ 0x58a2c06c) +% 0x159d967e) ^ 0xadf500ad) +% 0x219d3943),
        51 => ((((read(block, 0x054) +% 0x332eb65c) ^ 0x0b8905b4) +% 0x4286ddf1) ^ 0xdb1aa208),
        52 => ((((read(block, 0x2bc) ^ 0x220c0724) -% 0x16dfcc98) ^ 0xbffc21b1) -% 0x6e7122f0),
        53 => ((((read(block, 0x344) ^ 0x25420afc) +% 0x1869325b) ^ 0x43889687) +% 0x048404a2),
        54 => (((read(block, 0x30c) -% 0x13dac708) ^ 0x13dec24b) -% 0x22d56381),
        55 => ((((read(block, 0x36c) ^ 0x251bc1f6) -% 0x0212714e) ^ 0x8cc3a36c) +% 0x5f63bd73),
        56 => ((((read(block, 0x3bc) ^ 0x704c7830) -% 0x60c0feb3) ^ 0x88afd714) +% 0x259fc0b8),
        57 => (((read(block, 0x320) ^ 0x66dce437) +% 0x59479f7f) ^ 0x3315c9dc),
        58 => (((read(block, 0x23c) ^ 0x0a5c5094) -% 0x00992fbd) ^ 0x13728d90),
        59 => (((read(block, 0x134) -% 0x3d6d8755) ^ 0xae2c38bb) -% 0x40c1b904),
        60 => (((read(block, 0x3a8) +% 0x2d3206a5) ^ 0xf7e413e3) -% 0x6ad203b6),
        61 => ((((read(block, 0x2d4) ^ 0x7da944f1) +% 0x0c4613a1) ^ 0xf1dd92d7) -% 0x4d448df1),
        62 => (((read(block, 0x0b0) +% 0x1cbdfaec) ^ 0xdd3385cd) -% 0x7d3fa930),
        63 => (((read(block, 0x17c) ^ 0x1c77c8a0) -% 0x670b3ef8) ^ 0x5805de29),
    };
}

pub fn decodeBlock(block: *const [block_size]u8, output: *[lane_count]u32) void {
    for (output, 0..) |*value, lane| value.* = decodeLane(block, @intCast(lane));
}

test "known recipe lane outputs" {
    var block: [block_size]u8 = @splat(0);
    std.mem.writeInt(u32, block[0x18c..][0..4], 0xd5881931, .little);
    std.mem.writeInt(u32, block[0x17c..][0..4], 0xa366d5bf, .little);
    try std.testing.expectEqual(@as(u32, 0x252bd738), decodeLane(&block, 0));
    try std.testing.expectEqual(@as(u32, 0x0000000e), decodeLane(&block, 63));
}
