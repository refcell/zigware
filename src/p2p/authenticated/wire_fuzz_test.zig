//! Fuzz targets for the authenticated networks' wire decoders: discovery's `Payload` (and the
//! `Info`, `BitVec`, and `Data` it dispatches into) and lookup's `Message`. These decode bytes
//! received from peers, so any successful decode must re-encode to exactly its input (the
//! canonical-encoding property commonware's codec fuzzing checks), within the configured
//! limits, without leaking.
//!
//! Each iteration starts from the encoding of a valid message (or raw bytes after a forced
//! prefix) and applies a few drawn mutations, so the decoders are reached past their prefix
//! byte on seeded input too. Runs through `p2p.fuzz.run`: seeded in `zig build test`, then
//! under `std.testing.fuzz`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const cryptography = @import("cryptography");
const fuzz = @import("../fuzz.zig");
const discovery = @import("discovery/types.zig");
const lookup = @import("lookup/types.zig");
const data_mod = @import("data.zig");
const p2p_types = @import("../types.zig");

const standard = cryptography.secp256r1.standard;
const PublicKey = standard.PublicKey;
const PrivateKey = standard.PrivateKey;
const Info = discovery.Info(PublicKey);
const Payload = discovery.Payload(PublicKey);
const Draws = codec.fuzz.Draws;
const gpa = testing.allocator;

const cfg: discovery.PayloadConfig = .{ .max_bit_vec = 128, .max_peers = 3, .max_data_length = 64 };
/// Seeds that decode: four payloads, then two lookup messages.
const valid_count = 6;
/// Seeds one past a limit (peers, bits, data length), which must never decode.
const over_count = 3;
const seed_count = valid_count + over_count;
const input_max = 1024;

/// Encodings of valid messages that mutations start from.
const Seeds = struct {
    encodings: [seed_count][]u8,

    fn init() !Seeds {
        var rng = utils.rng.test_rng();
        const info_a = signed_info(&rng, 8080);
        const info_b = signed_info(&rng, 9090);
        const info_c = signed_info(&rng, 7070);
        const info_d = signed_info(&rng, 6060);
        var bits = try discovery.BitMap.ones(gpa, 71);
        defer bits.deinit(gpa);
        var bits_over = try discovery.BitMap.ones(gpa, cfg.max_bit_vec + 1);
        defer bits_over.deinit(gpa);
        const data: data_mod.Data = .{ .channel = 300, .message = "hello" };
        const long: [cfg.max_data_length + 1]u8 = @splat(0x5a);
        var seeds: Seeds = undefined;
        var filled: usize = 0;
        errdefer for (seeds.encodings[0..filled]) |encoding| gpa.free(encoding);
        const payloads = [_]Payload{
            .{ .greeting = info_a },
            .{ .peers = &.{ info_a, info_b } },
            .{ .bit_vec = .{ .index = 1234, .bits = bits } },
            .{ .data = data },
        };
        for (payloads) |payload| {
            seeds.encodings[filled] = try codec.encode(Payload, gpa, payload);
            filled += 1;
        }
        seeds.encodings[filled] = try codec.encode(lookup.Message, gpa, .{ .data = data });
        filled += 1;
        seeds.encodings[filled] = try codec.encode(lookup.Message, gpa, .ping);
        filled += 1;
        assert(filled == valid_count);
        const over = [_]Payload{
            .{ .peers = &.{ info_a, info_b, info_c, info_d } },
            .{ .bit_vec = .{ .index = 7, .bits = bits_over } },
            .{ .data = .{ .channel = 1, .message = &long } },
        };
        for (over) |payload| {
            seeds.encodings[filled] = try codec.encode(Payload, gpa, payload);
            filled += 1;
        }
        assert(filled == seed_count);
        return seeds;
    }

    fn deinit(seeds: *Seeds) void {
        for (seeds.encodings) |encoding| gpa.free(encoding);
        seeds.* = undefined;
    }
};

fn signed_info(rng: anytype, port: u16) Info {
    const signer = PrivateKey.random(rng);
    const ingress: p2p_types.Ingress = .{
        .socket = .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port },
    };
    return .{
        .ingress = ingress,
        .timestamp = 1234567890,
        .public_key = signer.public_key(),
        .signature = signer.sign("fuzz", &.{ 1, 2, 3 }),
    };
}

/// Builds the input: a seed encoding, or a drawn prefix byte followed by raw bytes, then up to
/// four drawn mutations (overwrite a byte, truncate, or append a byte).
fn build_input(seeds: *const Seeds, draws: Draws, buffer: *[input_max]u8) []u8 {
    var len: usize = 0;
    const arm = draws.range_at_most(usize, 0, seed_count);
    if (arm < seed_count) {
        const seed = seeds.encodings[arm];
        assert(seed.len <= buffer.len);
        @memcpy(buffer[0..seed.len], seed);
        len = seed.len;
    } else {
        buffer[0] = draws.range_at_most(u8, 0, 4);
        const raw = draws.slice(buffer[1..128]);
        len = 1 + raw.len;
    }
    const mutations = draws.range_at_most(u32, 0, 4);
    for (0..mutations) |_| {
        switch (draws.range_at_most(u8, 0, 2)) {
            0 => if (len > 0) {
                buffer[draws.range_at_most(usize, 0, len - 1)] = draws.value(u8);
            },
            1 => len = draws.range_at_most(usize, 0, len),
            2 => if (len < buffer.len) {
                buffer[len] = draws.value(u8);
                len += 1;
            },
            else => unreachable,
        }
    }
    assert(len <= buffer.len);
    return buffer[0..len];
}

/// Any successful decode of `T` under `limits` re-encodes to exactly `input`.
fn expect_canonical(comptime T: type, input: []const u8, limits: codec.Cfg(T)) !void {
    var value = codec.decode_cfg(T, gpa, input, limits) catch return;
    defer if (@hasDecl(T, "deinit")) value.deinit(gpa);
    try testing.expectEqual(input.len, value.encode_size());
    var buffer: [input_max]u8 = undefined;
    const encoded = codec.encode_to(T, value, &buffer);
    try testing.expectEqualSlices(u8, input, encoded);
}

/// The decoded payload stays within the configured limits.
fn expect_bounded(input: []const u8) !void {
    var payload = codec.decode_cfg(Payload, gpa, input, cfg) catch return;
    defer payload.deinit(gpa);
    switch (payload) {
        .data => |data| try testing.expect(data.message.len <= cfg.max_data_length),
        .greeting => {},
        .bit_vec => |bit_vec| try testing.expect(bit_vec.bits.len() <= cfg.max_bit_vec),
        .peers => |peers| try testing.expect(peers.len <= cfg.max_peers),
    }
}

fn decode_wire(seeds: *const Seeds, smith: *std.testing.Smith) anyerror!void {
    const draws: Draws = .init(smith);
    var buffer: [input_max]u8 = undefined;
    const input = build_input(seeds, draws, &buffer);
    try expect_canonical(Payload, input, cfg);
    try expect_bounded(input);
    try expect_canonical(lookup.Message, input, cfg.max_data_length);
    try expect_canonical(data_mod.Data, input, .to_inclusive(cfg.max_data_length));
}

test "fuzz authenticated wire decoders are canonical and bounded" {
    var seeds = try Seeds.init();
    defer seeds.deinit();
    // Every seed decodes as the type it encodes.
    for (seeds.encodings[0..4]) |encoding| {
        var payload = try codec.decode_cfg(Payload, gpa, encoding, cfg);
        payload.deinit(gpa);
    }
    for (seeds.encodings[4..valid_count]) |encoding| {
        _ = try codec.decode_cfg(lookup.Message, gpa, encoding, cfg.max_data_length);
    }
    // Seeds one past a limit never decode.
    for (seeds.encodings[valid_count..]) |encoding| {
        try testing.expectError(error.InvalidLength, codec.decode_cfg(Payload, gpa, encoding, cfg));
    }
    try fuzz.run(@as(*const Seeds, &seeds), decode_wire, 0x7032_7069_7265, 4000);
}
