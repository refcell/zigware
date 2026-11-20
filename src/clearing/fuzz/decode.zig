//! Decode fuzz for every bajillion wire type (commonware `clearing/fuzz/fuzz_targets/decode.rs`).
//!
//! The input picks a wire type and an `arbitrary` seed. The value drawn for that seed must
//! encode to its stated size and decode back to itself under the tightest configuration that
//! admits it. The rest of the input is then decoded as every wire type: a value that decodes
//! must round-trip the same way, and bytes that do not decode must be refused without a crash
//! or a leak. Beyond commonware's target, the drawn value's encoding is also decoded with two
//! bytes flipped, which reaches the decoders' later checks far more often than raw bytes.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const bajillion = @import("../bajillion/mod.zig");
const arb = @import("../bajillion/arbitrary.zig");
const bytes = @import("bytes.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const PublicKey = cryptography.ed25519.PublicKey;
const gpa = testing.allocator;

/// The most receivers a request or row may pay when decoding bytes.
const receivers = 16;

/// The limits closes are decoded from bytes with.
const limits: bajillion.Limits = .{ .rows = 16, .receivers = receivers, .withdrawals = 16 };

const Amounts = bajillion.Amounts(PublicKey, u64);
const Request = bajillion.Request(PublicKey, Digest, u64);
const Row = bajillion.Row(PublicKey, u64);
const Close = bajillion.Close(PublicKey, PublicKey, u64);

/// Every wire type, in commonware's `FuzzInput` order.
const types = [_]type{
    Amounts,
    bajillion.State(PublicKey, Digest),
    bajillion.Signatures(PublicKey),
    Request,
    bajillion.Receipt(PublicKey, PublicKey, Digest, u64),
    bajillion.Challenge(PublicKey, PublicKey, Digest, u64),
    bajillion.Withdrawal(PublicKey, u64),
    bajillion.Deposit(PublicKey, u64),
    bajillion.ForcedWithdrawal(PublicKey, u64),
    Row,
    Close,
    bajillion.Lookup(PublicKey, u64, Digest),
    bajillion.Opening(PublicKey, Digest, u64),
    bajillion.Flow(u64),
    bajillion.Processed(Digest),
    bajillion.Summary(Sha256),
    bajillion.Payout(PublicKey, u64),
    bajillion.PayoutProof(PublicKey, Digest, u64),
    bajillion.BalanceProof(Digest, u64),
};

/// Whether `a` equals `b`, through `T.eql` by value or by pointer.
fn equal(comptime T: type, a: *const T, b: *const T) bool {
    const by_value = @typeInfo(@TypeOf(T.eql)).@"fn".param_types[0].? == T;
    return if (by_value) a.eql(b.*) else a.eql(b);
}

/// The tightest configuration that admits `value`.
fn cfg_of(comptime T: type, value: *const T) codec.Cfg(T) {
    if (T == Amounts) return .to_inclusive(value.len());
    if (T == Request) return value.batch.len();
    if (T == Row) return value.payments.len();
    if (T == Close) {
        var widest: usize = 0;
        for (value.rows) |*row| widest = @max(widest, row.payments.len());
        return .{
            .rows = value.rows.len,
            .receivers = widest,
            .withdrawals = value.withdrawals.len,
        };
    }
    comptime assert(codec.Cfg(T) == void);
    return {};
}

/// The configuration bytes are decoded as `T` with.
fn bytes_cfg(comptime T: type) codec.Cfg(T) {
    if (T == Amounts) return .to_inclusive(receivers);
    if (T == Request or T == Row) return receivers;
    if (T == Close) return limits;
    comptime assert(codec.Cfg(T) == void);
    return {};
}

/// Checks that `value` encodes to its stated size and decodes back to itself under `cfg`.
fn roundtrip(comptime T: type, value: *const T, cfg: codec.Cfg(T)) !void {
    const encoded = try codec.encode(T, gpa, value.*);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(T, value.*), encoded.len);
    const decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    defer codec.free(T, gpa, decoded);
    try testing.expect(equal(T, &decoded, value));
}

/// Decodes `input` as a `T`. A value that decodes must round-trip, and bytes that do not
/// decode must be refused.
fn decode(comptime T: type, input: []const u8) !void {
    const cfg = bytes_cfg(T);
    const decoded = codec.decode_cfg(T, gpa, input, cfg) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    defer codec.free(T, gpa, decoded);
    try roundtrip(T, &decoded, cfg);
}

fn Generated(comptime T: type) type {
    return struct {
        fn generate(allocator: Allocator, u: *arb.Unstructured) arb.Error!T {
            return arb.value(T, allocator, u);
        }
    };
}

/// Draws a `T` for `seed` and checks it round-trips, then decodes its encoding with up to two
/// bytes the reader picks flipped. Values too large for the generator's buffer are skipped.
fn check_generated(comptime T: type, seed: u64, reader: *bytes.Reader) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const generate = Generated(T).generate;
    const value = codec.arbitrary.generate(T, generate, arena.allocator(), seed) catch |err|
        switch (err) {
            error.OutOfMemory => return err,
            else => return,
        };
    try roundtrip(T, &value, cfg_of(T, &value));
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    if (encoded.len == 0) return;
    for (0..2) |_| mutate(encoded, reader);
    try decode(T, encoded);
}

/// Flips a byte, zeroes a run, or copies a run over another offset. Zeroed and copied runs
/// make zero amounts and repeated entries, which raw flips almost never reach (the semantic
/// checks behind a decoder's framing).
fn mutate(encoded: []u8, reader: *bytes.Reader) void {
    assert(encoded.len > 0);
    const at = reader.below(encoded.len);
    const len = @min(reader.below(48) + 1, encoded.len - at);
    assert(at + len <= encoded.len);
    switch (reader.below(3)) {
        0 => encoded[at] ^= reader.int(u8),
        1 => @memset(encoded[at..][0..len], 0),
        2 => {
            const from = reader.below(encoded.len - len + 1);
            const to = encoded[at..][0..len];
            const source = encoded[from..][0..len];
            // The runs may overlap: copy away from the overlap.
            if (at <= from) std.mem.copyForwards(u8, to, source) else std.mem.copyBackwards(
                u8,
                to,
                source,
            );
        },
        else => unreachable,
    }
}

/// One fuzz input: a choice among the wire types or raw bytes, a seed, and bytes.
pub fn run_one(input: []const u8) anyerror!void {
    var reader = bytes.Reader.init(input);
    const choice = reader.below(types.len + 1);
    const seed = reader.int(u32);
    inline for (types, 0..) |T, index| {
        if (index == choice) try check_generated(T, seed, &reader);
    }
    const rest = input[reader.offset..];
    inline for (types) |T| try decode(T, rest);
}

test "fuzz clearing decoders (seeded)" {
    try bytes.seeded(256, 0x636c_6561_7264_6563, 512, run_one);
}

test "fuzz clearing decoders" {
    try testing.fuzz({}, bytes.smith(512, run_one), .{});
}
