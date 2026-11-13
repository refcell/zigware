//! Tests of `elector.zig`, ported from commonware's `simplex/elector.rs`, and the
//! `RoundRobinShuffleConformance` hash. The Random V0/V1 conformance hashes and the tests that
//! assemble threshold certificates wait for the bls-math lane's threshold signatures.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const elector = @import("elector.zig");
const vrf = @import("scheme/bls12381_threshold/vrf.zig");

const Participant = consensus_types.Participant;
const Round = consensus_types.Round;
const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;
const TermLength = consensus_types.TermLength;
const Duration = utils.Duration;
const Sha256 = cryptography.Sha256;
const MinPk = cryptography.bls12381.primitives.MinPk;
const RoundRobin = elector.RoundRobin(Sha256);
const Random = elector.Random(Sha256);

const gpa = testing.allocator;

fn round(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

fn term(length: u32) TermLength {
    return .new(utils.NonZero(u32).init(length).?);
}

fn stable(length: u32) RoundRobin {
    return RoundRobin.default().with_term(term(length), .from_secs(10), .zero());
}

test "stable terms preserve optimistic views" {
    for ([_]u64{ 0, 3, 4, 5, 6, std.math.maxInt(u64) }) |requested| {
        const terms = elector.Terms.stable(term(5), .from_secs(1), .new(requested));
        try testing.expectEqual(ViewDelta.new(requested), terms.optimistic_views);
    }
    const rotating = elector.Terms.rotating();
    try testing.expectEqual(1, rotating.length.get());
    try testing.expectEqual(null, rotating.stall_timeout);
}

test "round robin rotates through participants" {
    var built = try RoundRobin.default().build(gpa, 4);
    defer built.deinit(gpa);
    var previous = built.elect(round(0, 1), {});
    for (2..13) |view| {
        const leader = built.elect(round(0, view), {});
        try testing.expectEqual((previous.get() + 1) % 4, leader.get());
        previous = leader;
    }
}

test "round robin cycles through epochs" {
    var built = try RoundRobin.default().build(gpa, 5);
    defer built.deinit(gpa);
    var seen: [5]bool = @splat(false);
    for (0..5) |epoch| {
        const leader = built.elect(round(epoch, 1), {}).get();
        try testing.expect(!seen[leader]);
        seen[leader] = true;
    }
    for (seen) |was_seen| try testing.expect(was_seen);
}

test "round robin handles a wrapping epoch plus term index" {
    var built = try stable(5).build(gpa, 5);
    defer built.deinit(gpa);
    const epoch = std.math.maxInt(u64) - 1;
    // Term index of view 6 is 2; (2^64 - 2 + 2) wraps to 0. Without wrapping first, the
    // modulo would see 2^64 - 2 % 5 = 4 plus 2.
    try testing.expectEqual(0, built.elect(round(epoch, 6), {}).get());
}

test "round robin uses stable leaders within terms" {
    var built = try stable(3).build(gpa, 4);
    defer built.deinit(gpa);
    const leaders = [_]u32{
        built.elect(round(0, 1), {}).get(), built.elect(round(0, 2), {}).get(),
        built.elect(round(0, 3), {}).get(), built.elect(round(0, 4), {}).get(),
        built.elect(round(0, 5), {}).get(), built.elect(round(0, 6), {}).get(),
    };
    try testing.expect(leaders[0] == leaders[1] and leaders[0] == leaders[2]);
    try testing.expect(leaders[3] == leaders[4] and leaders[3] == leaders[5]);
    try testing.expect(leaders[0] != leaders[3]);
}

test "round robin epoch transition shifts the stable term leader" {
    var built = try stable(3).build(gpa, 4);
    defer built.deinit(gpa);
    try testing.expectEqual(1, built.elect(round(0, 1), {}).get());
    try testing.expectEqual(1, built.elect(round(0, 2), {}).get());
    try testing.expectEqual(2, built.elect(round(1, 1), {}).get());
    try testing.expectEqual(2, built.elect(round(1, 3), {}).get());
    try testing.expectEqual(3, built.elect(round(2, 1), {}).get());
    try testing.expectEqual(3, built.elect(round(2, 2), {}).get());
}

fn first_leaders(built: elector.RoundRobinElector) [5]u32 {
    var leaders: [5]u32 = undefined;
    for (&leaders, 1..) |*leader, view| leader.* = built.elect(round(0, view), {}).get();
    return leaders;
}

test "round robin shuffled changes order" {
    var no_seed = try RoundRobin.default().build(gpa, 5);
    defer no_seed.deinit(gpa);
    var seed_1 = try RoundRobin.shuffled("seed1").build(gpa, 5);
    defer seed_1.deinit(gpa);
    var seed_2 = try RoundRobin.shuffled("seed2").build(gpa, 5);
    defer seed_2.deinit(gpa);
    const leaders_no_seed = first_leaders(no_seed);
    const leaders_1 = first_leaders(seed_1);
    const leaders_2 = first_leaders(seed_2);
    try testing.expectEqual([5]u32{ 1, 2, 3, 4, 0 }, leaders_no_seed);
    try testing.expect(!std.mem.eql(u32, &leaders_1, &leaders_no_seed));
    try testing.expect(!std.mem.eql(u32, &leaders_2, &leaders_no_seed));
    try testing.expect(!std.mem.eql(u32, &leaders_1, &leaders_2));
    for ([_][5]u32{ leaders_1, leaders_2 }) |leaders| {
        var sorted = leaders;
        std.mem.sort(u32, &sorted, {}, std.sort.asc(u32));
        try testing.expectEqual([5]u32{ 0, 1, 2, 3, 4 }, sorted);
    }
}

test "round robin shuffle orders by hash of seed and index" {
    var built = try RoundRobin.shuffled("seed1").build(gpa, 5);
    defer built.deinit(gpa);
    // Independently: each index's key is SHA-256(seed || index as big-endian u32).
    for (built.permutation[0 .. built.permutation.len - 1], built.permutation[1..]) |a, b| {
        var key_a: [4]u8 = undefined;
        var key_b: [4]u8 = undefined;
        std.mem.writeInt(u32, &key_a, a.get(), .big);
        std.mem.writeInt(u32, &key_b, b.get(), .big);
        var digest_a: [32]u8 = undefined;
        var digest_b: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("seed1" ++ key_a, &digest_a, .{});
        std.crypto.hash.sha2.Sha256.hash("seed1" ++ key_b, &digest_b, .{});
        try testing.expectEqual(.lt, std.mem.order(u8, &digest_a, &digest_b));
    }
}

test "round robin same seed is deterministic" {
    var first = try RoundRobin.shuffled("same_seed").build(gpa, 5);
    defer first.deinit(gpa);
    var second = try RoundRobin.shuffled("same_seed").build(gpa, 5);
    defer second.deinit(gpa);
    for (1..11) |view| {
        try testing.expectEqual(first.elect(round(0, view), {}), second.elect(round(0, view), {}));
    }
}

test "random falls back to round robin for view 1" {
    const random = Random.init(.v1).build(MinPk, 5);
    var seen: [5]bool = @splat(false);
    for (0..5) |epoch| {
        const leader = random.elect(round(epoch, 1), null).get();
        try testing.expect(!seen[leader]);
        seen[leader] = true;
    }
    for (seen) |was_seen| try testing.expect(was_seen);
}

test "random fallback does not truncate before modulo" {
    // Five participants make truncation observable: 2^32 % 5 is 1, (2^32 as u32) % 5 is 0.
    var round_robin = try RoundRobin.default().build(gpa, 5);
    defer round_robin.deinit(gpa);
    const random = Random.init(.v1).build(MinPk, 5);
    const at = round(std.math.maxInt(u32), 1);
    try testing.expectEqual(1, round_robin.elect(at, {}).get());
    try testing.expectEqual(1, random.elect(at, null).get());
}

test "random uses the certificate's seed signature" {
    const G2 = MinPk.Signature;
    const n: u32 = 7;
    var keystream = codec.arbitrary.Keystream.init(42, 4096);
    var u = codec.arbitrary.Unstructured.init(&keystream);
    const seed = vrf.arbitrary_point(G2, &u);
    const other = vrf.arbitrary_point(G2, &u);
    const Certificate = vrf.Certificate(MinPk);
    const certificate = Certificate.init(.{ .vote_signature = other, .seed_signature = seed });
    const encoded = seed.to_bytes();
    // Independently: V0 reduces the 96-byte encoding as one big-endian integer, V1 its hash.
    const as_int = std.mem.readInt(u768, &encoded, .big);
    var hashed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&encoded, &hashed, .{});
    const v0 = Random.init(.v0).build(MinPk, n);
    const v1 = Random.init(.v1).build(MinPk, n);
    const at = round(3, 9);
    try testing.expectEqual(@as(u32, @intCast(as_int % n)), v0.elect(at, &certificate).get());
    const expected_v1: u32 = @intCast(std.mem.readInt(u256, &hashed, .big) % n);
    try testing.expectEqual(expected_v1, v1.elect(at, &certificate).get());
    // The seed signature decides, not the vote signature or the round.
    const swapped = Certificate.init(.{ .vote_signature = seed, .seed_signature = seed });
    try testing.expectEqual(v1.elect(at, &certificate), v1.elect(round(8, 2), &swapped));
}

// Conformance.

/// commonware's `RoundRobinShuffleConformance`: an ed25519 fixture of `random_range(1..=100)`
/// participants, a random 32-byte shuffle seed, then the encoded permutation.
const RoundRobinShuffleConformance = struct {
    pub fn commit(allocator: Allocator, seed: u64) ![]u8 {
        var rng = utils.rng.ChaCha8Rng.init(seed);
        const n = utils.rng.range_at_most(&rng, u32, 1, 100);
        // The fixture draws each private key as 32 bytes (`SigningKey::new`); the
        // permutation depends only on the count, so only the draws are reproduced.
        for (0..n) |_| {
            var key: [32]u8 = undefined;
            rng.fill_bytes(&key);
        }
        // rand's `[u8; 32]`: one `next_u32` per byte, truncated.
        var shuffle_seed: [32]u8 = undefined;
        for (&shuffle_seed) |*byte| byte.* = @truncate(rng.next_u32());
        var built = try RoundRobin.shuffled(&shuffle_seed).build(allocator, n);
        defer built.deinit(allocator);
        return codec.encode([]const Participant, allocator, built.permutation);
    }
};

test "round robin shuffle conformance hash matches commonware" {
    try conformance.verify(
        RoundRobinShuffleConformance,
        std.heap.smp_allocator,
        "commonware_consensus::simplex::elector::tests::conformance::RoundRobinShuffleConformance",
        512,
        @embedFile("../conformance.toml"),
    );
}
