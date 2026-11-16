//! Tests of `lookup.zig` (commonware `bajillion/lookup.rs` tests).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const storage = @import("storage");
const cryptography = @import("cryptography");
const lookup = @import("lookup.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const TestLookup = lookup.Lookup(u64, u64, Digest);
const Entry = TestLookup.Entry;
const bmt = storage.bmt;
const gpa = testing.allocator;

/// Returns the leaf committing to `key` and `value`.
fn leaf(key: *const u64, value: *const u64) Digest {
    var key_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &key_bytes, key.*, .big);
    var value_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &value_bytes, value.*, .big);
    return Sha256.hash(&.{ &key_bytes, &value_bytes });
}

/// `count` entries with keys 10, 20, ... and their tree.
const List = struct {
    entries: []Entry,
    tree: bmt.Tree(Digest),

    fn init(allocator: Allocator, count: u64) !List {
        const entries = try allocator.alloc(Entry, count);
        errdefer allocator.free(entries);
        var builder = try bmt.Builder(Sha256).init(allocator, count);
        defer builder.deinit(allocator);
        for (entries, 1..) |*entry, i| {
            entry.* = .{ 10 * i, i };
            _ = try builder.add(allocator, &leaf(&entry[0], &entry[1]));
        }
        return .{ .entries = entries, .tree = try builder.build(allocator) };
    }

    fn deinit(self: *List, allocator: Allocator) void {
        allocator.free(self.entries);
        self.tree.deinit(allocator);
    }

    fn open(self: *const List, key: u64) !TestLookup {
        return TestLookup.init(gpa, self.entries, &self.tree, &key);
    }
};

/// Verifies `opening` as an opening of `key` under `root`, and returns the value it opens.
fn verify(opening: *const TestLookup, key: u64, root: *const Digest) !?u64 {
    return opening.verify(Sha256, root, &key, leaf);
}

fn root_of(count: u64) !Digest {
    var list = try List.init(gpa, count);
    defer list.deinit(gpa);
    return list.tree.root();
}

// Every key, present or absent, opens and verifies under the root.
test "lookup: opens every key" {
    for (0..7) |count| {
        var list = try List.init(gpa, count);
        defer list.deinit(gpa);
        const root = list.tree.root();
        for (list.entries) |entry| {
            var opening = try list.open(entry[0]);
            defer opening.deinit(gpa);
            try testing.expect(opening == .member);
            try testing.expectEqual(@as(?u64, entry[1]), try verify(&opening, entry[0], &root));
        }
        for (0..count + 1) |i| {
            const key = 10 * i + 5;
            var opening = try list.open(key);
            defer opening.deinit(gpa);
            try testing.expect(opening == .non_member);
            try testing.expectEqual(@as(?u64, null), try verify(&opening, key, &root));
        }
    }
}

// A member opening verifies only for its own value, position, key, and root.
test "lookup: rejects tampered members" {
    var list = try List.init(gpa, 4);
    defer list.deinit(gpa);
    const root = list.tree.root();
    var opening = try list.open(20);
    defer opening.deinit(gpa);
    const member = opening.member;
    const position = member.position;
    const value = member.value;
    const tampered = [_]TestLookup{
        .{ .member = .{ .position = position, .value = value + 1, .proof = member.proof } },
        .{ .member = .{ .position = position + 1, .value = value, .proof = member.proof } },
    };
    for (&tampered) |*forged| {
        try testing.expectError(error.InvalidOpening, verify(forged, 20, &root));
    }
    try testing.expectError(error.InvalidOpening, verify(&opening, 30, &root));
    try testing.expectError(error.InvalidOpening, verify(&opening, 20, &try root_of(5)));
}

// A non-member opening verifies only for a key strictly between its neighbors, with every
// neighbor its position requires.
test "lookup: rejects tampered non-members" {
    var list = try List.init(gpa, 4);
    defer list.deinit(gpa);
    const root = list.tree.root();

    // An opening between two neighbors only proves keys strictly between them absent.
    var opening = try list.open(25);
    defer opening.deinit(gpa);
    for ([_]u64{ 20, 30, 15, 35 }) |key| {
        try testing.expectError(error.InvalidOpening, verify(&opening, key, &root));
    }
    const absent = opening.non_member;
    try testing.expectEqual(@as(u64, 20), absent.lower.?[0]);
    try testing.expectEqual(@as(u64, 30), absent.upper.?[0]);

    // Neighbors must be present unless the key precedes or follows every entry, so a present
    // key cannot be proven absent with one neighbor and that neighbor's own proof.
    var proof_one = try list.tree.proof(gpa, 1, null);
    defer proof_one.deinit(gpa);
    var proof_two = try list.tree.proof(gpa, 2, null);
    defer proof_two.deinit(gpa);
    const one_sided = [_]struct { u64, TestLookup }{
        .{ 30, .{ .non_member = .{
            .position = 2,
            .lower = list.entries[1],
            .upper = null,
            .proof = proof_one,
        } } },
        .{ 20, .{ .non_member = .{
            .position = 2,
            .lower = null,
            .upper = list.entries[2],
            .proof = proof_two,
        } } },
    };
    for (&one_sided) |*case| {
        try testing.expectError(error.InvalidOpening, verify(&case[1], case[0], &root));
    }

    // Neighbors must sit at the claimed position, and a list with entries does not open as
    // empty.
    const misplaced = [_]TestLookup{
        .{ .non_member = .{
            .position = absent.position + 1,
            .lower = absent.lower,
            .upper = absent.upper,
            .proof = absent.proof,
        } },
        .{ .non_member = .{
            .position = absent.position,
            .lower = absent.upper,
            .upper = absent.lower,
            .proof = absent.proof,
        } },
        .{ .non_member = .{ .position = 0, .lower = null, .upper = null, .proof = .{} } },
    };
    for (&misplaced) |*forged| {
        try testing.expectError(error.InvalidOpening, verify(forged, 25, &root));
    }

    // A present key cannot be proven absent with the neighbors of a nearby absent key.
    var first = try list.open(5);
    defer first.deinit(gpa);
    try testing.expectError(error.InvalidOpening, verify(&first, 10, &root));
    var last = try list.open(45);
    defer last.deinit(gpa);
    try testing.expectError(error.InvalidOpening, verify(&last, 40, &root));
}

// The empty list opens every key as absent, and its opening verifies under no other root.
test "lookup: empty list" {
    var list = try List.init(gpa, 0);
    defer list.deinit(gpa);
    var opening = try list.open(5);
    defer opening.deinit(gpa);
    try testing.expectEqual(@as(?u64, null), try verify(&opening, 5, &list.tree.root()));
    try testing.expectError(error.InvalidOpening, verify(&opening, 5, &try root_of(1)));
}

fn expect_round_trip(opening: *const TestLookup) !void {
    const encoded = try codec.encode(TestLookup, gpa, opening.*);
    defer gpa.free(encoded);
    try testing.expectEqual(encoded.len, codec.encode_size(TestLookup, opening.*));
    var decoded = try codec.decode(TestLookup, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(opening));
}

// The opening of an absent key between two entries proves both neighbors. In this list the
// neighbors sit at positions 2^17 - 1 and 2^17, and that proof holds more siblings than a
// single path can hold. The opening still round-trips and verifies.
test "lookup: opens absent key across subtrees" {
    var list = try List.init(gpa, (1 << 17) + (1 << 15) + 1);
    defer list.deinit(gpa);
    const key = 10 * (1 << 17) + 5;
    var opening = try list.open(key);
    defer opening.deinit(gpa);
    const absent = opening.non_member;
    try testing.expectEqual(@as(u32, 1 << 17), absent.position);
    try testing.expect(absent.lower != null and absent.upper != null);
    try testing.expect(absent.proof.siblings.len > bmt.max_levels);
    try expect_round_trip(&opening);
    try testing.expectEqual(@as(?u64, null), try verify(&opening, key, &list.tree.root()));
}

// Openings round-trip, and a tag naming neither variant is refused.
test "lookup: codec" {
    var list = try List.init(gpa, 3);
    defer list.deinit(gpa);
    for ([_]u64{ 5, 10, 25, 30, 35 }) |key| {
        var opening = try list.open(key);
        defer opening.deinit(gpa);
        try expect_round_trip(&opening);
    }

    var empty = try List.init(gpa, 0);
    defer empty.deinit(gpa);
    var opening = try empty.open(5);
    defer opening.deinit(gpa);
    try expect_round_trip(&opening);
    const mistagged = try codec.encode(TestLookup, gpa, opening);
    defer gpa.free(mistagged);
    mistagged[0] = 2;
    try testing.expectError(error.InvalidEnum, codec.decode(TestLookup, gpa, mistagged));
}
