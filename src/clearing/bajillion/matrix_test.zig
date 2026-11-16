//! Tests of `matrix.zig` (commonware `bajillion/matrix.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const matrix_module = @import("matrix.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const Digest = t.Digest;
const PublicKey = t.PublicKey;
const TestAmounts = t.TestAmounts;
const TestMatrix = matrix_module.Matrix(PublicKey, Sha256, u64);
const TestOpening = matrix_module.Opening(PublicKey, Digest, u64);
const gpa = testing.allocator;

/// A sender and the receivers it pays, by index into the accounts.
const RowSpec = struct { sender: usize, pays: []const [2]u64 };

/// Returns the payment map paying `keys[index]` its amount for each `{ index, amount }`.
fn payments(keys: []const PublicKey, pays: []const [2]u64) !TestAmounts {
    var entries: [8]TestAmounts.Entry = undefined;
    for (pays, entries[0..pays.len]) |pay, *entry| entry.* = .{ keys[pay[0]], pay[1] };
    return TestAmounts.init(gpa, entries[0..pays.len]);
}

/// Returns the matrix of `specs`, whose senders must strictly increase.
fn matrix(keys: []const PublicKey, specs: []const RowSpec) !TestMatrix {
    var rows: [8]TestMatrix.Row = undefined;
    for (specs, rows[0..specs.len]) |spec, *row| {
        const map = try payments(keys, spec.pays);
        row.* = .{ keys[spec.sender], map, map.root(Sha256) };
    }
    return TestMatrix.from_sorted(gpa, rows[0..specs.len]);
}

fn expect_round_trip(opening: *const TestOpening) !void {
    const encoded = try codec.encode(TestOpening, gpa, opening.*);
    defer gpa.free(encoded);
    var decoded = try codec.decode(TestOpening, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(opening));
}

// Every sender and receiver pair opens to the amount paid, or zero, and every sender to the
// root of its row, or to no row.
test "matrix: opens every pair" {
    const keys = t.accounts(6);
    const specs = [_]RowSpec{
        .{ .sender = 1, .pays = &.{ .{ 0, 5 }, .{ 4, 7 } } },
        .{ .sender = 3, .pays = &.{.{ 1, 1 }} },
        .{ .sender = 4, .pays = &.{ .{ 4, 2 }, .{ 5, 3 } } },
    };
    var value = try matrix(&keys, &specs);
    defer value.deinit();
    var shared = value.clone();
    defer shared.deinit();
    const root = shared.root();
    try testing.expectEqual(@as(usize, 3), value.len());
    try testing.expect(!value.is_empty());

    for (&keys, 0..) |*sender, sender_index| {
        var expected_map: ?TestAmounts = null;
        defer if (expected_map) |*map| map.deinit(gpa);
        for (specs) |spec| {
            if (spec.sender == sender_index) expected_map = try payments(&keys, spec.pays);
        }
        const found = value.payments(sender);
        try testing.expectEqual(expected_map == null, found == null);
        if (found) |map| try testing.expect(map.eql(&expected_map.?));
        for (&keys) |*receiver| {
            var opening = try value.open(gpa, sender, receiver);
            defer opening.deinit(gpa);
            const expected = if (expected_map) |*map| map.get(receiver) else 0;
            try testing.expectEqual(expected, try opening.verify(Sha256, &root, sender, receiver));
            const row = try opening.verify_row(Sha256, &root, sender);
            try testing.expectEqual(expected_map == null, row == null);
            if (row) |payments_root| {
                try testing.expect(payments_root.eql(expected_map.?.root(Sha256)));
            }
            try expect_round_trip(&opening);
        }
    }

    var empty = try TestMatrix.empty(gpa);
    defer empty.deinit();
    try testing.expect(empty.is_empty());
    var opening = try empty.open(gpa, &keys[0], &keys[1]);
    defer opening.deinit(gpa);
    const empty_root = empty.root();
    const paid = try opening.verify(Sha256, &empty_root, &keys[0], &keys[1]);
    try testing.expectEqual(@as(u64, 0), paid);
}

// An opening verifies with an entry from the sender's own row exactly when the sender has a
// row, and an opening of a payment verifies only under its own root and for its own pair.
test "matrix: rejects inconsistent openings" {
    const keys = t.accounts(4);
    const specs = [_]RowSpec{
        .{ .sender = 1, .pays = &.{.{ 0, 5 }} },
        .{ .sender = 3, .pays = &.{.{ 0, 1 }} },
    };
    var value = try matrix(&keys, &specs);
    defer value.deinit();
    const root = value.root();

    // A sender with a row must open the receiver's entry, and a sender without one must not.
    var present = try value.open(gpa, &keys[1], &keys[0]);
    defer present.deinit(gpa);
    var absent = try value.open(gpa, &keys[2], &keys[0]);
    defer absent.deinit(gpa);
    const without_entry: TestOpening = .{ .row = present.row, .entry = null };
    try testing.expectError(
        error.InvalidOpening,
        without_entry.verify(Sha256, &root, &keys[1], &keys[0]),
    );
    const with_entry: TestOpening = .{ .row = absent.row, .entry = present.entry };
    try testing.expectError(
        error.InvalidOpening,
        with_entry.verify(Sha256, &root, &keys[2], &keys[0]),
    );

    // A sender that pays cannot be shown to have no row by opening only the row before it.
    var proof = try value.inner.tree.proof(gpa, 0, null);
    defer proof.deinit(gpa);
    const forged: TestOpening = .{
        .row = .{ .non_member = .{
            .position = 1,
            .lower = value.rows()[0],
            .upper = null,
            .proof = proof,
        } },
        .entry = null,
    };
    try testing.expectError(error.InvalidOpening, forged.verify(Sha256, &root, &keys[3], &keys[0]));

    // The entry must open under the sender's own row.
    var other = try value.open(gpa, &keys[3], &keys[0]);
    defer other.deinit(gpa);
    const swapped: TestOpening = .{ .row = present.row, .entry = other.entry };
    try testing.expectError(
        error.InvalidOpening,
        swapped.verify(Sha256, &root, &keys[1], &keys[0]),
    );

    // An opening of a payment verifies only under its own root and for its own pair.
    var empty = try TestMatrix.empty(gpa);
    defer empty.deinit();
    const other_root = empty.root();
    const Error = error{InvalidOpening};
    const cases = [_]Error!u64{
        present.verify(Sha256, &other_root, &keys[1], &keys[0]),
        present.verify(Sha256, &root, &keys[3], &keys[0]),
        present.verify(Sha256, &root, &keys[1], &keys[2]),
    };
    for (cases) |result| try testing.expectError(error.InvalidOpening, result);
}

// The allocation-free matrix root matches the tree the matrix builds.
test "matrix: root matches the tree" {
    const keys = t.accounts(4);
    const specs = [_]RowSpec{
        .{ .sender = 0, .pays = &.{.{ 1, 5 }} },
        .{ .sender = 2, .pays = &.{ .{ 0, 1 }, .{ 3, 9 } } },
        .{ .sender = 3, .pays = &.{.{ 2, 4 }} },
    };
    var value = try matrix(&keys, &specs);
    defer value.deinit();
    var senders: [3]PublicKey = undefined;
    var roots: [3]Digest = undefined;
    for (value.rows(), &senders, &roots) |row, *sender, *payments_root| {
        sender.* = row[0];
        payments_root.* = row[1];
    }
    const streamed = matrix_module.root(Sha256, PublicKey, &senders, &roots);
    try testing.expect(streamed.eql(value.root()));
    var empty = try TestMatrix.empty(gpa);
    defer empty.deinit();
    try testing.expect(matrix_module.root(Sha256, PublicKey, &.{}, &.{}).eql(empty.root()));
}
