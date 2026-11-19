//! Tests of the `current` database over owned byte values (`Vec<u8>`, commonware's
//! `current/{unordered,ordered}/variable.rs` value type, as its benches use): batches own the
//! values they are given, the floor walk moves owned values, and every read and proof hands
//! the caller what it owns. The leak-checking allocator catches any slip. Every scenario runs
//! unordered and ordered, under both families.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const verification = @import("verification.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Bytes = []const u8;
const key = support.to_digest;
const databases = .{
    support.UnorderedBytes(merkle.mmr.Family),
    support.UnorderedBytes(merkle.mmb.Family),
    support.OrderedBytes(merkle.mmr.Family),
    support.OrderedBytes(merkle.mmb.Family),
};
const key_count = 20;

/// What a test expects of a value: `len` copies of `byte`.
const Shape = struct { byte: u8, len: usize };

fn shape_of(i: usize, round: usize) Shape {
    return .{ .byte = @intCast((i * 7 + round) % 251), .len = (i + round) % 6 };
}

fn make(shape: Shape) !Bytes {
    const bytes = try gpa.alloc(u8, shape.len);
    @memset(bytes, shape.byte);
    return bytes;
}

/// Checks `got` (borrowed) against `expected`.
fn expect_borrowed(expected: ?Shape, got: ?Bytes) !void {
    const want = expected orelse return testing.expectEqual(@as(?Bytes, null), got);
    try testing.expect(got != null);
    try testing.expectEqual(want.len, got.?.len);
    for (got.?) |byte| try testing.expectEqual(want.byte, byte);
}

/// Checks `got` (owned, freed here) against `expected`.
fn expect_value(expected: ?Shape, got: ?Bytes) !void {
    defer codec.free(?Bytes, gpa, got);
    try expect_borrowed(expected, got);
}

/// Writes `shape` (null deletes) to `key(i)` in `batch`.
fn write(batch: anytype, i: usize, shape: ?Shape) !void {
    const s = shape orelse return batch.write(key(i), null);
    const value = try make(s);
    errdefer gpa.free(value);
    try batch.write(key(i), value);
}

/// Applies twelve rounds of writes (a superseded write in each batch, deletes, and metadata
/// replaced twice) and returns the model they leave.
fn apply_rounds(comptime Db: type, db: *Db) ![key_count]?Shape {
    var model: [key_count]?Shape = @splat(null);
    for (0..12) |round| {
        var batch = try db.new_batch();
        const merkleized = merkleized: {
            errdefer batch.deinit();
            try write(&batch, round % key_count, shape_of(round, 1000));
            for (0..key_count) |i| {
                if ((i + round) % 3 != 0) continue;
                const shape: ?Shape = if ((i * round) % 7 == 3) null else shape_of(i, round);
                try write(&batch, i, shape);
                model[i] = shape;
            }
            try write(&batch, round % key_count, model[round % key_count]);
            batch.with_metadata(try make(.{ .byte = 9, .len = round }));
            batch.with_metadata(try make(.{ .byte = 9, .len = round % 4 }));
            break :merkleized try batch.merkleize(db);
        };
        defer merkleized.release();
        try db.apply_batch(merkleized);
    }
    return model;
}

/// Every active key's value proof verifies with the value it carries, which matches `model`.
fn expect_key_value_proofs(comptime Db: type, db: *Db, model: []const ?Shape) !void {
    const root = db.root();
    for (model, 0..) |shape, i| {
        if (shape == null) {
            try testing.expectError(error.KeyNotFound, db.key_value_proof(&key(i)));
            continue;
        }
        var proved = try db.key_value_proof(&key(i));
        defer proved.deinit(gpa);
        try expect_borrowed(shape, proved.value);
        const verify = Db.verify_key_value_proof_alloc;
        try testing.expect(try verify(gpa, &proved.proof, key(i), proved.value, &root));
        const wrong = try make(.{ .byte = shape.?.byte +% 1, .len = shape.?.len + 1 });
        defer gpa.free(wrong);
        try testing.expect(!try verify(gpa, &proved.proof, key(i), wrong, &root));
    }
}

/// Range proofs of up to four operations from every location from the sync boundary verify.
fn expect_range_proofs(comptime Db: type, db: *Db) !void {
    const root = db.root();
    var location = db.sync_boundary();
    while (location < db.bounds().end) : (location += 1) {
        var ranged = try db.range_proof(location, 4);
        defer ranged.deinit(gpa);
        var encoded: [4]Bytes = undefined;
        assert(ranged.operations.len <= encoded.len);
        var done: usize = 0;
        defer for (encoded[0..done]) |bytes| gpa.free(bytes);
        for (ranged.operations, 0..) |op, i| {
            encoded[i] = try codec.encode(Db.Operation, gpa, op);
            done += 1;
        }
        var chunks: [2]Bytes = undefined;
        assert(ranged.chunks.len <= chunks.len);
        for (ranged.chunks, 0..) |*chunk, i| chunks[i] = chunk;
        const ops = encoded[0..done];
        const used = chunks[0..ranged.chunks.len];
        const ok = verification.verify_range(
            Db.Family,
            Sha256,
            &ranged.proof,
            location,
            ops,
            used,
            32,
            &root,
        );
        try testing.expect(ok);
    }
}

/// Exclusion proofs of every deleted key verify, and none exists for an active key.
fn expect_exclusion_proofs(comptime Db: type, db: *Db, model: []const ?Shape) !void {
    const root = db.root();
    for (model, 0..) |shape, i| {
        if (shape != null) {
            try testing.expectError(error.KeyExists, db.exclusion_proof(&key(i)));
            continue;
        }
        var proof = try db.exclusion_proof(&key(i));
        defer proof.deinit(gpa);
        try testing.expect(try Db.verify_exclusion_proof_alloc(gpa, &proof, key(i), &root));
        const live = for (model, 0..) |other, j| {
            if (other != null) break key(j);
        } else continue;
        try testing.expect(!try Db.verify_exclusion_proof_alloc(gpa, &proof, live, &root));
    }
}

fn expect_model(comptime Db: type, db: *Db, model: []const ?Shape) !void {
    for (model, 0..) |shape, i| try expect_value(shape, try db.get(&key(i)));
    try expect_value(.{ .byte = 9, .len = 11 % 4 }, try db.get_metadata());
    try expect_key_value_proofs(Db, db, model);
    try expect_range_proofs(Db, db);
    if (comptime Db.Any.Update.siblings) try expect_exclusion_proofs(Db, db, model);
}

test "current owned values: rounds of writes, proofs, prune, and reopen" {
    inline for (databases) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        errdefer db.deinit();
        const model = try apply_rounds(Db, &db);
        // The floor moved past the first rounds, so their updates were rewritten at the tip.
        try testing.expect(db.inactivity_floor() > key_count);
        try expect_model(Db, &db, &model);
        try db.prune(db.sync_boundary());
        try expect_model(Db, &db, &model);
        try db.sync();
        const root = db.root();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(root));
        try expect_model(Db, &db, &model);
        try db.destroy();
    }
}
