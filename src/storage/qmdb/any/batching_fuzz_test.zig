//! The `qmdb_any_ordered_batching` fuzz target (commonware `storage/fuzz`): an ordered any
//! database driven by updates, deletes, commits with metadata, and reads under both families.
//! Each commit's metadata must read back before the next commit, reads must match the committed
//! model, and after the last commit every live key's span must link to its successor (wrapping).
//!
//! Keys come from a byte seed whose high nibble picks one of 16 `OneCap` buckets, so collisions
//! are common (commonware draws raw keys under `EightCap`).

const std = @import("std");
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const diff_mod = @import("diff.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const Model = std.AutoHashMapUnmanaged(Digest, Digest);

/// Commonware's `MAX_OPS`.
const max_operations = 25;

const Operation = union(enum) {
    update: struct { key: u8, value: u8 },
    delete: u8,
    commit: u8,
    get: u8,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        return switch (reader.int(u8) % 4) {
            0 => .{ .update = .{ .key = reader.int(u8), .value = reader.int(u8) } },
            1 => .{ .delete = reader.int(u8) },
            2 => .{ .commit = reader.int(u8) },
            3 => .{ .get = reader.int(u8) },
            else => unreachable, // Proof: `% 4` is in 0..4.
        };
    }
};

fn key_of(seed: u8) Digest {
    return support.colliding_digest(seed >> 4, seed);
}

fn value_of(seed: u8) Digest {
    return .{ .bytes = @splat(seed) };
}

fn Driver(comptime D: type) type {
    return struct {
        const Self = @This();

        harness: support.Harness,
        db: D,
        writes: std.ArrayList(support.Write) = .empty,
        model: Model = .empty,
        last_metadata: ?Digest = null,

        fn commit(self: *Self, metadata: ?Digest) !void {
            var batch = try self.db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (self.writes.items) |w| try batch.write(w.key, w.value);
                batch.with_metadata(metadata);
                break :merkleized try batch.merkleize(&self.db);
            };
            defer merkleized.release();
            try self.db.apply_batch(merkleized);
            try self.db.commit();
            for (self.writes.items) |w| {
                if (w.value) |v| {
                    try self.model.put(gpa, w.key, v);
                } else {
                    _ = self.model.remove(w.key);
                }
            }
            self.writes.clearRetainingCapacity();
        }

        fn get(self: *Self, k: *const Digest) !void {
            const got = try self.db.get(k);
            const want = self.model.get(k.*);
            try testing.expectEqual(want == null, got == null);
            if (want) |w| try testing.expect(w.eql(got.?));
        }

        /// The smallest live key above `k`, else the smallest live key (the model is not empty).
        fn successor(self: *const Self, k: *const Digest) Digest {
            var above: ?Digest = null;
            var first: ?Digest = null;
            var it = self.model.keyIterator();
            while (it.next()) |c| {
                if (first == null or diff_mod.order(Digest, c, &first.?) == .lt) first = c.*;
                if (diff_mod.order(Digest, c, k) != .gt) continue;
                if (above == null or diff_mod.order(Digest, c, &above.?) == .lt) above = c.*;
            }
            return above orelse first.?;
        }

        fn step(self: *Self, op: Operation) !void {
            switch (op) {
                .update => |u| {
                    const w: support.Write = .{ .key = key_of(u.key), .value = value_of(u.value) };
                    try self.writes.append(gpa, w);
                },
                .delete => |seed| {
                    try self.writes.append(gpa, .{ .key = key_of(seed), .value = null });
                },
                .commit => |seed| {
                    const got = try self.db.get_metadata();
                    try testing.expectEqual(self.last_metadata == null, got == null);
                    if (self.last_metadata) |m| try testing.expect(m.eql(got.?));
                    try self.commit(value_of(seed));
                    self.last_metadata = value_of(seed);
                },
                .get => |seed| try self.get(&key_of(seed)),
            }
        }

        fn run(ops: []const Operation) !void {
            var self: Self = .{ .harness = try .init(gpa), .db = undefined };
            defer self.harness.deinit();
            self.db = try self.harness.open(D, null);
            defer self.db.deinit();
            defer self.writes.deinit(gpa);
            defer self.model.deinit(gpa);
            for (ops) |op| try self.step(op);
            try self.commit(null);
            for (0..256) |seed| {
                const k = key_of(@intCast(seed));
                try self.get(&k);
                if (!self.model.contains(k)) continue;
                var span = (try self.db.get_span(&k)).?; // A live key owns a span.
                defer span.update.deinit(gpa);
                try testing.expect(span.update.key.eql(k));
                try testing.expect(span.update.next_key.eql(self.successor(&k)));
            }
        }
    };
}

fn run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var ops: [max_operations]Operation = undefined;
    var count: usize = 0;
    while (count < max_operations and !reader.done()) : (count += 1) {
        ops[count] = Operation.decode(&reader);
    }
    try Driver(support.OrderedFixed(merkle.mmr.Family)).run(ops[0..count]);
    try Driver(support.OrderedFixed(merkle.mmb.Family)).run(ops[0..count]);
}

test "fuzz qmdb_any_ordered_batching (seeded)" {
    try fuzz_bytes.seeded(128, 0x62617463, 48, run);
}

test "fuzz qmdb_any_ordered_batching" {
    try testing.fuzz({}, fuzz_bytes.smith(128, run), .{});
}
