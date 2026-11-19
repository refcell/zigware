//! The shared sync tests' harness (`sync/harness.zig`) for `any` and `current` databases:
//! commonware's `any/sync/tests.rs` harnesses and `current/sync/tests.rs`, which reuse them.
//! `Harness(S)` adapts the sync database `S` (`any.sync.Database` or `current.sync.Database`);
//! whether it is `current`, ordered, or holds byte values follows from its database type.
//!
//! Operations come from commonware's `create_*_ops(n, seed)`: from `TestRng::new(seed)`, a
//! random first "previous key", then for each `i` a delete of the previous key when `i` is a
//! positive multiple of 10, else an update of a random key (ordered ops also draw a next key)
//! to a random value: a digest, or 7 to 19 copies of one byte. `apply_ops` writes them in one
//! batch, then commits an empty batch carrying the metadata, as commonware's `apply_ops` does.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const sync = @import("../sync/mod.zig");
const sync_harness = @import("../sync/harness.zig");

const gpa = testing.allocator;
const TestRng = utils.TestRng;

pub fn Harness(comptime S: type) type {
    return struct {
        pub const Family = S.Family;
        pub const Sync = S;
        const Db = S.Db;
        const current = @hasField(Db, "grafted_tree");
        const Any = if (current) Db.Any else Db;
        const ordered = Any.Update.siblings;
        const bytes = Db.Value == []const u8;
        const Digest = S.Digest;
        pub const Source = sync.JournalSource(Family, Any.Log);

        comptime {
            assert(bytes or Db.Value == Digest);
            sync.database.assert_database(S);
        }

        pub fn config(fixture: *sync_harness.Fixture, suffix: []const u8) !S.Config {
            const support = @import("../test_support.zig");
            var log = support.log_config(@FieldType(S.Config, "log"), &fixture.cache_ref);
            log.partition = try fixture.partition(suffix, "log");
            var cfg: S.Config = undefined;
            cfg.merkle = .{
                .journal_partition = try fixture.partition(suffix, "journal"),
                .metadata_partition = try fixture.partition(suffix, "metadata"),
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &fixture.cache_ref,
            };
            cfg.log = log;
            cfg.translator = .{};
            cfg.init_cache = 3;
            cfg.init_concurrency = 1;
            cfg.io = null; // Untimed.
            if (comptime current) {
                cfg.grafted_metadata_partition = try fixture.partition(suffix, "grafted");
            }
            return cfg;
        }

        pub fn source(db: *Db) Source {
            return .{ .journal = if (comptime current) &db.any.log else &db.log };
        }

        pub fn ops_root(db: *const Db) Digest {
            return if (comptime current) db.ops_root() else db.root();
        }

        pub fn canonical_root(db: *const Db) Digest {
            return db.root();
        }

        /// A value as the generator draws it; byte values are `len` copies of `byte`.
        const Drawn = if (bytes) struct { byte: u8, len: u8 } else Digest;
        const Op = struct { key: Digest, value: ?Drawn, next_key: Digest = undefined };

        /// Commonware's `create_*_ops(count, seed)`, one operation at a time.
        const Ops = struct {
            rng: TestRng,
            previous: Digest,
            index: u64 = 0,

            fn init(seed: u64) Ops {
                var rng: TestRng = .init(seed);
                const previous = Digest.random(utils.rng.random(&rng));
                return .{ .rng = rng, .previous = previous };
            }

            fn next(self: *Ops) Op {
                defer self.index += 1;
                if (self.index % 10 == 0 and self.index > 0) {
                    return .{ .key = self.previous, .value = null };
                }
                const random = utils.rng.random(&self.rng);
                const key = Digest.random(random);
                // Commonware draws an ordered update's (arbitrary) next key here.
                const next_key = if (ordered) Digest.random(random) else undefined;
                const value: Drawn = if (bytes) .{
                    .len = @intCast(self.rng.next_u64() % 13 + 7),
                    .byte = @intCast(self.rng.next_u64() % 255),
                } else Digest.random(random);
                self.previous = key;
                return .{ .key = key, .value = value, .next_key = next_key };
            }
        };

        fn make(drawn: Drawn) !Db.Value {
            if (comptime !bytes) return drawn;
            const value = try gpa.alloc(u8, drawn.len);
            @memset(value, drawn.byte);
            return value;
        }

        fn sample_metadata() !Db.Value {
            if (comptime bytes) return gpa.dupe(u8, &.{42});
            return .{ .bytes = @splat(1) };
        }

        /// Merkleizes `batch` (consumed) and applies it.
        fn apply(db: *Db, batch: *Db.UnmerkleizedBatch) !void {
            const merkleized = merkleized: {
                errdefer batch.deinit();
                break :merkleized try batch.merkleize(db);
            };
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }

        pub fn apply_ops(db: *Db, seed: u64, count: u64, metadata: bool) !void {
            const before = db.bounds().end;
            var ops: Ops = .init(seed);
            var batch = try db.new_batch();
            {
                errdefer batch.deinit();
                for (0..count) |_| {
                    const op = ops.next();
                    const value = if (op.value) |v| try make(v) else null;
                    errdefer codec.free(?Db.Value, gpa, value);
                    try batch.write(op.key, value);
                }
            }
            try apply(db, &batch);
            var tail = try db.new_batch();
            {
                errdefer tail.deinit();
                tail.with_metadata(if (metadata) try sample_metadata() else null);
            }
            try apply(db, &tail);
            try db.commit();
            assert(db.bounds().end > before);
        }

        /// The operations `apply_ops(db, seed, count, _)` writes, owned by the caller.
        pub fn create_ops(seed: u64, count: u64) ![]S.Op {
            const ops = try gpa.alloc(S.Op, count);
            errdefer gpa.free(ops);
            var generator: Ops = .init(seed);
            var filled: usize = 0;
            errdefer codec.free_items(S.Op, gpa, ops[0..filled]);
            for (ops) |*op| {
                op.* = try to_operation(generator.next());
                filled += 1;
            }
            assert(filled == count);
            return ops;
        }

        fn to_operation(op: Op) !S.Op {
            const drawn = op.value orelse return .{ .delete = op.key };
            const value = try make(drawn);
            if (comptime ordered) {
                return .{ .update = .{ .key = op.key, .value = value, .next_key = op.next_key } };
            }
            return .{ .update = .{ .key = op.key, .value = value } };
        }

        pub fn prune(db: *Db, location: u64) !void {
            try db.prune(@min(location, db.sync_boundary()));
        }

        fn expect_value(want: ?Drawn, got: ?Db.Value) !void {
            defer codec.free(?Db.Value, gpa, got);
            try testing.expectEqual(want == null, got == null);
            const w = want orelse return;
            if (comptime !bytes) return testing.expect(w.eql(got.?));
            try testing.expectEqual(@as(usize, w.len), got.?.len);
            for (got.?) |byte| try testing.expectEqual(w.byte, byte);
        }

        /// Each key's last write in the operations reads back from `db`.
        pub fn expect_ops_applied(db: *Db, _: u64, seed: u64, count: u64) !void {
            var expected: std.AutoArrayHashMapUnmanaged(Digest, ?Drawn) = .empty;
            defer expected.deinit(gpa);
            var ops: Ops = .init(seed);
            for (0..count) |_| {
                const op = ops.next();
                try expected.put(gpa, op.key, op.value);
            }
            for (expected.keys(), expected.values()) |key, value| {
                try expect_value(value, try db.get(&key));
            }
        }

        pub fn expect_ops_absent(db: *Db, seed: u64, count: u64) !void {
            var ops: Ops = .init(seed);
            for (0..count) |_| {
                const op = ops.next();
                if (op.value == null) continue;
                try expect_value(null, try db.get(&op.key));
            }
        }

        pub fn expect_sample_metadata(db: *Db) !void {
            const got = try db.get_metadata();
            defer codec.free(?Db.Value, gpa, got);
            const want = try sample_metadata();
            defer codec.free(Db.Value, gpa, want);
            try testing.expect(got != null);
            if (comptime bytes) {
                try testing.expectEqualSlices(u8, want, got.?);
            } else {
                try testing.expect(want.eql(got.?));
            }
        }
    };
}
