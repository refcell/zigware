//! commonware `glue/src/stateful/db/current.rs` tests, over `current` databases of SHA-256
//! keys and values with a `TwoCap` index and 64-byte chunks: commonware's `FixedDb`, and the
//! variable-encoded and ordered databases (`VariableDb`, `OrderedFixedDb`,
//! `OrderedVariableDb`).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const current_mod = @import("current.zig");
const state_sync = @import("state_sync.zig");
const sync = @import("sync.zig");

const qmdb = storage.qmdb;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const operation = qmdb.any.operation;
const metrics = runtime.telemetry.metrics;
const contiguous = storage.journal.contiguous;
const UnorderedIndex = storage.index.unordered.Index(storage.translator.TwoCap, u64);
const OrderedIndex = storage.index.ordered.Index(storage.translator.TwoCap, u64);

/// A `current` database over `Digest` keys and `E`-encoded values, ordered or not.
fn Database(comptime ordered: bool, comptime E: type) type {
    const Operation = if (ordered) operation.Ordered else operation.Unordered;
    const Update = if (ordered) operation.update.Ordered else operation.update.Unordered;
    const Op = Operation(Family, Digest, E);
    const Journal = if (E.fixed) contiguous.fixed.Journal(Op) else contiguous.variable.Journal(Op);
    const Index = if (ordered) OrderedIndex else UnorderedIndex;
    const Inner = qmdb.current.Db(Family, Update(Digest, E), Journal, Index, Sha256, 64);
    return current_mod.Current(Inner);
}

const FixedDb = Database(false, qmdb.value.Fixed(Digest));
const OrderedFixedDb = Database(true, qmdb.value.Fixed(Digest));
const variants = .{
    FixedDb,
    Database(false, qmdb.value.Variable(Digest)),
    OrderedFixedDb,
    Database(true, qmdb.value.Variable(Digest)),
};

/// The codec configuration of a test operation: units stay units, and slices (a field
/// `range`) are bounded to 10000 items. Configurations nest at most one tuple deep.
fn codec_config(comptime C: type) C {
    if (comptime is_slice_cfg(C) or C == void) return leaf_config(C);
    var result: C = undefined;
    inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
        result[index] = leaf_config(field_type);
    }
    return result;
}

fn is_slice_cfg(comptime C: type) bool {
    return @typeInfo(C) == .@"struct" and @hasField(C, "range");
}

fn leaf_config(comptime C: type) C {
    if (comptime is_slice_cfg(C)) return .{ .range = .inclusive(0, 10000) };
    return codec.unit_cfg(C);
}

fn log_config(
    comptime LogCfg: type,
    comptime suffix: []const u8,
    cache_ref: *runtime.buffer.paged.CacheRef,
) LogCfg {
    const partition = "stateful-current-log-" ++ suffix;
    if (comptime @hasField(LogCfg, "items_per_section")) return .{
        .partition = partition,
        .items_per_section = 7,
        .codec_config = codec_config(@FieldType(LogCfg, "codec_config")),
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
    return .{
        .partition = partition,
        .items_per_blob = 7,
        .cache_ref = cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    };
}

/// Storage, a page cache, and metrics for opening test databases of `Current`. Each open
/// takes a distinct metrics label, as commonware's child contexts do.
fn Harness(comptime Current: type) type {
    return struct {
        const Self = @This();

        storage: runtime.buffer.mocks.Storage,
        cache_ref: runtime.buffer.paged.CacheRef,
        registry: metrics.Registry,

        fn init(harness: *Self) !void {
            harness.* = .{
                .storage = .init(testing.allocator),
                .cache_ref = try .init(testing.allocator, 101, 11),
                .registry = metrics.Registry.init(testing.allocator),
            };
        }

        fn deinit(harness: *Self) void {
            harness.registry.deinit();
            harness.cache_ref.deinit();
            harness.storage.deinit();
        }

        fn env(harness: *Self, label: []const u8) db.Env {
            return .{
                .gpa = testing.allocator,
                .io = testing.io,
                .storage = harness.storage.interface(),
                .scope = metrics.Scope.init(&harness.registry).child(label),
            };
        }

        /// commonware's `fixed_config(suffix)` and `variable_config(suffix)`.
        fn config(harness: *Self, comptime suffix: []const u8) Current.Config {
            const LogCfg = @FieldType(Current.Config, "log");
            return .{
                .merkle = .{
                    .journal_partition = "stateful-current-journal-" ++ suffix,
                    .metadata_partition = "stateful-current-metadata-" ++ suffix,
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &harness.cache_ref,
                },
                .log = log_config(LogCfg, suffix, &harness.cache_ref),
                .grafted_metadata_partition = "stateful-current-grafted-" ++ suffix,
                .translator = .{},
                .init_cache = 1024,
            };
        }

        fn open(
            harness: *Self,
            label: []const u8,
            comptime suffix: []const u8,
            expected: ?Current.SyncTarget,
        ) !Current.Shared {
            return Current.Shared.open(harness.env(label), harness.config(suffix), expected);
        }
    };
}

fn hash(text: []const u8) Digest {
    return Sha256.hash(&.{text});
}

fn hash_u64(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

fn apply_and_finalize(shared: anytype, batch: anytype) !void {
    try shared.apply(batch);
    const barrier = try shared.finalize();
    try barrier.durable();
}

/// A batch over `shared` writing `key` = `value` with `metadata`.
fn write_one(shared: anytype, key: Digest, value: Digest) !@TypeOf(shared).Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    try batch.write(key, value);
    batch.with_metadata(hash("metadata"));
    return batch.merkleize();
}

test "stateful current: a managed db applies a batch and proves its value" {
    inline for (variants) |Current| try a_managed_db_applies_a_batch_and_proves_its_value(Current);
}

fn a_managed_db_applies_a_batch_and_proves_its_value(comptime Current: type) !void {
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "managed-db", null);
    defer shared.deinit();

    const key = hash("key");
    const value = hash("value");
    var merkleized = try write_one(shared, key, value);
    defer merkleized.deinit();
    const expected_root = merkleized.root();
    try testing.expect(!expected_root.eql(merkleized.ops_root()));
    try apply_and_finalize(shared, &merkleized);

    // Proofs hash through the journal (`*Db`), so they hold the database exclusively.
    var slot = try shared.write();
    defer slot.put();
    const inner = &slot.get().inner;
    try testing.expect(inner.root().eql(expected_root));
    try testing.expectEqual(value, (try inner.get(&key)).?);
    var proved = try inner.key_value_proof(&key);
    defer proved.deinit(testing.allocator);
    try testing.expectEqual(value, proved.value);
    const root = inner.root();
    try testing.expect(Current.Database.verify_key_value_proof(&proved.proof, key, value, &root));
    const other = hash("other");
    try testing.expect(!Current.Database.verify_key_value_proof(&proved.proof, key, other, &root));
    try testing.expectError(error.KeyNotFound, inner.key_value_proof(&hash("missing")));
}

test "stateful current: matches_sync_target rejects a wrong ops root and range" {
    inline for (variants) |Current| try rejects_wrong_ops_root_and_range(Current);
}

fn rejects_wrong_ops_root_and_range(comptime Current: type) !void {
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "matches-sync-target", null);
    defer shared.deinit();
    var merkleized = try write_one(shared, hash("key"), hash("value"));
    defer merkleized.deinit();

    const verification_config = harness.config("matches-sync-target-verification");
    var verification = try Current.init(harness.env("verification"), verification_config, null);
    defer verification.deinit();
    try verification.inner.apply_batch(merkleized.inner);
    try verification.inner.sync();

    const valid = verification.sync_target();
    try testing.expect(Current.matches_sync_target(&merkleized, &valid));
    // The target commits to the ops root, not the canonical root.
    try testing.expect(valid.root.eql(merkleized.ops_root()));

    var wrong_root = valid;
    wrong_root.root = hash("wrong ops root");
    try testing.expect(!Current.matches_sync_target(&merkleized, &wrong_root));
    var canonical_root = valid;
    canonical_root.root = merkleized.root();
    try testing.expect(!Current.matches_sync_target(&merkleized, &canonical_root));
    var wrong_end = valid;
    wrong_end.end += 1;
    try testing.expect(!Current.matches_sync_target(&merkleized, &wrong_end));
    var wrong_start = valid;
    wrong_start.start += 1;
    try testing.expect(!Current.matches_sync_target(&merkleized, &wrong_start));
}

test "stateful current: staged merkleize matches explicit writes" {
    inline for (variants) |Current| try staged_merkleize_matches_explicit_writes(Current);
}

/// Seeds keys 0..50 and persists them.
fn seed_keys(shared: anytype) !void {
    var seed = try shared.new_batches();
    errdefer seed.deinit();
    for (0..50) |i| try seed.write(hash_u64(i), hash_u64(i + 10_000));
    var merkleized = try seed.merkleize();
    defer merkleized.deinit();
    try apply_and_finalize(shared, &merkleized);
}

/// Metadata set before staging carries through to the staged merkleize.
fn expect_carried_metadata(
    comptime Current: type,
    shared: Current.Shared,
    keys: *const [3]Digest,
    slots: []const Current.Slot,
    unstaged: []const Current.Mutation,
    metadata: Digest,
    explicit: struct { *const [3]?Digest, Digest },
) !void {
    var carried_values: [3]?Digest = undefined;
    var batch = try shared.new_batches();
    batch.with_metadata(metadata);
    var staged = batch.stage(keys, &carried_values) catch |err| {
        batch.deinit();
        return err;
    };
    var carried = try staged.merkleize(slots, unstaged);
    defer carried.deinit();
    try testing.expectEqualSlices(?Digest, explicit[0], &carried_values);
    try testing.expect(explicit[1].eql(carried.root()));
}

fn staged_merkleize_matches_explicit_writes(comptime Current: type) !void {
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "glue-staged", null);
    defer shared.deinit();
    const metadata = hash("metadata");

    try seed_keys(shared);

    // Read set: key 1 updated, key 2 deleted, key 999 missing and created.
    const keys = [_]Digest{ hash_u64(1), hash_u64(2), hash_u64(999) };
    const slots = [_]Current.Slot{
        .{ .put = hash_u64(11_000) }, .delete, .{ .put = hash_u64(11_001) },
    };
    const unstaged = [_]Current.Mutation{.{ .key = hash_u64(3), .value = hash_u64(11_002) }};

    // Explicit path.
    var explicit_values: [keys.len]?Digest = undefined;
    const explicit_root = explicit: {
        var batch = try shared.new_batches();
        errdefer batch.deinit();
        try batch.get_many(&keys, &explicit_values);
        for (keys, slots) |key, slot| try batch.write(key, switch (slot) {
            .put => |value| value,
            .delete => null,
            .keep => unreachable, // Every staged read is written.
        });
        for (unstaged) |m| try batch.write(m.key, m.value);
        batch.with_metadata(metadata);
        var merkleized = try batch.merkleize();
        defer merkleized.deinit();
        break :explicit merkleized.root();
    };
    try testing.expectEqual(hash_u64(10_001), explicit_values[0].?);
    try testing.expectEqual(null, explicit_values[2]);

    // Staged path in two reads, with metadata set on the staged handle.
    var staged_values: [keys.len]?Digest = undefined;
    {
        var batch = try shared.new_batches();
        var staged = batch.stage(keys[0..2], staged_values[0..2]) catch |err| {
            batch.deinit();
            return err;
        };
        var merkleized = merkleized: {
            errdefer staged.deinit();
            const range = try staged.expand(keys[2..], staged_values[2..]);
            try testing.expectEqual(2, range.start);
            try testing.expectEqual(keys.len, range.end);
            try testing.expectEqual(keys.len, staged.len());
            try testing.expect(!staged.is_empty());
            staged.with_metadata(metadata);
            break :merkleized try staged.merkleize(&slots, &unstaged);
        };
        defer merkleized.deinit();
        try testing.expectEqualSlices(?Digest, &explicit_values, &staged_values);
        try testing.expect(explicit_root.eql(merkleized.root()));
    }

    try expect_carried_metadata(Current, shared, &keys, &slots, &unstaged, metadata, .{
        &explicit_values,
        explicit_root,
    });
}

test "stateful current: bounded initialization discards later targets durably" {
    inline for (variants) |Current| try bounded_init_discards_later_targets(Current);
}

fn bounded_init_discards_later_targets(comptime Current: type) !void {
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    var first: Current.SyncTarget = undefined;
    var second: Current.SyncTarget = undefined;
    {
        const shared = try harness.open("db", "bounded-init", null);
        defer shared.deinit();
        var a = try write_one(shared, hash("key1"), hash("value1"));
        defer a.deinit();
        try apply_and_finalize(shared, &a);
        first = try shared.committed_targets();
        var b = try write_one(shared, hash("key2"), hash("value2"));
        defer b.deinit();
        try apply_and_finalize(shared, &b);
        second = try shared.committed_targets();
    }
    try testing.expect(!db.targets_eql(Current.SyncTarget, &first, &second));

    // Reopening at the first target discards the second, durably.
    {
        const bounded = try harness.open("bounded", "bounded-init", first);
        defer bounded.deinit();
        const reopened = try bounded.committed_targets();
        try testing.expect(db.targets_eql(Current.SyncTarget, &first, &reopened));
    }
    const unbounded = try harness.open("unbounded", "bounded-init", null);
    const recovered = try unbounded.committed_targets();
    unbounded.deinit();
    try testing.expect(db.targets_eql(Current.SyncTarget, &first, &recovered));

    // The discarded second target cannot be restored, and the rejection leaves the first.
    try testing.expectError(error.TargetMismatch, harness.open("second", "bounded-init", second));
    const restart = try harness.open("restart", "bounded-init", null);
    defer restart.deinit();
    const restarted = try restart.committed_targets();
    try testing.expect(db.targets_eql(Current.SyncTarget, &first, &restarted));
}

test "stateful current: pruning keeps retained targets initializable" {
    inline for (variants) |Current| try pruning_keeps_retained_targets_initializable(Current);
}

fn pruning_keeps_retained_targets_initializable(comptime Current: type) !void {
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    var targets: [4]Current.SyncTarget = undefined;
    {
        const shared = try harness.open("db", "prune-recovery-window", null);
        defer shared.deinit();
        // Four generations rewrite the same keys. H1 through H3 are durable, and H4 is applied
        // without a barrier of its own when the prune to H2 runs.
        for (0..4) |generation| {
            var batch = try shared.new_batches();
            errdefer batch.deinit();
            for (0..384) |i| {
                var value: [8]u8 = undefined;
                std.mem.writeInt(u64, &value, generation * 1_000 + i, .little);
                try batch.write(hash_u64(i), Sha256.hash(&.{&value}));
            }
            var merkleized = try batch.merkleize();
            defer merkleized.deinit();
            try shared.apply(&merkleized);
            if (generation < 3) try (try shared.finalize()).durable();
            targets[generation] = try shared.committed_targets();
        }
        // The pruned target starts a whole chunk above zero, so the prune moves the bitmap.
        try testing.expect(targets[1].start > 0);
        try shared.prune(&targets[1]);
    }

    // An unbounded reopen recovers H4, which the prune committed.
    {
        const reopened = try harness.open("reopen", "prune-recovery-window", null);
        defer reopened.deinit();
        const recovered = try reopened.committed_targets();
        try testing.expect(db.targets_eql(Current.SyncTarget, &targets[3], &recovered));
    }
    // H3 and H2 stay inside the retained window, so bounded initialization at either succeeds.
    const labels = [_][]const u8{ "h3", "h2" };
    for (labels, [_]usize{ 2, 1 }) |label, index| {
        const bounded = try harness.open(label, "prune-recovery-window", targets[index]);
        defer bounded.deinit();
        const recovered = try bounded.committed_targets();
        try testing.expect(db.targets_eql(Current.SyncTarget, &targets[index], &recovered));
    }
}

fn applies_batch_and_proves_exclusion(comptime Current: type) !void {
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    const shared = try harness.open("db", "ordered-managed-db", null);
    defer shared.deinit();
    const key = hash("key");
    const value = hash("value");
    const missing = hash("missing");
    var merkleized = try write_one(shared, key, value);
    defer merkleized.deinit();
    const expected_root = merkleized.root();
    try apply_and_finalize(shared, &merkleized);

    // Proofs hash through the journal (`*Db`), so they hold the database exclusively.
    var slot = try shared.write();
    defer slot.put();
    const inner = &slot.get().inner;
    const root = inner.root();
    try testing.expect(root.eql(expected_root));
    try testing.expectEqual(value, (try inner.get(&key)).?);
    var proof = try inner.exclusion_proof(&missing);
    defer proof.deinit(testing.allocator);
    try testing.expect(Current.Database.verify_exclusion_proof(&proof, missing, &root));
    try testing.expect(!Current.Database.verify_exclusion_proof(&proof, key, &root));
    try testing.expectError(error.KeyExists, inner.exclusion_proof(&key));
}

test "stateful current: an ordered managed db applies a batch and proves exclusion" {
    // commonware `ordered_fixed_managed_db_applies_batch_and_proves_exclusion` and
    // `ordered_variable_managed_db_applies_batch_and_proves_exclusion`.
    try applies_batch_and_proves_exclusion(OrderedFixedDb);
    try applies_batch_and_proves_exclusion(variants[3]);
}

test "stateful current: every adapter implements StateSyncDb" {
    // commonware `ordered_current_db_trait_impls_compile` and
    // `variable_current_db_trait_impls_compile`.
    comptime {
        for (variants) |Current| state_sync.assert_state_sync_db(Current);
    }
}

/// Syncs a fresh `Current` (own storage and page cache) from a populated one served through
/// its `sync_source`, with no later tips; the target commits to the ops root.
fn syncs_from_populated(comptime Current: type) !void {
    var source_harness: Harness(Current) = undefined;
    try source_harness.init();
    defer source_harness.deinit();
    const source = try source_harness.open("source", "sync-source", null);
    defer source.deinit();
    try seed_keys(source);
    const target = try source.committed_targets();

    // Serving reads the journal through `*Log`, so it holds the database exclusively.
    var slot = try source.write();
    defer slot.put();
    var log_source = slot.get().sync_source();
    var harness: Harness(Current) = undefined;
    try harness.init();
    defer harness.deinit();
    const Tip = sync.TipUpdate(Digest, Current.SyncTarget);
    var tips = try utils.channel.ring.channel(Tip, testing.allocator, testing.io, 1);
    tips.sender.deinit();
    const start: sync.Anchor(Digest) = .{
        .height = .new(1),
        .round = .new(.zero(), .new(1)),
        .digest = .{ .bytes = @splat(1) },
    };
    const synced = try state_sync.sync_shared(
        Current,
        Digest,
        harness.env("synced"),
        harness.config("sync-target"),
        &log_source,
        start,
        target,
        tips.receiver,
        .{ .fetch_batch_size = 3, .apply_batch_size = 2, .max_outstanding_requests = 2 },
    );
    defer synced.databases.deinit();
    const reached = try synced.databases.committed_targets();
    try testing.expect(db.targets_eql(Current.SyncTarget, &reached, &target));
    var batch = try synced.databases.new_batches();
    defer batch.deinit();
    try testing.expectEqual(hash_u64(10_007), (try batch.get(&hash_u64(7))).?);
}

test "stateful current: a database syncs from a populated one" {
    inline for (variants) |Current| try syncs_from_populated(Current);
}

/// Storage that keeps unsynced writes and drops unsynced resizes at a crash, with one
/// fixed-database operation per page so a bounded initialization truncates page aligned.
const CrashHarness = struct {
    const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);
    /// Operations the journal write buffer holds.
    const capacity: u64 = 4;
    const op_size: usize = codec.fixed_size(FixedDb.Database.Operation).?;

    memory: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    faulty: Faulty,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(self: *CrashHarness) !void {
        self.memory = .init(testing.allocator);
        self.rng = .init(0);
        self.faulty = .init(testing.allocator, &self.memory, &self.rng, .{
            .write_rate = .{ .failure_rate = .zero, .retention_rate = .one, .mode = .prefix },
            .resize_rate = .{ .failure_rate = .zero, .partial_rate = .zero },
        });
        self.cache_ref = try .init(testing.allocator, @intCast(op_size), 11);
        self.registry = metrics.Registry.init(testing.allocator);
    }

    fn deinit(self: *CrashHarness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.faulty.deinit();
        self.memory.deinit();
    }

    /// A buffer of `capacity` pages keeps an append of at most `capacity` operations in
    /// memory; a larger append writes every page to the blob at once. One blob keeps the
    /// applied batch over the discarded second target's bytes.
    fn config(self: *CrashHarness) FixedDb.Config {
        var result = harness_config(self);
        result.log.write_buffer = capacity * op_size;
        result.log.items_per_blob = 1000;
        result.merkle.items_per_blob = 1000;
        return result;
    }

    fn harness_config(self: *CrashHarness) FixedDb.Config {
        const suffix = "bounded-init-crash";
        return .{
            .merkle = .{
                .journal_partition = "stateful-current-journal-" ++ suffix,
                .metadata_partition = "stateful-current-metadata-" ++ suffix,
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = log_config(@FieldType(FixedDb.Config, "log"), suffix, &self.cache_ref),
            .grafted_metadata_partition = "stateful-current-grafted-" ++ suffix,
            .translator = .{},
            .init_cache = 1024,
        };
    }

    fn open(
        self: *CrashHarness,
        label: []const u8,
        expected: ?FixedDb.SyncTarget,
    ) !FixedDb.Shared {
        const env: db.Env = .{
            .gpa = testing.allocator,
            .io = testing.io,
            .storage = self.faulty.storage(),
            .scope = metrics.Scope.init(&self.registry).child(label),
        };
        return FixedDb.Shared.open(env, self.config(), expected);
    }

    /// Loses everything unsynced, as the process dying would.
    fn crash(self: *CrashHarness) !void {
        try self.faulty.crash();
        self.memory.crash();
    }
};

/// Batch `id` writes `writes` keys and metadata that no other batch uses.
fn crash_batch(shared: FixedDb.Shared, id: u8, writes: u8) !FixedDb.Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    for (0..writes) |i| {
        const tag = [_]u8{ id, @intCast(i) };
        try batch.write(Sha256.hash(&.{ "key", &tag }), Sha256.hash(&.{ "value", &tag }));
    }
    batch.with_metadata(Sha256.hash(&.{ "metadata", &[_]u8{id} }));
    return batch.merkleize();
}

const CrashTargets = struct {
    first: FixedDb.SyncTarget,
    second: FixedDb.SyncTarget,
    applied: FixedDb.SyncTarget,
};

/// Reopens at the first target (initialization syncs the truncated journal before
/// returning) and applies a batch of `writes` keys without finalizing.
fn apply_over_discarded(
    harness: *CrashHarness,
    result: *CrashTargets,
    writes: u8,
    written: bool,
) !void {
    // Initialization at the first target syncs the truncated journal before returning.
    const bounded = try harness.open("bounded", result.first);
    defer bounded.deinit();
    const reopened = try bounded.committed_targets();
    try testing.expect(db.targets_eql(FixedDb.SyncTarget, &result.first, &reopened));
    // One journal append of the batch's updates, floor moves, and commit: three operations
    // for one key, six for four keys. Only the written case exceeds `capacity`.
    var merkleized = try crash_batch(bounded, 3, writes);
    defer merkleized.deinit();
    try bounded.apply(&merkleized);
    result.applied = try bounded.committed_targets();
    try testing.expect(!db.targets_eql(FixedDb.SyncTarget, &result.applied, &result.first));
    try testing.expect(result.applied.end < result.second.end);
    const ops = result.applied.end - result.first.end;
    try testing.expectEqual(written, ops > CrashHarness.capacity);
}

/// Finalizes two targets, reopens at the first, and applies a batch of `writes` keys over
/// the discarded second target's bytes without finalizing, then crashes.
fn crash_after_apply(harness: *CrashHarness, writes: u8, written: bool) !CrashTargets {
    var result: CrashTargets = undefined;
    {
        const shared = try harness.open("db", null);
        defer shared.deinit();
        // The second writes one more key than the applied batch below, so the applied batch
        // cannot cover all of its operations.
        for ([_]u8{ 1, 2 }, [_]u8{ 1, writes + 1 }) |id, count| {
            var merkleized = try crash_batch(shared, id, count);
            defer merkleized.deinit();
            try apply_and_finalize(shared, &merkleized);
            const target = try shared.committed_targets();
            if (id == 1) result.first = target else result.second = target;
        }
    }
    try testing.expect(!db.targets_eql(FixedDb.SyncTarget, &result.first, &result.second));
    try apply_over_discarded(harness, &result, writes, written);
    try harness.crash();
    return result;
}

/// commonware `managed_db_bounded_init_then_apply_crash_recovers_history`: recovery yields
/// the first target or the applied batch, as the write-buffer geometry selects; the first
/// target reopens, and the discarded second target is rejected.
fn crash_recovers_history(writes: u8, written: bool) !void {
    var harness: CrashHarness = undefined;
    try harness.init();
    defer harness.deinit();
    const targets = try crash_after_apply(&harness, writes, written);
    {
        const recovering = try harness.open("recover", null);
        defer recovering.deinit();
        const recovered = try recovering.committed_targets();
        const at_first = db.targets_eql(FixedDb.SyncTarget, &recovered, &targets.first);
        const at_applied = db.targets_eql(FixedDb.SyncTarget, &recovered, &targets.applied);
        try testing.expect(at_first or at_applied);
        // A buffered batch is dropped whole and a written one kept whole.
        try testing.expectEqual(written, at_applied);
    }
    {
        const first = try harness.open("first", targets.first);
        defer first.deinit();
        const reopened = try first.committed_targets();
        try testing.expect(db.targets_eql(FixedDb.SyncTarget, &targets.first, &reopened));
    }
    try testing.expectError(error.TargetMismatch, harness.open("second", targets.second));
    // A rejected initialization leaves the first target in place.
    const restart = try harness.open("restart", null);
    defer restart.deinit();
    const restarted = try restart.committed_targets();
    try testing.expect(db.targets_eql(FixedDb.SyncTarget, &targets.first, &restarted));
}

test "stateful current: a buffered applied batch is lost at a crash after bounded init" {
    try crash_recovers_history(1, false);
}

test "stateful current: a written applied batch survives a crash after bounded init" {
    try crash_recovers_history(4, true);
}
