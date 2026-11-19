//! commonware `glue/src/stateful/db/compact.rs` tests, except the state-sync ones (with
//! `state_sync.zig`). Bounded initialization runs over keyless and immutable operations, fixed
//! and variable values, and both Merkle families; the adapter tests over the fixed keyless
//! (`U64`) and immutable (SHA-256 keys and values) operations of commonware's
//! `AdapterOperation`s.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const compact = @import("compact.zig");

const qmdb = storage.qmdb;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const U64 = utils.sequence.U64;
const Bytes = []const u8;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;

/// The adapter over keyless (`keyed` false) or immutable operations of family `F`, with fixed
/// (`U64` or `Digest`) or variable (byte string) values, and how tests fill its batches.
fn Case(comptime F: type, comptime keyed: bool, comptime variable: bool) type {
    const Fixed = if (keyed) Digest else U64;
    const E = if (variable) qmdb.value.Variable(Bytes) else qmdb.value.Fixed(Fixed);
    const O = if (keyed) qmdb.immutable.Operation(F, Digest, E) else qmdb.keyless.Operation(F, E);
    return struct {
        pub const Adapter = compact.Compact(F, O, Sha256);
        const Value = Adapter.Value;

        /// commonware's `mutate(batch, seed)` of the bounded-initialization matrix (and of
        /// `AdapterOperation` for fixed values).
        fn mutate(batch: *Adapter.Unmerkleized, seed: u64) !void {
            if (keyed) {
                const value = try make_value(seed);
                errdefer codec.free(Value, gpa, value);
                try batch.set(hash_be(seed), value);
            } else {
                const value = try make_value(seed);
                errdefer codec.free(Value, gpa, value);
                try batch.append(value);
            }
        }

        /// The value made from `seed`: `U64(seed)`, `hash(seed.to_le_bytes())`, or the bytes
        /// `seed.to_le_bytes()` (owned).
        fn make_value(seed: u64) !Value {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, seed, .little);
            if (variable) return gpa.dupe(u8, &bytes);
            if (keyed) return Sha256.hash(&.{&bytes});
            return U64.init(seed);
        }

        /// Checks `got` (owned, freed here) is the value made from `seed`.
        fn expect_value(seed: u64, got: ?Value) !void {
            defer codec.free(?Value, gpa, got);
            const want = try make_value(seed);
            defer codec.free(Value, gpa, want);
            if (variable) {
                try testing.expectEqualSlices(u8, want, got.?);
            } else {
                try testing.expect(std.meta.eql(want, got.?));
            }
        }

        fn config(harness: *Harness, comptime partition: []const u8) Adapter.Config {
            return harness.config(Adapter, partition);
        }
    };
}

/// commonware's `Sha256::hash(&[&seed.to_be_bytes()])` (`immutable_key`).
fn hash_be(seed: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, seed, .big);
    return Sha256.hash(&.{&bytes});
}

/// The codec configuration of `A`'s commits: units stay units and byte strings (a field
/// `range`) are bounded to 10000 items. Configurations nest at most one tuple deep.
fn codec_config(comptime A: type) @FieldType(A.Config, "codec_config") {
    const C = @FieldType(A.Config, "codec_config");
    if (comptime leaf(C)) return leaf_config(C);
    var cfg: C = undefined;
    inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
        comptime std.debug.assert(leaf(field_type));
        cfg[index] = leaf_config(field_type);
    }
    return cfg;
}

fn leaf(comptime C: type) bool {
    return C == void or (@typeInfo(C) == .@"struct" and @hasField(C, "range"));
}

fn leaf_config(comptime C: type) C {
    if (C == void) return {};
    return .{ .range = .inclusive(0, 10000) };
}

/// Storage, a page cache, and metrics for opening test databases.
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    /// Witnesses per journal section (commonware's `compact_config` uses 64).
    items_per_section: u64 = 64,

    fn init(harness: *Harness) !void {
        harness.* = .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    fn env(harness: *Harness) db.Env {
        return .{
            .gpa = gpa,
            .io = testing.io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        };
    }

    /// commonware's `compact_config(suffix)`; the partition name must outlive the database.
    fn config(harness: *Harness, comptime A: type, comptime partition: []const u8) A.Config {
        return .{
            .witness = .{
                .partition = partition,
                .items_per_section = harness.items_per_section,
                .codec_config = {},
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .codec_config = codec_config(A),
        };
    }
};

/// Applies a batch over `inner` filled by `mutate` for each of `seeds`, with
/// `metadata(metadata_seed)` and an optional floor, then syncs it. The batch reaches the
/// database directly, as commonware's matrix drives the storage db.
fn commit_inner(
    comptime C: type,
    inner: *C.Adapter.Database,
    seeds: []const u64,
    metadata_seed: u64,
    floor: ?u64,
) !void {
    // Only `batch` is used: `mutate` and the setters never read the shared handle.
    var batch: C.Adapter.Unmerkleized = .{ .batch = try inner.new_batch(), .db = undefined };
    const merkleized = merkleized: {
        errdefer batch.batch.deinit();
        for (seeds) |seed| try C.mutate(&batch, seed);
        batch.with_metadata(try C.make_value(metadata_seed));
        if (floor) |location| batch.with_inactivity_floor(location);
        break :merkleized try batch.batch.merkleize(inner);
    };
    defer merkleized.release();
    try inner.apply_batch(merkleized);
    try inner.sync();
}

/// commonware's `bounded_initialization`: bounded initialization through `ManagedDb.init`
/// reports target mismatches, restores an exact target that then serves and verifies, and
/// fails once that target is pruned.
fn bounded_initialization(comptime C: type) !void {
    const A = C.Adapter;
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.items_per_section = 1;
    const config = C.config(&harness, "compact-initialization-matrix");

    var seed_db = try A.init(harness.env(), config, null);
    var first: A.SyncTarget = undefined;
    var latest: A.SyncTarget = undefined;
    {
        defer seed_db.deinit();
        try commit_inner(C, &seed_db.inner, &.{ 1, 2, 3 }, 11, null);
        first = seed_db.sync_target();
        try testing.expectEqual(@as(u64, 5), first.size);
        try commit_inner(C, &seed_db.inner, &.{4}, 22, 1);
        latest = seed_db.sync_target();
    }

    var wrong_root = latest;
    wrong_root.root = .{ .bytes = @splat(0xff) };
    try testing.expectError(error.TargetMismatch, A.init(harness.env(), config, wrong_root));
    {
        // The mismatch reports the latest target as recovered.
        var recovered = try A.init(harness.env(), config, null);
        defer recovered.deinit();
        try testing.expect(recovered.sync_target().eql(latest));
    }
    // A cap inside a batch selects the preceding commit, but is not an exact sync target.
    var between = first;
    between.size += 1;
    try testing.expectError(error.TargetMismatch, A.init(harness.env(), config, between));

    try expect_exact_restore(C, &harness, config, first);
    {
        var reopened = try A.init(harness.env(), config, null);
        defer reopened.deinit();
        // The exact restore durably discarded the later witness.
        try testing.expect(reopened.sync_target().eql(first));
        try commit_inner(C, &reopened.inner, &.{5}, 33, first.size - 1);
        latest = reopened.sync_target();
        try reopened.prune(&latest);
    }
    try testing.expectError(error.HistoricalFloorPruned, A.init(harness.env(), config, first));
    var restored = try A.init(harness.env(), config, latest);
    defer restored.deinit();
    try C.expect_value(33, try restored.inner.get_metadata());
}

/// Opens at `first` exactly, checks its metadata and floor, and verifies a boundary proof it
/// serves against `first`.
fn expect_exact_restore(
    comptime C: type,
    harness: *Harness,
    config: C.Adapter.Config,
    first: C.Adapter.SyncTarget,
) !void {
    const A = C.Adapter;
    var exact = try A.init(harness.env(), config, first);
    defer exact.deinit();
    try C.expect_value(11, try exact.inner.get_metadata());
    try testing.expectEqual(@as(u64, 0), exact.inner.inactivity_floor());
    const start = first.size - 1;
    var response = try exact.inner.serve(.{ .boundary = .{ .size = first.size, .start = start } });
    defer response.deinit(gpa);
    const served = response.boundary;
    const ops = [_]A.Operation{served.op};
    try testing.expect(try qmdb.verify.verify_with_pinned_nodes(
        A.Family,
        Sha256,
        A.Operation,
        gpa,
        &served.proof,
        start,
        &ops,
        served.pinned_nodes,
        &first.root,
    ));
}

test "stateful compact: bounded initialization, keyless fixed and variable" {
    inline for (.{ storage.mmr.Family, storage.mmb.Family }) |F| {
        try bounded_initialization(Case(F, false, false));
        try bounded_initialization(Case(F, false, true));
    }
}

test "stateful compact: bounded initialization, immutable fixed and variable" {
    inline for (.{ storage.mmr.Family, storage.mmb.Family }) |F| {
        try bounded_initialization(Case(F, true, false));
        try bounded_initialization(Case(F, true, true));
    }
}

/// commonware's `AdapterOperation`s: fixed keyless and immutable operations over MMR.
const adapter_cases = .{
    Case(storage.mmr.Family, false, false),
    Case(storage.mmr.Family, true, false),
};

/// A merkleized batch on `parent` (or over `shared`) filled by `mutate(seed)`, with optional
/// metadata from `metadata_seed` and floor.
fn merkleize_one(
    comptime C: type,
    shared: C.Adapter.Shared,
    parent: ?*const C.Adapter.Merkleized,
    seed: u64,
    metadata_seed: ?u64,
    floor: ?u64,
) !C.Adapter.Merkleized {
    var batch = if (parent) |link| try link.new_batch() else try shared.new_batches();
    errdefer batch.deinit();
    try C.mutate(&batch, seed);
    if (floor) |location| batch.with_inactivity_floor(location);
    if (metadata_seed) |meta| batch.with_metadata(try C.make_value(meta));
    return batch.merkleize();
}

test "stateful compact: an unset inactivity floor inherits the parent's floor" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-inherit-parent-floor-witness");
        const shared = try C.Adapter.Shared.open(harness.env(), config, null);
        defer shared.deinit();
        var parent = try merkleize_one(C, shared, null, 7, null, 1);
        defer parent.deinit();
        var child = try merkleize_one(C, shared, &parent, 8, null, null);
        defer child.deinit();
        try testing.expectEqual(@as(u64, 1), child.bounds().inactivity_floor);
    }
}

test "stateful compact: an unset inactivity floor inherits the applied floor" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-inherit-applied-floor-witness");
        const shared = try C.Adapter.Shared.open(harness.env(), config, null);
        defer shared.deinit();
        var first = try merkleize_one(C, shared, null, 7, null, 1);
        defer first.deinit();
        try shared.apply(&first);
        var next = try merkleize_one(C, shared, null, 9, null, null);
        defer next.deinit();
        try testing.expectEqual(@as(u64, 1), next.bounds().inactivity_floor);
        try shared.apply(&next);
        var guard = try shared.read();
        defer guard.deinit();
        try testing.expectEqual(@as(u64, 1), guard.get().inner.inactivity_floor());
    }
}

test "stateful compact: trait impls compile" {
    inline for (.{ false, true }) |keyed| {
        inline for (.{ false, true }) |variable| {
            comptime db.assert_managed_db(Case(storage.mmr.Family, keyed, variable).Adapter);
        }
    }
}

test "stateful compact: apply and finalize persist batches" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-managed-db-witness");
        var target: C.Adapter.SyncTarget = undefined;
        {
            const shared = try C.Adapter.Shared.open(harness.env(), config, null);
            defer shared.deinit();
            var merkleized = try merkleize_one(C, shared, null, 7, 1007, 1);
            defer merkleized.deinit();
            const expected_root = merkleized.root();
            try shared.apply(&merkleized);
            const barrier = try shared.finalize();
            try barrier.durable();

            var guard = try shared.read();
            defer guard.deinit();
            try testing.expect(guard.get().inner.root().eql(expected_root));
            try C.expect_value(1007, try guard.get().inner.get_metadata());
            target = guard.get().sync_target();
            try testing.expect(target.root.eql(expected_root));
            try testing.expectEqual(@as(u64, 3), target.size);
        }
        var reopened = try C.Adapter.init(harness.env(), config, null);
        defer reopened.deinit();
        try testing.expect(reopened.sync_target().eql(target));
        try C.expect_value(1007, try reopened.inner.get_metadata());
    }
}

test "stateful compact: apply retains each bounded initialization target" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-apply-checkpoints-witness");
        var first_target: C.Adapter.SyncTarget = undefined;
        {
            const shared = try C.Adapter.Shared.open(harness.env(), config, null);
            defer shared.deinit();
            var first = try merkleize_one(C, shared, null, 1, 1001, null);
            defer first.deinit();
            first_target = .{ .root = first.root(), .size = first.bounds().tip.size };
            try shared.apply(&first);
            var second = try merkleize_one(C, shared, null, 2, 1002, null);
            defer second.deinit();
            try shared.apply(&second);
            const barrier = try shared.finalize();
            try barrier.durable();
        }
        // Apply journals each checkpoint, so the first stays an exact target after finalize.
        var reopened = try C.Adapter.init(harness.env(), config, first_target);
        defer reopened.deinit();
        try testing.expect(reopened.sync_target().eql(first_target));
    }
}

test "stateful compact: matches_sync_target rejects a wrong size" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-matches-sync-target-witness");
        const shared = try C.Adapter.Shared.open(harness.env(), config, null);
        defer shared.deinit();
        var merkleized = try merkleize_one(C, shared, null, 7, 1007, 1);
        defer merkleized.deinit();
        const valid: C.Adapter.SyncTarget = .{
            .root = merkleized.root(),
            .size = merkleized.bounds().tip.size,
        };
        try testing.expect(C.Adapter.matches_sync_target(&merkleized, &valid));
        var wrong_size = valid;
        wrong_size.size -= 1;
        try testing.expect(!C.Adapter.matches_sync_target(&merkleized, &wrong_size));
        var wrong_root = valid;
        wrong_root.root = hash_be(1);
        try testing.expect(!C.Adapter.matches_sync_target(&merkleized, &wrong_root));
    }
}

test "stateful compact: a database set's bounded initialization persists an aligned target" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-aligned-bounded-init-witness");
        var target: C.Adapter.SyncTarget = undefined;
        {
            const shared = try C.Adapter.Shared.open(harness.env(), config, null);
            defer shared.deinit();
            var batch = try merkleize_one(C, shared, null, 1, 1001, null);
            defer batch.deinit();
            try shared.apply(&batch);
            target = try shared.committed_targets();
            const barrier = try shared.finalize();
            try barrier.durable();
        }
        const aligned = try C.Adapter.Shared.open(harness.env(), config, target);
        aligned.deinit();
        var reopened = try C.Adapter.init(harness.env(), config, null);
        defer reopened.deinit();
        try testing.expect(reopened.sync_target().eql(target));
    }
}

test "stateful compact: bounded initialization spans multiple commit ranges" {
    // commonware `managed_db_initializes_multiple_commit_ranges`.
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        const config = C.config(&harness, "stateful-compact-commit-ranges-witness");
        var targets: [3]C.Adapter.SyncTarget = undefined;
        {
            var database = try C.Adapter.init(harness.env(), config, null);
            defer database.deinit();
            // Three committed ranges, so reopening at the first spans several commits.
            for (&targets, [_]u64{ 1, 2, 3 }) |*target, seed| {
                try commit_inner(C, &database.inner, &.{seed}, seed + 1000, null);
                target.* = database.sync_target();
            }
            try testing.expect(!targets[2].eql(targets[0]));
        }
        var capped = try C.Adapter.init(harness.env(), config, targets[0]);
        defer capped.deinit();
        try testing.expect(capped.sync_target().eql(targets[0]));
        try C.expect_value(1001, try capped.inner.get_metadata());
    }
}

test "stateful compact: prune bounds bounded initialization history" {
    inline for (adapter_cases) |C| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        // One witness entry per section so pruning takes effect at entry granularity.
        harness.items_per_section = 1;
        const config = C.config(&harness, "stateful-compact-prune-witness");
        var targets: [3]C.Adapter.SyncTarget = undefined;
        {
            var database = try C.Adapter.init(harness.env(), config, null);
            defer database.deinit();
            for (&targets, [_]u64{ 1, 2, 3 }) |*target, seed| {
                try commit_inner(C, &database.inner, &.{seed}, seed + 1000, null);
                target.* = database.sync_target();
            }
            try testing.expect(!targets[0].eql(targets[1]));
            // Pruning at the second target retains it but excludes the first.
            try database.prune(&targets[1]);
        }
        {
            var capped = try C.Adapter.init(harness.env(), config, targets[1]);
            defer capped.deinit();
            try testing.expect(capped.sync_target().eql(targets[1]));
        }
        const pruned = C.Adapter.init(harness.env(), config, targets[0]);
        try testing.expectError(error.HistoricalFloorPruned, pruned);
    }
}
