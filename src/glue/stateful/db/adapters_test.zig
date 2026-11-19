//! commonware `glue/src/stateful/db/mod.rs`'s cross-adapter rstests:
//! `merkleize_stale_batch_returns_error` (6 cases) and
//! `initial_sync_target_and_empty_apply_match_initialized_database` (14 cases), each case one
//! adapter over a fresh storage.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const any_mod = @import("any.zig");
const current_mod = @import("current.zig");
const immutable = @import("immutable.zig");
const keyless = @import("keyless.zig");
const compact = @import("compact.zig");

const qmdb = storage.qmdb;
const contiguous = storage.journal.contiguous;
const operation = qmdb.any.operation;
const metrics = runtime.telemetry.metrics;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const U64 = utils.sequence.U64;
const Bytes = []const u8;
const TwoCap = storage.translator.TwoCap;
const gpa = testing.allocator;

fn Journal(comptime E: type, comptime Op: type) type {
    return if (E.fixed) contiguous.fixed.Journal(Op) else contiguous.variable.Journal(Op);
}

/// An `any` (`current` when `is_current`) adapter over digest values.
fn Keyed(comptime is_current: bool, comptime ordered: bool, comptime E: type) type {
    const Operation = if (ordered) operation.Ordered else operation.Unordered;
    const Update = if (ordered) operation.update.Ordered else operation.update.Unordered;
    const Index = storage.index;
    const I = if (ordered) Index.ordered.Index(TwoCap, u64) else Index.unordered.Index(TwoCap, u64);
    const J = Journal(E, Operation(Family, Digest, E));
    if (is_current) {
        return current_mod.Current(qmdb.current.Db(Family, Update(Digest, E), J, I, Sha256, 64));
    }
    return any_mod.Any(qmdb.any.Db(Family, Update(Digest, E), J, I, Sha256, 64), Sha256);
}

fn Immutable(comptime E: type) type {
    const J = Journal(E, qmdb.immutable.Operation(Family, Digest, E));
    return immutable.Immutable(Family, Digest, E, J, Sha256, TwoCap);
}

fn Keyless(comptime E: type) type {
    return keyless.Keyless(Family, E, Journal(E, qmdb.keyless.Operation(Family, E)), Sha256);
}

const FixedDigest = qmdb.value.Fixed(Digest);
const VariableDigest = qmdb.value.Variable(Digest);
const FixedU64 = qmdb.value.Fixed(U64);
const VariableBytes = qmdb.value.Variable(Bytes);

const AnyFixed = Keyed(false, false, FixedDigest);
const CurrentUnorderedFixed = Keyed(true, false, FixedDigest);
const ImmutableFixed = Immutable(FixedDigest);
const ImmutableCompactFixed = compact.Compact(
    Family,
    qmdb.immutable.Operation(Family, Digest, FixedDigest),
    Sha256,
);
const KeylessFixed = Keyless(FixedU64);
const KeylessCompactFixed = compact.Compact(
    Family,
    qmdb.keyless.Operation(Family, FixedU64),
    Sha256,
);

/// `merkleize_stale_batch_returns_error`'s cases.
const stale_cases = .{
    AnyFixed,
    CurrentUnorderedFixed,
    ImmutableFixed,
    ImmutableCompactFixed,
    KeylessFixed,
    KeylessCompactFixed,
};

/// `initial_sync_target_and_empty_apply_match_initialized_database`'s cases.
const initial_cases = .{
    AnyFixed,
    Keyed(false, false, VariableDigest),
    CurrentUnorderedFixed,
    Keyed(true, true, FixedDigest),
    Keyed(true, false, VariableDigest),
    Keyed(true, true, VariableDigest),
    ImmutableFixed,
    Immutable(VariableBytes),
    ImmutableCompactFixed,
    compact.Compact(Family, qmdb.immutable.Operation(Family, Digest, VariableBytes), Sha256),
    KeylessFixed,
    Keyless(VariableBytes),
    KeylessCompactFixed,
    compact.Compact(Family, qmdb.keyless.Operation(Family, VariableBytes), Sha256),
};

comptime {
    std.debug.assert(stale_cases.len == 6);
    std.debug.assert(initial_cases.len == 14);
}

/// Storage, a page cache, and metrics for one adapter's database.
const Harness = struct {
    io: std.Io,
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(harness: *Harness, io: std.Io) !void {
        harness.* = .{
            .io = io,
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

    fn open(harness: *Harness, comptime DB: type) !DB.Shared {
        const env: db.Env = .{
            .gpa = gpa,
            .io = harness.io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        };
        return DB.Shared.open(env, harness.config(DB.Config), null);
    }

    /// The configuration of any adapter, filled field by field (commonware's per-adapter
    /// `*_config("db")` helpers).
    fn config(harness: *Harness, comptime C: type) C {
        var result: C = undefined;
        inline for (@typeInfo(C).@"struct".field_names) |name| {
            const F = @FieldType(C, name);
            @field(result, name) = if (comptime std.mem.eql(u8, name, "merkle"))
                harness.merkle_config()
            else if (comptime std.mem.eql(u8, name, "log"))
                harness.log_config(F, "adapters-log")
            else if (comptime std.mem.eql(u8, name, "witness"))
                harness.log_config(F, "adapters-witness")
            else if (comptime std.mem.eql(u8, name, "grafted_metadata_partition"))
                "adapters-grafted"
            else if (comptime std.mem.eql(u8, name, "init_cache"))
                1024
            else if (comptime std.mem.eql(u8, name, "translator"))
                .{}
            else if (comptime std.mem.eql(u8, name, "codec_config"))
                codec_config(F)
            else if (comptime std.mem.eql(u8, name, "io"))
                null // Untimed.
            else
                @compileError("unknown adapter config field " ++ name);
        }
        return result;
    }

    fn merkle_config(harness: *Harness) storage.merkle.full.Config {
        return .{
            .journal_partition = "adapters-journal",
            .metadata_partition = "adapters-metadata",
            .items_per_blob = 11,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &harness.cache_ref,
        };
    }

    /// A fixed journal's or a sectioned (variable) one's configuration.
    fn log_config(harness: *Harness, comptime C: type, comptime partition: []const u8) C {
        if (comptime @hasField(C, "items_per_section")) return .{
            .partition = partition,
            .items_per_section = 7,
            .codec_config = codec_config(@FieldType(C, "codec_config")),
            .cache_ref = &harness.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
        return .{
            .partition = partition,
            .items_per_blob = 7,
            .cache_ref = &harness.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
    }
};

/// A codec configuration: units stay units, and slices (a field `range`) are bounded to
/// 10000 items. Configurations nest at most one tuple deep.
fn codec_config(comptime C: type) C {
    if (comptime is_slice_config(C) or C == void) return leaf_config(C);
    var result: C = undefined;
    inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
        result[index] = leaf_config(field_type);
    }
    return result;
}

fn is_slice_config(comptime C: type) bool {
    return @typeInfo(C) == .@"struct" and @hasField(C, "range");
}

fn leaf_config(comptime C: type) C {
    if (comptime is_slice_config(C)) return .{ .range = .inclusive(0, 10000) };
    return codec.unit_cfg(C);
}

/// Merkleizes an empty batch over the applied state.
fn empty_merkleized(comptime DB: type, shared: DB.Shared) !DB.Merkleized {
    var batch = try shared.new_batches();
    errdefer batch.deinit();
    return batch.merkleize();
}

fn expect_stale_merkleize_fails(comptime DB: type) !void {
    var harness: Harness = undefined;
    try harness.init(testing.io);
    defer harness.deinit();
    const shared = try harness.open(DB);
    defer shared.deinit();

    var stale = try shared.new_batches();
    defer stale.deinit();
    var winner = try empty_merkleized(DB, shared);
    defer winner.deinit();
    // Batch creation released the read lock, so a sibling can be applied.
    try shared.apply(&winner);
    try testing.expectError(error.StaleBatch, stale.merkleize());
    var fresh = try empty_merkleized(DB, shared);
    fresh.deinit();
}

fn expect_initial_target_and_empty_apply(comptime DB: type) !void {
    var harness: Harness = undefined;
    try harness.init(testing.io);
    defer harness.deinit();
    const initial = DB.Shared.initial_sync_targets();
    const shared = try harness.open(DB);
    defer shared.deinit();
    const committed = try shared.committed_targets();
    try testing.expect(db.targets_eql(DB.SyncTarget, &initial, &committed));

    var batch = try empty_merkleized(DB, shared);
    defer batch.deinit();
    try shared.apply(&batch);
    const barrier = try shared.finalize();
    try barrier.durable();
}

test "stateful db adapters: merkleizing a stale batch fails" {
    inline for (stale_cases) |DB| try expect_stale_merkleize_fails(DB);
}

test "stateful db adapters: the initial target matches a fresh database and an empty apply" {
    inline for (initial_cases) |DB| try expect_initial_target_and_empty_apply(DB);
}

/// Tasks over a `DB` shared database, recording when they got through.
fn Tasks(comptime DB: type) type {
    return struct {
        fn read(shared: DB.Shared, done: *bool) anyerror!void {
            var guard = try shared.read();
            defer guard.deinit();
            _ = guard.get().sync_target();
            done.* = true;
        }

        fn write(shared: DB.Shared, done: *bool) anyerror!void {
            var batch = try empty_merkleized(DB, shared);
            defer batch.deinit();
            try shared.apply(&batch);
            done.* = true;
        }
    };
}

fn guard_sharing(comptime DB: type) fn (std.Io) anyerror!void {
    return struct {
        fn body(io: std.Io) anyerror!void {
            var harness: Harness = undefined;
            try harness.init(io);
            defer harness.deinit();
            const shared = try harness.open(DB);
            defer shared.deinit();
            var first = try shared.read();
            var first_held = true;
            defer if (first_held) first.deinit();
            var reader_done = false;
            var reader = try io.concurrent(Tasks(DB).read, .{ shared, &reader_done });
            defer reader.cancel(io) catch {};
            try io.sleep(.fromMilliseconds(10), .awake);
            // A second reader shares the guard only when the database opts in.
            try testing.expectEqual(DB.Shared.concurrent, reader_done);
            var writer_done = false;
            var writer = try io.concurrent(Tasks(DB).write, .{ shared, &writer_done });
            defer writer.cancel(io) catch {};
            try io.sleep(.fromMilliseconds(10), .awake);
            // A writer waits for every reader.
            try testing.expect(!writer_done);
            first.deinit();
            first_held = false;
            try reader.await(io);
            try writer.await(io);
            try testing.expect(reader_done and writer_done);
        }
    }.body;
}

/// Runs `body` on a deterministic runtime that fails after 5 simulated seconds.
fn run_deterministic(comptime body: fn (std.Io) anyerror!void) !void {
    const timeout_ns = 5 * std.time.ns_per_s;
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = timeout_ns });
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

test "stateful db adapters: concurrent-read databases share read guards; writers wait" {
    // No adapter opts in until merkle batch reference counts are atomic (see glue.md); then
    // the qmdb variants share guards. Compact databases always serialize readers.
    comptime std.debug.assert(!KeylessCompactFixed.Shared.concurrent);
    const cases = .{
        AnyFixed,
        CurrentUnorderedFixed,
        KeylessFixed,
        ImmutableFixed,
        KeylessCompactFixed,
    };
    inline for (cases) |DB| {
        try run_deterministic(guard_sharing(DB));
    }
}

fn digest_of(tag: []const u8, i: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, i, .big);
    return Sha256.hash(&.{ tag, &bytes });
}

const stress_keys = 16;

/// Reads every key under shared guards and merkleizes batches, beside a writer.
fn Stress(comptime DB: type) type {
    return struct {
        fn reader(shared: DB.Shared) anyerror!void {
            for (0..40) |_| {
                {
                    var guard = try shared.read();
                    defer guard.deinit();
                    for (0..stress_keys) |i| {
                        const found = try guard.get().inner.get(&digest_of("key", i));
                        if (found) |value| try testing.expect(value.eql(digest_of("value", i)));
                    }
                }
                var batch = try shared.new_batches();
                errdefer batch.deinit();
                try batch.write(digest_of("reader", 0), digest_of("value", 0));
                // A writer may have applied since the batch was built.
                var merkleized = batch.merkleize() catch |err| switch (err) {
                    error.StaleBatch => {
                        batch.deinit();
                        continue;
                    },
                    else => return err,
                };
                merkleized.deinit();
            }
        }

        fn run() !void {
            const io = testing.io;
            var harness: Harness = undefined;
            try harness.init(io);
            defer harness.deinit();
            const shared = try harness.open(DB);
            defer shared.deinit();
            var readers: [4]std.Io.Future(anyerror!void) = undefined;
            var started: usize = 0;
            defer for (readers[0..started]) |*future| future.cancel(io) catch {};
            for (&readers) |*future| {
                future.* = try io.concurrent(reader, .{shared});
                started += 1;
            }
            for (0..stress_keys) |i| {
                var batch = try shared.new_batches();
                errdefer batch.deinit();
                try batch.write(digest_of("key", i), digest_of("value", i));
                var merkleized = try batch.merkleize();
                defer merkleized.deinit();
                try shared.apply(&merkleized);
            }
            for (readers[0..started]) |*future| try future.await(io);
            started = 0;
            var guard = try shared.read();
            defer guard.deinit();
            for (0..stress_keys) |i| {
                const value = (try guard.get().inner.get(&digest_of("key", i))).?;
                try testing.expect(value.eql(digest_of("value", i)));
            }
        }
    };
}

test "stateful db adapters: readers merkleize beside a writer" {
    inline for (.{ AnyFixed, CurrentUnorderedFixed }) |DB| try Stress(DB).run();
}
