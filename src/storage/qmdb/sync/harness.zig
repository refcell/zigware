//! The shared sync test harness (commonware's `qmdb/sync/harness/full.rs`): the tests every
//! database that supports sync runs, written once against a comptime harness `H`.
//! `Tests(H)` instantiates them (commonware's `sync_tests!`); a variant's sync test file
//! names them with `comptime { _ = harness.Tests(MyHarness); }`.
//!
//! `H` declares:
//! - `Family`, `Sync` (a sync `Database`, see `database.zig`, whose `db` field is an
//!   `H.Sync.Db`), and `Source` (a source serving an open `H.Sync.Db`);
//! - `config(fixture: *Fixture, suffix: []const u8) !Sync.Config`: partitions unique to
//!   `suffix`, every page cache `fixture.cache_ref`;
//! - `source(db: *Sync.Db) Source`;
//! - `apply_ops(db, seed, count, metadata: bool) !void`: applies commonware's
//!   `create_ops_seeded(count, seed)` as one batch that keeps the inactivity floor, whose
//!   commit carries the sample metadata when `metadata`;
//! - `prune(db, location) !void`: raises the floor to `location` when the database needs it,
//!   then prunes;
//! - `expect_ops_applied(db, start, seed, count) !void`: the operations of
//!   `create_ops_seeded(count, seed)`, applied as one batch at `start`, are present;
//! - `expect_ops_absent(db, seed, count) !void`: none of those operations is present;
//! - `expect_sample_metadata(db) !void`: the last commit carries the sample metadata;
//! - `create_ops(seed, count) ![]Sync.Op`: those operations themselves, owned by the caller
//!   (for the engine tests, which hand them to the engine);
//! - optionally `ops_root(db)` (else `db.root()`) and `canonical_root(db)` (else the ops
//!   root), for databases that authenticate more than their operations.
//!
//! The database is used directly for `init(gpa, storage, scope, cfg, null)`, `bounds`,
//! `sync_boundary`, `inactivity_floor`, `sync`, and `deinit`.
//!
//! Every database of one test shares the fixture's page cache (runtime's lock makes that safe
//! across the engine's fetch tasks). Sources are wrapped in `Locked`, commonware's
//! `AsyncRwLock` around a target the test advances while a client syncs from it.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");
const channel = @import("utils").channel;
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const engine_mod = @import("engine.zig");
const journal_mod = @import("journal.zig");
const source_mod = @import("source.zig");
const target_mod = @import("target.zig");

const gpa = testing.allocator;
const io = testing.io;
const metrics = runtime.telemetry.metrics;
const ring = channel.ring;

/// commonware's `PAGE_SIZE` and `PAGE_CACHE_SIZE`.
pub const page_size: u16 = 77;
pub const page_cache_size: u32 = 9;

/// Storage, the shared page cache, partition names, and a fresh metrics registry per open.
pub const Fixture = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    arena: std.heap.ArenaAllocator,
    registries: std.ArrayList(*metrics.Registry) = .empty,

    pub fn init() !Fixture {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, page_size, page_cache_size),
            .arena = .init(gpa),
        };
    }

    pub fn deinit(self: *Fixture) void {
        for (self.registries.items) |registry| {
            registry.deinit();
            gpa.destroy(registry);
        }
        self.registries.deinit(gpa);
        self.arena.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    /// The partition `name` of the database named by `suffix`.
    pub fn partition(self: *Fixture, suffix: []const u8, name: []const u8) ![]const u8 {
        assert(suffix.len > 0);
        assert(name.len > 0);
        return std.fmt.allocPrint(self.arena.allocator(), "{s}-{s}", .{ name, suffix });
    }

    /// A metrics scope of its own, as commonware gives each database a fresh context.
    pub fn scope(self: *Fixture) !metrics.Scope {
        const registry = try gpa.create(metrics.Registry);
        errdefer gpa.destroy(registry);
        registry.* = .init(gpa);
        errdefer registry.deinit();
        try self.registries.append(gpa, registry);
        assert(self.registries.items.len > 0);
        return metrics.Scope.init(registry).child("db");
    }

    /// Opens (or recovers) the database that `cfg` names.
    pub fn open(self: *Fixture, comptime H: type, cfg: H.Sync.Config) !H.Sync.Db {
        const storage = self.storage.interface();
        return H.Sync.Db.init(gpa, storage, try self.scope(), cfg, null);
    }

    /// The engine configuration of a sync into `cfg` from `source` to `target`.
    pub fn sync_config(
        self: *Fixture,
        comptime H: type,
        comptime S: type,
        cfg: H.Sync.Config,
        source: *S,
        target: TargetOf(H),
        options: Options,
    ) !engine_mod.Config(H.Sync, S) {
        assert(options.fetch_batch_size > 0);
        assert(options.max_outstanding_requests > 0);
        return .{
            .storage = self.storage.interface(),
            .scope = try self.scope(),
            .source = source,
            .target = target,
            .max_outstanding_requests = options.max_outstanding_requests,
            .fetch_batch_size = options.fetch_batch_size,
            .apply_batch_size = options.apply_batch_size,
            .db_config = cfg,
        };
    }

    /// Syncs into `cfg` from `source` to `target` (commonware's `sync::sync`).
    pub fn sync(
        self: *Fixture,
        comptime H: type,
        comptime S: type,
        cfg: H.Sync.Config,
        source: *S,
        target: TargetOf(H),
        options: Options,
    ) !H.Sync {
        const config = try self.sync_config(H, S, cfg, source, target, options);
        return engine_mod.sync(H.Sync, S, gpa, io, config);
    }
};

/// The engine knobs the shared tests vary (commonware's defaults otherwise).
pub const Options = struct {
    fetch_batch_size: u64 = 10,
    max_outstanding_requests: usize = 1,
    apply_batch_size: u64 = 1024,
};

pub fn TargetOf(comptime H: type) type {
    return target_mod.Target(H.Family, H.Sync.Digest);
}

/// A source behind a mutex the test also takes while it advances the served database
/// (commonware's `Arc<AsyncRwLock<Option<Db>>>` source).
pub fn Locked(comptime S: type) type {
    source_mod.assert_source(S);
    return struct {
        const Self = @This();
        pub const Family = S.Family;
        pub const Op = S.Op;
        pub const Digest = S.Digest;
        pub const Error = S.Error;
        const Served = source_mod.Served(source_mod.ResponseOf(S));

        inner: S,
        mutex: Io.Mutex = .init,

        pub fn serve(
            self: *Self,
            allocator: Allocator,
            request: source_mod.Request(Family),
        ) (Error || Io.Cancelable)!Served {
            try self.mutex.lock(io);
            defer self.mutex.unlock(io);
            return self.inner.serve(allocator, request);
        }
    };
}

/// A source whose every request fails (commonware's `FailSource`).
pub fn FailSource(comptime F: type, comptime O: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Family = F;
        pub const Op = O;
        pub const Digest = D;
        pub const Error = qmdb.Error;
        const Served = source_mod.Served(source_mod.Response(F, O, D));

        /// Requests served, so a test can check the source was never queried.
        served: u32 = 0,

        pub fn serve(self: *Self, _: Allocator, _: source_mod.Request(F)) Error!Served {
            self.served += 1;
            return error.KeyNotFound; // Arbitrary, as commonware's.
        }
    };
}

fn ops_root(comptime H: type, db: *const H.Sync.Db) H.Sync.Digest {
    if (comptime @hasDecl(H, "ops_root")) return H.ops_root(db);
    return db.root();
}

fn canonical_root(comptime H: type, db: *const H.Sync.Db) H.Sync.Digest {
    if (comptime @hasDecl(H, "canonical_root")) return H.canonical_root(db);
    return ops_root(H, db);
}

/// Whether the heavy cases run: everywhere but plain Debug builds.
fn heavy() bool {
    return builtin.mode != .debug or build_options.slow_tests;
}

/// commonware's 1000-operation histories, shortened in plain Debug builds.
fn history_ops() u64 {
    return if (heavy()) 1000 else 200;
}

/// The shared sync tests of harness `H` (commonware's `sync_tests!`).
pub fn Tests(comptime H: type) type {
    comptime source_mod.assert_source(H.Source);
    return struct {
        const Db = H.Sync.Db;
        const Digest = H.Sync.Digest;
        const Target = TargetOf(H);
        const Source = Locked(H.Source);
        const Fail = FailSource(H.Family, H.Sync.Op, Digest);
        const Engine = engine_mod.Engine(H.Sync, Source);

        fn locked(db: *Db) Source {
            return .{ .inner = H.source(db) };
        }

        fn target_of(db: *Db, start: u64) Target {
            return .init(ops_root(H, db), start, db.bounds().end);
        }

        /// Steps `engine` until it completes (commonware's `Engine::sync`).
        fn finish(engine: *Engine) !H.Sync {
            while (true) {
                if (try engine.step()) |synced| return synced;
            }
        }

        /// Steps `engine` while its journal holds at most `size` operations.
        fn step_past(engine: *Engine, size: u64) !void {
            while (engine.journal.size() <= size) {
                if (try engine.step()) |synced| {
                    var unexpected = synced;
                    unexpected.deinit();
                    return error.TestUnexpectedResult; // The client completed too early.
                }
            }
        }

        fn sync_case(target_ops: u64, fetch_batch_size: u64) !void {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            // Prune the target as far as its sync boundary permits and request the range
            // that begins there.
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            const target_start = target_db.bounds().end;
            try H.apply_ops(&target_db, 0, target_ops, true);
            const lower_bound = target_db.sync_boundary();
            try H.prune(&target_db, lower_bound);
            const target = target_of(&target_db, lower_bound);
            const floor = target_db.inactivity_floor();
            const canonical = canonical_root(H, &target_db);
            const client_cfg = try H.config(&fixture, "client");
            var source = locked(&target_db);
            const options: Options = .{ .fetch_batch_size = fetch_batch_size };
            const new_start = new_start: {
                var synced = try fixture.sync(H, Source, client_cfg, &source, target, options);
                defer synced.deinit();
                const got = &synced.db;
                try testing.expectEqual(target.end, got.bounds().end);
                try testing.expectEqual(lower_bound, got.bounds().start);
                try testing.expectEqual(floor, got.inactivity_floor());
                try testing.expect(ops_root(H, got).eql(target.root));
                try testing.expect(canonical_root(H, got).eql(canonical));
                try H.expect_ops_applied(got, target_start, 0, target_ops);
                // The same new operations keep both databases in step, so the client is a
                // usable continuation of the target.
                const new_start = got.bounds().end;
                try H.apply_ops(got, 1, target_ops, false);
                try H.apply_ops(&target_db, 1, target_ops, false);
                try testing.expect(ops_root(H, got).eql(ops_root(H, &target_db)));
                try H.expect_ops_applied(got, target_start, 0, target_ops);
                try H.expect_ops_applied(got, new_start, 1, target_ops);
                try got.sync();
                break :new_start new_start;
            };
            // The continued state persists across a reopen.
            var reopened = try fixture.open(H, client_cfg);
            defer reopened.deinit();
            try testing.expectEqual(target_db.bounds().end, reopened.bounds().end);
            try testing.expectEqual(target_db.inactivity_floor(), reopened.inactivity_floor());
            const reopened_root = canonical_root(H, &reopened);
            try testing.expect(reopened_root.eql(canonical_root(H, &target_db)));
            try H.expect_ops_applied(&reopened, target_start, 0, target_ops);
            try H.expect_ops_applied(&reopened, new_start, 1, target_ops);
        }

        test "sync: a client synced from the sync boundary matches and continues the target" {
            const cases = [_][2]u64{
                .{ 1, 1 },      .{ 1, 2 },       .{ 1000, 1 },    .{ 1000, 3 }, .{ 1000, 999 },
                .{ 1000, 100 }, .{ 1000, 1000 }, .{ 1000, 1001 }, .{ 10, 1 },   .{ 10, 20 },
            };
            for (cases) |case| {
                // Plain Debug builds keep one large case, shortened to `history_ops`; the rest
                // run in release builds and with -Dslow-tests.
                if (case[0] == 1000 and case[1] != 100 and !heavy()) continue;
                try sync_case(if (case[0] == 1000) history_ops() else case[0], case[1]);
            }
        }

        test "sync: an empty client synced to commits only recovers bounds, root, metadata" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            // The target applies no operations, so its history holds only commits.
            try H.apply_ops(&target_db, 0, 0, true);
            const bounds = target_db.bounds();
            const target = target_of(&target_db, bounds.start);
            var source = locked(&target_db);
            const cfg = try H.config(&fixture, "client");
            var synced = try fixture.sync(H, Source, cfg, &source, target, .{});
            defer synced.deinit();
            try testing.expectEqual(bounds.end, synced.db.bounds().end);
            try testing.expectEqual(bounds.start, synced.db.bounds().start);
            try testing.expect(ops_root(H, &synced.db).eql(target.root));
            try H.expect_sample_metadata(&synced.db);
        }

        test "sync: a synced database reopens with the target's root, bounds, operations" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            const target_start = target_db.bounds().end;
            try H.apply_ops(&target_db, 0, 10, true);
            const target = target_of(&target_db, target_db.bounds().start);
            const cfg = try H.config(&fixture, "persistence-test");
            var source = locked(&target_db);
            const expected = expected: {
                const options: Options = .{ .fetch_batch_size = 5 };
                var synced = try fixture.sync(H, Source, cfg, &source, target, options);
                defer synced.deinit();
                try testing.expect(ops_root(H, &synced.db).eql(target.root));
                try synced.db.sync();
                break :expected synced.db.bounds();
            };
            // A reopen from the same config recovers the synced state from storage alone.
            var reopened = try fixture.open(H, cfg);
            defer reopened.deinit();
            try testing.expect(ops_root(H, &reopened).eql(target.root));
            try testing.expectEqual(expected, reopened.bounds());
            try H.expect_ops_applied(&reopened, target_start, 0, 10);
        }

        test "sync: a client synced to a newer target rewinds to an older one durably" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            // The older source holds the shared base operations; the newer one extends them.
            var older_db = try fixture.open(H, try H.config(&fixture, "older-source"));
            defer older_db.deinit();
            try H.apply_ops(&older_db, 0, 10, false);
            const older = target_of(&older_db, older_db.sync_boundary());
            const older_root = canonical_root(H, &older_db);
            var newer_db = try fixture.open(H, try H.config(&fixture, "newer-source"));
            defer newer_db.deinit();
            try H.apply_ops(&newer_db, 0, 10, false);
            try H.apply_ops(&newer_db, 1, 5, false);
            const newer = target_of(&newer_db, newer_db.sync_boundary());
            const newer_root = canonical_root(H, &newer_db);
            try testing.expect(newer.end > older.end);
            const cfg = try H.config(&fixture, "client");
            const options: Options = .{ .fetch_batch_size = 5 };
            // Sync the client to the newer target first, leaving that state in its storage.
            var newer_source = locked(&newer_db);
            var synced = try fixture.sync(H, Source, cfg, &newer_source, newer, options);
            try testing.expect(canonical_root(H, &synced.db).eql(newer_root));
            synced.deinit();
            // Syncing the same storage to the older target rewinds it to the older state.
            var older_source = locked(&older_db);
            var recovered = try fixture.sync(H, Source, cfg, &older_source, older, options);
            try testing.expect(canonical_root(H, &recovered.db).eql(older_root));
            try testing.expectEqual(older.end, recovered.db.bounds().end);
            try testing.expectEqual(older.start, recovered.db.sync_boundary());
            recovered.deinit();
            // The rewind is durable, so a reopen recovers the older state.
            var reopened = try fixture.open(H, cfg);
            defer reopened.deinit();
            try testing.expect(canonical_root(H, &reopened).eql(older_root));
            try testing.expectEqual(older.end, reopened.bounds().end);
            try testing.expectEqual(older.start, reopened.sync_boundary());
        }

        /// `far` steps the client to just short of the initial target instead of just past its
        /// lower bound, so the journal always holds operations past the updated lower bound.
        fn update_during_sync_case(
            initial_ops: u64,
            additional_ops: u64,
            fetch: u64,
            far: bool,
        ) !void {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            const initial_start = target_db.bounds().end;
            try H.apply_ops(&target_db, 0, initial_ops, false);
            const initial = target_of(&target_db, target_db.sync_boundary());
            // The source is shared, so the target advances while the client syncs.
            var source = locked(&target_db);
            var updates = try ring.channel(Target, gpa, io, 1);
            defer updates.receiver.deinit();
            defer updates.sender.deinit();
            const cfg = try H.config(&fixture, "client");
            var config = try fixture.sync_config(H, Source, cfg, &source, initial, .{
                .fetch_batch_size = fetch,
                .max_outstanding_requests = 10,
            });
            config.update_rx = &updates.receiver;
            var engine: Engine = undefined;
            try engine.init(gpa, io, config);
            defer engine.deinit();
            // Step the client past the initial lower bound, so the update arrives mid-sync.
            try step_past(&engine, if (far) initial.end - 2 else initial.start);
            const additional_start = target_db.bounds().end;
            const final = final: {
                source.mutex.lockUncancelable(io);
                defer source.mutex.unlock(io);
                try H.apply_ops(&target_db, 1, additional_ops, false);
                break :final target_of(&target_db, target_db.sync_boundary());
            };
            // No step runs until `finish`, which handles the update first, so the journal holds
            // this many operations when the update resizes it.
            const size_at_update = engine.journal.size();
            if (far) try testing.expect(size_at_update > final.start);
            try testing.expect(updates.sender.send_lossy(final));
            var synced = try finish(&engine);
            defer synced.deinit();
            const got = &synced.db;
            try testing.expect(ops_root(H, got).eql(final.root));
            try testing.expectEqual(target_db.bounds().end, got.bounds().end);
            const got_start = got.bounds().start;
            try expect_updated_start(got_start, initial.start, final.start, size_at_update);
            try testing.expectEqual(target_db.inactivity_floor(), got.inactivity_floor());
            try testing.expect(canonical_root(H, got).eql(canonical_root(H, &target_db)));
            try H.expect_ops_applied(got, initial_start, 0, initial_ops);
            try H.expect_ops_applied(got, additional_start, 1, additional_ops);
        }

        /// A resize rebuilds a journal that ends at or below the new lower bound exactly there,
        /// but prunes one that holds operations past it only to a blob or section boundary, as
        /// commonware's does. commonware's deterministic runtime lands one fetch per step, so
        /// its client never passes the new bound before the update; zigware's concurrent
        /// fetches can land out of order and then apply several at once (the 9b62ab9 flake).
        fn expect_updated_start(got: u64, initial_start: u64, final_start: u64, size: u64) !void {
            if (size <= final_start) return testing.expectEqual(final_start, got);
            try testing.expect(got >= initial_start);
            try testing.expect(got <= final_start);
        }

        test "sync: a client mid-sync adopts a target update and completes at it" {
            const cases = [_][3]u64{
                .{ 1, 1, 1 },   .{ 1, 2, 1 },     .{ 1, 100, 1 },    .{ 2, 1, 1 },
                .{ 2, 2, 1 },   .{ 2, 100, 1 },   .{ 20, 10, 1 },    .{ 100, 1, 1 },
                .{ 100, 2, 1 }, .{ 100, 100, 1 }, .{ 100, 1000, 1 }, .{ 50, 25, 1 },
                .{ 50, 25, 2 },
            };
            for (cases) |case| {
                if (case[0] + case[1] > 100 and !heavy()) continue;
                try update_during_sync_case(case[0], case[1], case[2], false);
            }
        }

        test "sync: a target update below operations the client already holds completes" {
            const cases = [_][3]u64{ .{ 20, 1, 1 }, .{ 20, 10, 3 }, .{ 50, 25, 2 } };
            for (cases) |case| try update_during_sync_case(case[0], case[1], case[2], true);
        }

        test "sync: a historical target of an advanced source holds none of the later ops" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            // Record the target before the final operation, so it names a strict prefix.
            try H.apply_ops(&target_db, 0, history_ops() - 1, false);
            const target = target_of(&target_db, target_db.sync_boundary());
            const canonical = canonical_root(H, &target_db);
            // Advance the source past the target, so it serves the target from history.
            try H.apply_ops(&target_db, 2, 1, false);
            var source = locked(&target_db);
            const cfg = try H.config(&fixture, "client");
            var synced = try fixture.sync(H, Source, cfg, &source, target, .{});
            defer synced.deinit();
            try testing.expect(ops_root(H, &synced.db).eql(target.root));
            try testing.expect(canonical_root(H, &synced.db).eql(canonical));
            try testing.expectEqual(target.end, synced.db.bounds().end);
            try testing.expectEqual(target.start, synced.db.sync_boundary());
            try H.expect_ops_absent(&synced.db, 2, 1);
        }

        test "sync: a client that applied a prefix of the target completes at the target" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            const cfg = try H.config(&fixture, "client");
            // The client applies the same operations as the target, then closes unsynced.
            const original_start = target_db.bounds().end;
            try H.apply_ops(&target_db, 0, history_ops(), false);
            {
                var client_db = try fixture.open(H, cfg);
                defer client_db.deinit();
                try H.apply_ops(&client_db, 0, history_ops(), false);
            }
            // One more operation on the target leaves the client all but its tail.
            const last_start = target_db.bounds().end;
            try H.apply_ops(&target_db, 1, 1, false);
            const target = target_of(&target_db, target_db.sync_boundary());
            var source = locked(&target_db);
            var synced = try fixture.sync(H, Source, cfg, &source, target, .{});
            defer synced.deinit();
            const got = &synced.db;
            try testing.expectEqual(target.end, got.bounds().end);
            try testing.expectEqual(target_db.inactivity_floor(), got.inactivity_floor());
            try testing.expect(ops_root(H, got).eql(target.root));
            try testing.expect(canonical_root(H, got).eql(canonical_root(H, &target_db)));
            try H.expect_ops_applied(got, original_start, 0, history_ops());
            try H.expect_ops_applied(got, last_start, 1, 1);
        }

        test "sync: a client already at the target completes without querying the source" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            const cfg = try H.config(&fixture, "client");
            // Both apply the same operations and prune to their sync boundaries, so the
            // client's persisted state equals the target.
            const target_start = target_db.bounds().end;
            try H.apply_ops(&target_db, 0, history_ops(), false);
            try H.prune(&target_db, target_db.sync_boundary());
            {
                var client_db = try fixture.open(H, cfg);
                defer client_db.deinit();
                try H.apply_ops(&client_db, 0, history_ops(), false);
                try H.prune(&client_db, client_db.sync_boundary());
                try client_db.sync();
            }
            const target = target_of(&target_db, target_db.sync_boundary());
            var source: Fail = .{};
            var synced = try fixture.sync(H, Fail, cfg, &source, target, .{});
            defer synced.deinit();
            try testing.expectEqual(@as(u32, 0), source.served);
            try testing.expectEqual(target.end, synced.db.bounds().end);
            try testing.expectEqual(target.start, synced.db.sync_boundary());
            try testing.expect(ops_root(H, &synced.db).eql(target.root));
            const canonical = canonical_root(H, &target_db);
            try testing.expect(canonical_root(H, &synced.db).eql(canonical));
            try H.expect_ops_applied(&synced.db, target_start, 0, history_ops());
        }

        /// Opens a client engine syncing from `source` to `target`, with `updates` attached.
        fn open_engine(
            engine: *Engine,
            fixture: *Fixture,
            source: *Source,
            target: Target,
            updates: *ring.Receiver(Target),
            fetch: u64,
            outstanding: usize,
        ) !void {
            const cfg = try H.config(fixture, "client");
            var config = try fixture.sync_config(H, Source, cfg, source, target, .{
                .fetch_batch_size = fetch,
                .max_outstanding_requests = outstanding,
            });
            config.update_rx = updates;
            try engine.init(gpa, io, config);
        }

        test "sync: updates that lower the lower bound are discarded" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            try H.apply_ops(&target_db, 0, 100, false);
            try H.prune(&target_db, 10);
            // Start at the inactivity floor, which is positive, so updates can lower it.
            const initial = target_of(&target_db, target_db.inactivity_floor());
            try testing.expect(initial.start > 0);
            var source = locked(&target_db);
            var updates = try ring.channel(Target, gpa, io, 2);
            defer updates.receiver.deinit();
            defer updates.sender.deinit();
            var engine: Engine = undefined;
            try open_engine(&engine, &fixture, &source, initial, &updates.receiver, 5, 10);
            defer engine.deinit();
            // Both updates keep the root, so adopting either would fail on an unchanged root.
            for ([_]u64{ initial.end, initial.end + 1 }) |end| {
                const lowered: Target = .init(initial.root, initial.start - 1, end);
                try testing.expect(updates.sender.send_lossy(lowered));
            }
            var synced = try finish(&engine);
            defer synced.deinit();
            try testing.expect(ops_root(H, &synced.db).eql(initial.root));
            const canonical = canonical_root(H, &target_db);
            try testing.expect(canonical_root(H, &synced.db).eql(canonical));
        }

        test "sync: an update that lowers the upper bound is discarded" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            try H.apply_ops(&target_db, 0, 50, false);
            const initial = target_of(&target_db, target_db.sync_boundary());
            var source = locked(&target_db);
            var updates = try ring.channel(Target, gpa, io, 1);
            defer updates.receiver.deinit();
            defer updates.sender.deinit();
            var engine: Engine = undefined;
            try open_engine(&engine, &fixture, &source, initial, &updates.receiver, 5, 10);
            defer engine.deinit();
            const shorter: Target = .init(initial.root, initial.start, initial.end - 1);
            try testing.expect(updates.sender.send_lossy(shorter));
            var synced = try finish(&engine);
            defer synced.deinit();
            try testing.expect(ops_root(H, &synced.db).eql(initial.root));
            const canonical = canonical_root(H, &target_db);
            try testing.expect(canonical_root(H, &synced.db).eql(canonical));
        }

        test "sync: an update that raises both bounds is adopted" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            try H.apply_ops(&target_db, 0, 100, false);
            const initial = target_of(&target_db, target_db.inactivity_floor());
            // More operations move the upper bound; pruning and a commit move the floor.
            try H.apply_ops(&target_db, 1, 5, false);
            try H.prune(&target_db, 10);
            try H.apply_ops(&target_db, 2, 0, false);
            const final = target_of(&target_db, target_db.inactivity_floor());
            const canonical = canonical_root(H, &target_db);
            const boundary = target_db.sync_boundary();
            try testing.expect(final.start != initial.start);
            try testing.expect(final.end != initial.end);
            var source = locked(&target_db);
            var updates = try ring.channel(Target, gpa, io, 1);
            defer updates.receiver.deinit();
            defer updates.sender.deinit();
            // Queue the update before sync starts, so it is pending from the first step.
            try testing.expect(updates.sender.send_lossy(final));
            var engine: Engine = undefined;
            try open_engine(&engine, &fixture, &source, initial, &updates.receiver, 1, 1);
            defer engine.deinit();
            var synced = try finish(&engine);
            defer synced.deinit();
            const got = &synced.db;
            try testing.expect(ops_root(H, got).eql(final.root));
            try testing.expect(canonical_root(H, got).eql(canonical));
            try testing.expectEqual(final.end, got.bounds().end);
            try testing.expectEqual(final.start, got.bounds().start);
            try testing.expectEqual(final.start, got.inactivity_floor());
            try testing.expectEqual(boundary, got.sync_boundary());
        }

        test "sync: an update sent after sync returned leaves the original target" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            try H.apply_ops(&target_db, 0, 10, false);
            const target = target_of(&target_db, target_db.sync_boundary());
            const canonical = canonical_root(H, &target_db);
            var source = locked(&target_db);
            var updates = try ring.channel(Target, gpa, io, 1);
            defer updates.receiver.deinit();
            defer updates.sender.deinit();
            var engine: Engine = undefined;
            try open_engine(&engine, &fixture, &source, target, &updates.receiver, 20, 10);
            var synced = synced: {
                defer engine.deinit();
                break :synced try finish(&engine);
            };
            defer synced.deinit();
            // The engine is gone, so the late update reaches nothing.
            const late: Target = .init(.fill(2), target.start + 1, target.end + 1);
            _ = updates.sender.send_lossy(late);
            const got = &synced.db;
            try testing.expect(ops_root(H, got).eql(target.root));
            try testing.expect(canonical_root(H, got).eql(canonical));
            try testing.expectEqual(target.end, got.bounds().end);
            try testing.expectEqual(target.start, got.bounds().start);
            try testing.expectEqual(target.start, got.sync_boundary());
        }

        test "sync: a source error is terminal" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var source: Fail = .{};
            const cfg = try H.config(&fixture, "client");
            const target: Target = .init(.fill(0), 0, 5);
            const result = fixture.sync(H, Fail, cfg, &source, target, .{
                .fetch_batch_size = 2,
                .max_outstanding_requests = 2,
                .apply_batch_size = 2,
            });
            try testing.expectError(error.KeyNotFound, result);
        }

        // commonware's `engine.rs` tests that run per harness: an engine over a real database
        // whose fetches never answer (`FailSource`, its results never handled), driven by
        // inserting requests and handing it results directly.

        const Retention = engine_mod.Engine(H.Sync, Fail);

        /// commonware's `retention_engine`: target `[5, 10)`, one request of one operation.
        fn retention_engine(engine: *Retention, fixture: *Fixture, source: *Fail) !void {
            const cfg = try H.config(fixture, "retention");
            const target: Target = .init(.fill(1), 5, 10);
            const config = try fixture.sync_config(H, Fail, cfg, source, target, .{
                .fetch_batch_size = 1,
                .apply_batch_size = 1,
            });
            try engine.init(gpa, io, config);
        }

        /// A late operations response at size 10 carrying `ops` (owned).
        fn late_response(ops: []H.Sync.Op) Retention.Response {
            return .{ .operations = .{ .proof = .{ .leaves = 10 }, .operations = ops } };
        }

        /// An operations request at the first target size, 10.
        fn operations_at(start: u64, max_ops: u64) Retention.Request {
            return .{ .operations = .{ .size = 10, .start = start, .max_ops = max_ops } };
        }

        fn batch_at(engine: *const Retention, start: u64) ?[]H.Sync.Op {
            for (engine.fetched.items) |batch| {
                if (batch.start == start) return batch.ops;
            }
            return null;
        }

        test "engine: a boundary response keeps a fetched batch at the lower bound" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var source: Fail = .{};
            var engine: Retention = undefined;
            try retention_engine(&engine, &fixture, &source);
            defer engine.deinit();
            const ops = try H.create_ops(0, 3);
            try engine.store_operations(6, ops);
            // Move the lower bound to the start of the fetched batch.
            try engine.reset_for_target_update(.init(.fill(2), 6, 12));
            try testing.expect(engine.pinned_nodes == null);
            // The boundary response sets pinned nodes without replacing the batch.
            const boundary: Retention.Request = .{ .boundary = .{ .size = 12, .start = 6 } };
            const id = try engine.requests.insert(gpa, boundary);
            const op = try H.create_ops(0, 1);
            defer gpa.free(op);
            const pins = try gpa.dupe(Digest, &.{.fill(7)});
            try engine.handle_fetch_result(id, .{ .boundary = .{
                .proof = .{ .leaves = 12 },
                .op = op[0],
                .pinned_nodes = pins,
            } });
            try testing.expectEqualSlices(Digest, &.{.fill(7)}, engine.pinned_nodes.?);
            try testing.expectEqual(ops.ptr, batch_at(&engine, 6).?.ptr);
            // Applying moves the journal past the whole batch.
            try engine.apply_operations();
            try testing.expectEqual(@as(u64, 9), engine.journal.size());
        }

        test "engine: moving the lower bound drops a canceled request's queued result" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var source: Fail = .{};
            var engine: Retention = undefined;
            try retention_engine(&engine, &fixture, &source);
            defer engine.deinit();
            // The boundary request and an operations request below the next lower bound.
            try testing.expect(engine.requests.contains(5));
            const request = operations_at(6, 1);
            const old_id = try engine.requests.insert(gpa, request);
            const queued = late_response(try H.create_ops(0, 1));
            try testing.expectEqual(@as(usize, 2), engine.requests.len());
            // Moving the lower bound beyond both starts cancels both requests.
            try engine.reset_for_target_update(.init(.fill(2), 7, 12));
            try testing.expectEqual(@as(usize, 0), engine.requests.len());
            try testing.expect(engine.requests.remove(old_id) == null);
            // The queued result of the canceled request is ignored, and no fetch is left.
            try engine.handle_fetch_result(old_id, queued);
            try testing.expectEqual(@as(usize, 0), engine.fetched.items.len);
            try testing.expect(engine.pinned_nodes == null);
            try testing.expectEqual(@as(usize, 0), engine.tasks.items.len);
        }

        test "engine: an old-size request beyond the floor survives target updates" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var source: Fail = .{};
            var engine: Retention = undefined;
            try retention_engine(&engine, &fixture, &source);
            defer engine.deinit();
            // A pending boundary request and an operations request at the first size.
            try testing.expect(engine.requests.contains(5));
            _ = try engine.requests.insert(gpa, .{ .boundary = .{ .size = 10, .start = 5 } });
            const request = operations_at(8, 1);
            const id = try engine.requests.insert(gpa, request);
            try testing.expectEqual(@as(usize, 2), engine.requests.len());
            // Updates with an unchanged lower bound keep both requests.
            var root: u8 = 2;
            for (11..21) |end| {
                try engine.reset_for_target_update(.init(.fill(root), 5, end));
                root += 1;
                try testing.expect(engine.requests.contains(5));
                try testing.expect(engine.requests.contains(8));
                try testing.expectEqual(@as(usize, 2), engine.requests.len());
            }
            // Updates that move the lower bound below the request's start cancel the boundary
            // and keep the operations request.
            for ([_][2]u64{ .{ 6, 22 }, .{ 7, 24 } }) |range| {
                try engine.reset_for_target_update(.init(.fill(root), range[0], range[1]));
                root += 1;
                try testing.expect(engine.requests.contains(8));
                try testing.expectEqual(@as(usize, 1), engine.requests.len());
            }
            // The late response at the first size is stored at its start.
            const ops = try H.create_ops(0, 1);
            try engine.handle_fetch_result(id, late_response(ops));
            try testing.expectEqual(@as(usize, 0), engine.requests.len());
            try testing.expectEqual(ops.ptr, batch_at(&engine, 8).?.ptr);
        }

        test "engine: moving the floor cancels operations ending at the new bound" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var source: Fail = .{};
            var engine: Retention = undefined;
            try retention_engine(&engine, &fixture, &source);
            defer engine.deinit();
            // Operations requests below and beyond the next lower bound.
            const below = operations_at(6, 2);
            _ = try engine.requests.insert(gpa, below);
            const beyond = operations_at(9, 1);
            _ = try engine.requests.insert(gpa, beyond);
            try testing.expectEqual(@as(usize, 3), engine.requests.len());
            // A lower bound at the end of the first request cancels it and the old boundary.
            try engine.reset_for_target_update(.init(.fill(2), 8, 14));
            try testing.expect(!engine.requests.contains(5));
            try testing.expect(!engine.requests.contains(6));
            try testing.expect(engine.requests.contains(9));
            try testing.expectEqual(@as(usize, 1), engine.requests.len());
        }

        test "engine: a moved floor schedules its boundary without the old operation" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var source: Fail = .{};
            var engine: Retention = undefined;
            try retention_engine(&engine, &fixture, &source);
            defer engine.deinit();
            const request = operations_at(6, 1);
            const operation_id = try engine.requests.insert(gpa, request);
            try testing.expect(engine.requests.contains(5));
            // A lower bound at the start of the operations request cancels it and the old
            // boundary; scheduling issues the boundary at the new lower bound.
            try engine.reset_for_target_update(.init(.fill(2), 6, 12));
            try engine.schedule_requests();
            try testing.expect(engine.requests.remove(operation_id) == null);
            try testing.expect(!engine.requests.contains(5));
            try testing.expect(engine.requests.contains(6));
            try testing.expectEqual(@as(usize, 1), engine.requests.len());
        }

        // commonware's issue 5669 regressions: client storage whose destroy stopped after
        // emptying its log, beside a Merkle structure the destroy never removed.

        /// Operations in each batch the interrupted-destroy tests apply: commonware's 300,
        /// halved in plain Debug builds.
        const interrupted_destroy_ops: u64 = if (heavy()) 300 else 150;
        /// Least sync boundary `prune_to_sync_boundary` leaves.
        const pruned_sync_boundary = 64;

        /// Raises the sync boundary of `db` to at least `pruned_sync_boundary`, applying the
        /// operations of `seed` again until it does, and prunes `db` to that boundary.
        fn prune_to_sync_boundary(db: *Db, seed: u64) !void {
            // A database that derives its floor raises it once the same keys are rewritten;
            // a few passes suffice for every harness.
            for (0..8) |_| {
                try H.prune(db, pruned_sync_boundary);
                const boundary = db.sync_boundary();
                if (boundary >= pruned_sync_boundary) return H.prune(db, boundary);
                try H.apply_ops(db, seed, interrupted_destroy_ops, false);
            }
            return error.TestUnexpectedResult;
        }

        /// Destroys the durable `db` that `cfg` names with every removal failing, so the
        /// destroy stops once the clear of its log is durable. Consumes `db`.
        fn interrupt_destroy(fixture: *Fixture, db: *Db, cfg: H.Sync.Config) !void {
            const end = db.bounds().end;
            // The first removal of a destroy follows the durable clear of its log.
            fixture.storage.remove_failures_after = 0;
            const result = db.destroy();
            fixture.storage.remove_failures_after = null;
            if (result) |_| return error.TestUnexpectedResult else |_| {}
            // The log reopens empty beside the whole Merkle structure of the destroyed db.
            const storage = fixture.storage.interface();
            const log_cfg = H.Sync.journal_config(cfg);
            const range: journal_mod.Bounds = .{ .start = 0, .end = end };
            var log = try journal_mod.init(H.Sync.Journal, gpa, storage, log_cfg, range);
            defer log.deinit();
            try testing.expectEqual(@as(u64, 0), log.size());
            const hasher = qmdb.hasher(H.Sync.Hasher);
            const Merkle = merkle.full.Merkle(H.Family, Digest);
            var structure = try Merkle.init(gpa, storage, &hasher, cfg.merkle);
            defer structure.deinit();
            try testing.expectEqual(end, structure.leaves());
        }

        /// A target, and client storage an interrupted destroy left holding other operations.
        const Interrupted = struct {
            /// Source of the target's operations; the caller closes it.
            target_db: Db,
            target: Target,
            canonical: Digest,
            /// Names the client storage.
            cfg: H.Sync.Config,
        };

        /// The target's range starts at its sync boundary when `pruned`, else at zero. The
        /// client's Merkle structure extends past that start, and past the end when `ahead`.
        fn interrupted_destroy(fixture: *Fixture, pruned: bool, ahead: bool) !Interrupted {
            var target_db = try fixture.open(H, try H.config(fixture, "target"));
            errdefer target_db.deinit();
            try H.apply_ops(&target_db, 0, interrupted_destroy_ops, true);
            if (pruned) try prune_to_sync_boundary(&target_db, 0);
            const start = if (pruned) target_db.sync_boundary() else 0;
            const target = target_of(&target_db, start);
            const local_ops = if (ahead) 2 * target.end else (start + 3 * target.end) / 4;
            const cfg = try H.config(fixture, "client");
            var local_db = try fixture.open(H, cfg);
            {
                errdefer local_db.deinit();
                try H.apply_ops(&local_db, 1, local_ops, false);
                try local_db.sync();
                const local_end = local_db.bounds().end;
                try testing.expect(local_end > start); // Nodes past the target's bound.
                try testing.expectEqual(ahead, local_end > target.end);
            }
            try interrupt_destroy(fixture, &local_db, cfg);
            const canonical = canonical_root(H, &target_db);
            return .{
                .target_db = target_db,
                .target = target,
                .canonical = canonical,
                .cfg = cfg,
            };
        }

        fn sync_after_interrupted_destroy_case(pruned: bool, ahead: bool) !void {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var setup = try interrupted_destroy(&fixture, pruned, ahead);
            defer setup.target_db.deinit();
            const target = setup.target;
            var source = locked(&setup.target_db);
            var synced = try fixture.sync(H, Source, setup.cfg, &source, target, .{});
            try testing.expect(ops_root(H, &synced.db).eql(target.root));
            try testing.expect(canonical_root(H, &synced.db).eql(setup.canonical));
            try testing.expectEqual(target.end, synced.db.bounds().end);
            synced.deinit();
            // A reopen recovers the target's state from storage alone.
            var reopened = try fixture.open(H, setup.cfg);
            defer reopened.deinit();
            try testing.expect(ops_root(H, &reopened).eql(target.root));
            try testing.expect(canonical_root(H, &reopened).eql(setup.canonical));
            try testing.expectEqual(target.end, reopened.bounds().end);
        }

        test "issue 5669: a sync after an interrupted destroy reaches the target durably" {
            for ([_]bool{ false, true }) |pruned| {
                for ([_]bool{ false, true }) |ahead| {
                    // Plain Debug builds run one case; -Dslow-tests and release run all four.
                    if (!heavy() and !(pruned and ahead)) continue;
                    try sync_after_interrupted_destroy_case(pruned, ahead);
                }
            }
        }

        /// Steps `engine` until its journal holds `stop` operations, then makes it durable.
        fn stop_at(engine: *Engine, stop: u64) !void {
            while (engine.journal.size() < stop) {
                if (try engine.step()) |synced| {
                    var unexpected = synced;
                    unexpected.deinit();
                    return error.TestUnexpectedResult; // It completed before it was stopped.
                }
            }
            try engine.journal.sync();
        }

        fn restart_after_destroy_case(pruned: bool, fetched: bool) !void {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var setup = try interrupted_destroy(&fixture, pruned, false);
            defer setup.target_db.deinit();
            const target = setup.target;
            var source = locked(&setup.target_db);
            // Stop the first sync before it builds the database, with its journal durable.
            {
                const config = try fixture.sync_config(H, Source, setup.cfg, &source, target, .{});
                var engine: Engine = undefined;
                try engine.init(gpa, io, config);
                defer engine.deinit();
                try stop_at(&engine, if (fetched) target.end else target.start + 1);
            }
            // The restarted sync resumes the journal and reaches the target.
            var synced = try fixture.sync(H, Source, setup.cfg, &source, target, .{});
            defer synced.deinit();
            try testing.expect(ops_root(H, &synced.db).eql(target.root));
            try testing.expect(canonical_root(H, &synced.db).eql(setup.canonical));
            try testing.expectEqual(target.end, synced.db.bounds().end);
        }

        test "issue 5669: a sync restarted after an interrupted destroy reaches the target" {
            for ([_]bool{ false, true }) |pruned| {
                for ([_]bool{ false, true }) |fetched| {
                    // Plain Debug builds run one case; -Dslow-tests and release run all four.
                    if (!heavy() and !(pruned and !fetched)) continue;
                    try restart_after_destroy_case(pruned, fetched);
                }
            }
        }

        test "issue 5669: opening after a stopped sync recovers the target's first commit" {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            // The target rewrites the same keys before its first commit, so a database that
            // derives its floor commits past every chunk the client pruned.
            var target_db = try fixture.open(H, try H.config(&fixture, "target"));
            defer target_db.deinit();
            for (0..3) |_| try H.apply_ops(&target_db, 0, interrupted_destroy_ops, false);
            const first_end = target_db.bounds().end;
            const first_root = ops_root(H, &target_db);
            const first_canonical = canonical_root(H, &target_db);
            try H.apply_ops(&target_db, 2, interrupted_destroy_ops, false);
            const target = target_of(&target_db, 0);
            // The client pruned a different history before its destroy was interrupted.
            const cfg = try H.config(&fixture, "client");
            var local_db = try fixture.open(H, cfg);
            {
                errdefer local_db.deinit();
                try H.apply_ops(&local_db, 1, interrupted_destroy_ops, false);
                try prune_to_sync_boundary(&local_db, 1);
                try local_db.sync();
            }
            try interrupt_destroy(&fixture, &local_db, cfg);
            // Stop the sync between the target's commits, with its journal durable.
            var source = locked(&target_db);
            {
                const config = try fixture.sync_config(H, Source, cfg, &source, target, .{});
                var engine: Engine = undefined;
                try engine.init(gpa, io, config);
                defer engine.deinit();
                try stop_at(&engine, first_end);
                try testing.expect(engine.journal.size() < target.end);
            }
            // The reopened database holds the first commit under the target's roots.
            var reopened = try fixture.open(H, cfg);
            defer reopened.deinit();
            try testing.expectEqual(first_end, reopened.bounds().end);
            try testing.expect(ops_root(H, &reopened).eql(first_root));
            try testing.expect(canonical_root(H, &reopened).eql(first_canonical));
        }
    };
}
