//! commonware's `qmdb/sync/engine.rs` unit tests over a test database whose journal only
//! counts operations and whose source answers every request with an empty response.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const channel = @import("utils").channel;
const merkle = @import("../../merkle/mod.zig");
const engine_mod = @import("engine.zig");
const source_mod = @import("source.zig");
const target_mod = @import("target.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Mmr = merkle.mmr.Family;
const Target = target_mod.Target(Mmr, D);
const Storage = runtime.storage.Storage;
const metrics = runtime.telemetry.metrics;

const TestConfig = struct {
    journal_size: u64,
    local_state_discards: *u32,
    pinned_node_probes: *u32,
};

const TestJournal = struct {
    size_value: u64,

    pub fn size(self: *const TestJournal) u64 {
        return self.size_value;
    }

    pub fn resize(self: *TestJournal, start: u64) !void {
        self.size_value = start;
    }

    pub fn append(self: *TestJournal, ops: []const u64) !void {
        self.size_value += ops.len;
    }

    pub fn sync(_: *TestJournal) !void {}

    pub fn deinit(self: *TestJournal) void {
        self.* = undefined;
    }
};

const TestDb = struct {
    pub const Family = Mmr;
    pub const Op = u64;
    pub const Digest = D;
    pub const Hasher = Sha256;
    pub const Journal = TestJournal;
    pub const Config = TestConfig;

    pub fn journal_config(cfg: TestConfig) u64 {
        return cfg.journal_size;
    }

    pub fn open_journal(_: Allocator, _: Storage, cfg: TestConfig, _: merkle.Range) !TestJournal {
        return .{ .size_value = cfg.journal_size };
    }

    pub fn from_sync_result(
        allocator: Allocator,
        _: Storage,
        _: metrics.Scope,
        _: TestConfig,
        journal: TestJournal,
        pinned_nodes: ?[]D,
        _: merkle.Range,
        _: u64,
    ) !TestDb {
        var owned = journal;
        owned.deinit();
        if (pinned_nodes) |pins| allocator.free(pins);
        return .{};
    }

    pub fn persist_sync_result(_: *TestDb) !void {}

    pub fn discard_local_state(_: Allocator, _: Storage, cfg: TestConfig) !void {
        cfg.local_state_discards.* += 1;
    }

    pub fn local_pinned_nodes(
        allocator: Allocator,
        _: Storage,
        cfg: TestConfig,
        _: Target,
        _: *const TestJournal,
    ) !?[]D {
        cfg.pinned_node_probes.* += 1;
        return try allocator.alloc(D, 0);
    }

    pub fn ops_root(_: *const TestDb) D {
        return .fill(0);
    }

    pub fn deinit(_: *TestDb) void {}
};

const TestSource = struct {
    pub const Family = Mmr;
    pub const Op = u64;
    pub const Digest = D;
    pub const Error = Allocator.Error;
    const Response = source_mod.Response(Mmr, u64, D);

    pub fn serve(
        _: *TestSource,
        allocator: Allocator,
        _: source_mod.Request(Mmr),
    ) Error!source_mod.Served(Response) {
        const ops = try allocator.alloc(u64, 0);
        const response: Response = .{ .operations = .{ .proof = .{}, .operations = ops } };
        return .{ .response = response, .feedback = null };
    }
};

const Engine = engine_mod.Engine(TestDb, TestSource);

const Fixture = struct {
    storage: runtime.storage.memory.Storage,
    registry: metrics.Registry,
    source: TestSource = .{},
    discards: u32 = 0,
    probes: u32 = 0,

    fn init() Fixture {
        return .{ .storage = .init(gpa), .registry = .init(gpa) };
    }

    fn deinit(self: *Fixture) void {
        self.registry.deinit();
        self.storage.deinit();
    }

    /// commonware's `test_engine_config`: target `[5, 10)`, one request of one operation.
    fn config(self: *Fixture, journal_size: u64) engine_mod.Config(TestDb, TestSource) {
        return .{
            .storage = self.storage.storage(),
            .scope = metrics.Scope.init(&self.registry),
            .source = &self.source,
            .target = .init(.fill(1), 5, 10),
            .max_outstanding_requests = 1,
            .fetch_batch_size = 1,
            .apply_batch_size = 1,
            .db_config = .{
                .journal_size = journal_size,
                .local_state_discards = &self.discards,
                .pinned_node_probes = &self.probes,
            },
        };
    }
};

fn ops_of(values: []const u64) ![]u64 {
    return gpa.dupe(u64, values);
}

test "sync target updates keep operations and reset pins only when the floor moves" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var engine: Engine = undefined;
    try engine.init(gpa, testing.io, fixture.config(5));
    defer engine.deinit();
    // Pinned nodes and two batches fetched ahead of the journal tip.
    try engine.store_operations(6, try ops_of(&.{ 1, 2 }));
    try engine.store_operations(8, try ops_of(&.{ 3, 4 }));
    engine.pinned_nodes = try gpa.dupe(D, &.{D.fill(7)});
    // An unchanged lower bound keeps operations and pinned nodes.
    try engine.reset_for_target_update(.init(.fill(2), 5, 12));
    try testing.expectEqual(@as(usize, 2), engine.fetched.items.len);
    try testing.expectEqualSlices(D, &.{D.fill(7)}, engine.pinned_nodes.?);
    // A moved lower bound keeps operations and clears pinned nodes.
    try engine.reset_for_target_update(.init(.fill(3), 9, 14));
    try testing.expectEqual(@as(usize, 2), engine.fetched.items.len);
    try testing.expect(engine.pinned_nodes == null);
    // Applying drops the batch below the new bound and appends the straddling one's tail.
    try engine.apply_operations();
    try testing.expectEqual(@as(u64, 10), engine.journal.size());
    try testing.expectEqual(@as(usize, 0), engine.fetched.items.len);
}

test "sync engine probes local pinned nodes only when the journal reaches the target" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var complete: Engine = undefined;
    try complete.init(gpa, testing.io, fixture.config(10));
    complete.deinit();
    try testing.expectEqual(@as(u32, 1), fixture.probes);
    var partial: Engine = undefined;
    try partial.init(gpa, testing.io, fixture.config(7));
    partial.deinit();
    try testing.expectEqual(@as(u32, 1), fixture.probes);
}

test "sync engine discards local state only when the journal resumes nothing" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var empty: Engine = undefined;
    try empty.init(gpa, testing.io, fixture.config(5));
    empty.deinit();
    try testing.expectEqual(@as(u32, 1), fixture.discards);
    try testing.expectEqual(@as(u32, 0), fixture.probes);
    // A journal holding part of the range or all of it resumes operations.
    for ([_]u64{ 6, 10 }) |journal_size| {
        var resumed: Engine = undefined;
        try resumed.init(gpa, testing.io, fixture.config(journal_size));
        resumed.deinit();
    }
    try testing.expectEqual(@as(u32, 1), fixture.discards);
}

test "sync engine schedules operations after the boundary request" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var config = fixture.config(5);
    config.max_outstanding_requests = 2;
    config.fetch_batch_size = 5;
    var engine: Engine = undefined;
    try engine.init(gpa, testing.io, config);
    defer engine.deinit();
    try testing.expectEqual(@as(usize, 2), engine.requests.len());
    try testing.expect(engine.requests.contains(5));
    try testing.expect(engine.requests.contains(6));
}

test "sync step takes a queued update before completing" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var updates = try channel.ring.channel(Target, gpa, testing.io, 2);
    defer updates.receiver.deinit();
    defer updates.sender.deinit();
    var config = fixture.config(10);
    config.update_rx = &updates.receiver;
    // The stale update is discarded; the advancing one retargets instead of completing.
    const advancing: Target = .init(.fill(3), 5, 12);
    try testing.expect(updates.sender.send_lossy(.init(.fill(2), 5, 10)));
    try testing.expect(updates.sender.send_lossy(advancing));
    var engine: Engine = undefined;
    try engine.init(gpa, testing.io, config);
    defer engine.deinit();
    try testing.expect(try engine.step() == null);
    try testing.expect(engine.target.eql(advancing));
}

test "sync step completes at the current target after finish" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var updates = try channel.ring.channel(Target, gpa, testing.io, 1);
    defer updates.receiver.deinit();
    defer updates.sender.deinit();
    var finish = try channel.mpsc.channel(void, gpa, testing.io, 1);
    defer finish.receiver.deinit();
    defer finish.sender.deinit();
    var config = fixture.config(10);
    config.target.root = .fill(0); // TestDb's root, so the final check passes.
    config.update_rx = &updates.receiver;
    config.finish_rx = &finish.receiver;
    try testing.expect(updates.sender.send_lossy(.init(.fill(3), 5, 12)));
    try finish.sender.try_send({});
    var engine: Engine = undefined;
    try engine.init(gpa, testing.io, config);
    defer engine.deinit();
    // A requested finish wins over a queued update.
    var db = (try engine.step()).?;
    db.deinit();
}

test "sync handle fetch result ignores untracked requests" {
    var fixture = Fixture.init();
    defer fixture.deinit();
    var engine: Engine = undefined;
    try engine.init(gpa, testing.io, fixture.config(5));
    defer engine.deinit();
    // A late result for an unknown id is released and ignored.
    const ops = try ops_of(&.{9});
    const late: Engine.Response = .{ .operations = .{ .proof = .{}, .operations = ops } };
    try engine.handle_fetch_result(1000, late);
    try testing.expectEqual(@as(usize, 0), engine.fetched.items.len);
}
