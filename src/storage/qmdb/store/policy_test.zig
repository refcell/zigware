//! The store's floor-policy scenarios (qmdb/store/db.rs's `test_store_policy_*`), over
//! commonware's `PolicyStore`: SHA-256 digest keys and values under `OneCap`, with 7 items per
//! log section. Locations, floors, and decisions match commonware's.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const cryptography = @import("cryptography");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const floor_mod = @import("../floor.zig");
const test_support = @import("../test_support.zig");
const store = @import("mod.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const max_usize = std.math.maxInt(usize);
const max_u64 = std.math.maxInt(u64);

/// Counts `OneCap` transforms, one per snapshot probe (commonware's `CountingTranslator`).
var probes: usize = 0;

const CountingCap = struct {
    pub const Key = translator.OneCap.Key;
    pub const ordered = true;

    pub fn transform(_: CountingCap, key: []const u8) Key {
        probes += 1;
        return (translator.OneCap{}).transform(key);
    }

    pub fn hash(_: CountingCap, key: Key) u64 {
        return (translator.OneCap{}).hash(key);
    }

    pub fn order(a: Key, b: Key) std.math.Order {
        return translator.OneCap.order(a, b);
    }

    pub fn eql(a: Key, b: Key) bool {
        return translator.OneCap.eql(a, b);
    }
};

fn Store(comptime T: type) type {
    return store.Db(Digest, value.Variable(Digest), T);
}

const Db = Store(translator.OneCap);
const Write = Db.Write;
const Op = Db.Operation;

/// Storage and a page cache for one store.
fn Harness(comptime T: type) type {
    return struct {
        const Self = @This();
        const D = Store(T);
        const CodecCfg = @FieldType(D.Journal.Cfg, "codec_config");

        storage: runtime.buffer.mocks.Storage,
        cache_ref: runtime.buffer.paged.CacheRef,

        fn init(self: *Self) !void {
            self.storage = .init(gpa);
            errdefer self.storage.deinit();
            self.cache_ref = try .init(gpa, 77, 9);
        }

        fn deinit(self: *Self) void {
            self.cache_ref.deinit();
            self.storage.deinit();
        }

        fn open(self: *Self) !D {
            const cfg: D.Cfg = .{
                .log = .{
                    .partition = "policy",
                    .items_per_section = 7,
                    .codec_config = test_support.codec_config(CodecCfg),
                    .cache_ref = &self.cache_ref,
                    .write_buffer = 64 * 1024,
                    .replay_buffer = 64 * 1024,
                },
                .translator = .{},
                .init_cache = 1024,
            };
            return D.init(gpa, self.storage.interface(), cfg, null);
        }
    };
}

/// Commonware's `digest(i)`: `Sha256::hash(&[&i.to_be_bytes()])`.
fn digest(i: u64) Digest {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, i, .big);
    return Sha256.hash(&.{&be});
}

fn digest_less(_: void, a: Digest, b: Digest) bool {
    return std.mem.order(u8, &a.bytes, &b.bytes) == .lt;
}

fn write_less(_: void, a: Write, b: Write) bool {
    return digest_less({}, a.key, b.key);
}

/// Commonware's `seed(n)`: `n` keys in ascending order, the `i`th holding `digest(100 + i)`.
fn seed(comptime n: usize) [n]Write {
    var keys: [n]Digest = undefined;
    for (&keys, 0..) |*k, i| k.* = digest(i);
    std.mem.sort(Digest, &keys, {}, digest_less);
    var writes: [n]Write = undefined;
    for (&writes, keys, 0..) |*w, k, i| w.* = .{ .key = k, .value = digest(100 + i) };
    return writes;
}

const Range = struct { start: u64, end: u64 };

/// Applies `writes` with `policy`, without metadata, returning the applied range.
fn apply(db: anytype, writes: []const Write, policy: anytype) !Range {
    const D = @TypeOf(db.*);
    const start = db.bounds().end;
    // A store's `Write` type depends on its translator; the fields are the same.
    const converted = try gpa.alloc(D.Write, writes.len);
    defer gpa.free(converted);
    for (converted, writes) |*c, w| c.* = .{ .key = w.key, .value = w.value };
    var changeset = try D.Changeset.init(gpa, converted);
    try db.apply_batch_with(&changeset, policy);
    return .{ .start = start, .end = db.bounds().end };
}

fn hold(db: anytype, writes: []const Write) !void {
    var policy: floor_mod.Hold = .{};
    _ = try apply(db, writes, &policy);
}

fn expect_get(db: *Db, k: Digest, want: ?Digest) !void {
    const got = try db.get(&k);
    try testing.expectEqual(want, got);
}

fn expect_op(db: *Db, location: u64, want: Op) !void {
    var op = try db.log.read(location);
    defer op.deinit(gpa);
    try testing.expectEqualDeep(want, op);
}

const Choice = union(enum) { keep, evict, replace: Digest, stop };
const Rule = struct { key: Digest, choice: Choice };
const Visit = struct { location: u64, key: Digest, value: Digest };

/// Commonware's `Script`: fixed limits, a choice per key (`default` otherwise), and the
/// updates it visited.
const Script = struct {
    entries: usize,
    skips: u64,
    rules: []const Rule = &.{},
    default: Choice = .keep,
    visited: std.ArrayList(Visit) = .empty,

    fn deinit(self: *Script) void {
        self.visited.deinit(gpa);
    }

    fn locations(self: *const Script, out: []u64) []const u64 {
        for (self.visited.items, out[0..self.visited.items.len]) |v, *o| o.* = v.location;
        return out[0..self.visited.items.len];
    }

    pub fn evicts(_: *const Script) bool {
        return true;
    }

    pub fn limits(self: *const Script, _: usize) floor_mod.Limits {
        return .{ .entries = self.entries, .skips = self.skips };
    }

    pub fn decide(
        self: *Script,
        comptime K: type,
        comptime V: type,
        entry: floor_mod.Entry(K, V),
    ) floor_mod.Decision(V) {
        self.visited.append(gpa, .{
            .location = entry.location,
            .key = entry.key.*,
            .value = entry.value,
        }) catch @panic("test allocation");
        var choice = self.default;
        for (self.rules) |rule| {
            if (rule.key.eql(entry.key.*)) choice = rule.choice;
        }
        return switch (choice) {
            .keep => entry.keep(),
            .evict => entry.evict()[0],
            .replace => |v| entry.replace(v),
            .stop => entry.stop(),
        };
    }
};

fn visit(location: u64, w: Write) Visit {
    return .{ .location = location, .key = w.key, .value = w.value.? };
}

fn expect_visits(script: *const Script, want: []const Visit) !void {
    try testing.expectEqualSlices(Visit, want, script.visited.items);
}

/// Commonware's `walk_model`: the floor a fixed-limit walk from `floor` reaches over the
/// ascending `active` locations below `tip`, and the locations it decides (none stop).
fn walk_model(
    active: []const u64,
    start: u64,
    tip: u64,
    entries_limit: usize,
    skips_limit: u64,
    visited: *std.ArrayList(u64),
) !u64 {
    var floor = start;
    var entries = entries_limit;
    var skips = skips_limit;
    while (entries > 0) {
        var next = tip;
        for (active) |loc| if (loc >= floor and loc < tip) {
            next = loc;
            break;
        };
        const gap = next - floor;
        if (gap > skips) {
            floor += skips;
            break;
        }
        skips -= gap;
        floor = next;
        if (next == tip) break;
        try visited.append(gpa, next);
        floor = next + 1;
        entries -= 1;
    }
    return floor;
}

test "store policy replace writes its value at the tip" {
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    defer db.deinit();
    const s = seed(3);
    try hold(&db, &s);
    const tip = db.bounds().end;
    var policy: Script = .{
        .entries = max_usize,
        .skips = max_u64,
        .rules = &.{.{ .key = s[1].key, .choice = .{ .replace = digest(201) } }},
    };
    defer policy.deinit();
    const range = try apply(&db, &.{}, &policy);
    var buffer: [8]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3 }, policy.locations(&buffer));
    try testing.expectEqual(tip, db.inactivity_floor());
    try testing.expectEqual(Range{ .start = 5, .end = 9 }, range);
    const moved = [_]Write{ s[0], .{ .key = s[1].key, .value = digest(201) }, s[2] };
    for (moved, 5..) |w, loc| {
        try expect_op(&db, loc, .{ .update = .{ .key = w.key, .value = w.value.? } });
        try expect_get(&db, w.key, w.value);
    }
}

/// Commonware's `colliding_digest`.
fn colliding(prefix: u8, suffix: u64) Digest {
    var d: Digest = .{ .bytes = @splat(0) };
    d.bytes[0] = prefix;
    std.mem.writeInt(u64, d.bytes[24..32], suffix, .big);
    return d;
}

// Commonware's evictions also count value clones; zigware's policies receive owned values.
test "store policy evicts every reached update in location order" {
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    defer db.deinit();
    const keys = [_]Digest{
        colliding(0xaa, 0), colliding(0xaa, 1), colliding(0xaa, 2), colliding(0xbb, 0),
    };
    var writes: [4]Write = undefined;
    for (&writes, keys, 0..) |*w, k, tag| w.* = .{ .key = k, .value = digest(tag) };
    try hold(&db, &writes);
    var policy: Script = .{ .entries = max_usize, .skips = max_u64, .default = .evict };
    defer policy.deinit();
    const range = try apply(&db, &.{.{ .key = keys[0], .value = digest(20) }}, &policy);
    try expect_visits(&policy, &.{
        .{ .location = 2, .key = keys[1], .value = digest(1) },
        .{ .location = 3, .key = keys[2], .value = digest(2) },
        .{ .location = 4, .key = keys[3], .value = digest(3) },
        .{ .location = 6, .key = keys[0], .value = digest(20) },
    });
    try testing.expectEqual(Range{ .start = 6, .end = 12 }, range);
    try expect_op(&db, 6, .{ .update = .{ .key = keys[0], .value = digest(20) } });
    for ([_]Digest{ keys[1], keys[2], keys[3], keys[0] }, 7..) |k, loc| {
        try expect_op(&db, loc, .{ .delete = k });
    }
    try expect_op(&db, 11, .{ .commit = .{ .metadata = null, .floor = 11 } });
    for (keys) |k| try expect_get(&db, k, null);
    try testing.expect(db.is_empty());
}

test "store walk leaves an unreachable own write undecided" {
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    defer db.deinit();
    // The window ends at min(2, 0 + 0 + 2) = 2, but reaching the write at 1 costs a skip.
    var policy: floor_mod.Bounded = .{ .entries = 2, .skips = 0 };
    const range = try apply(&db, &.{.{ .key = digest(0), .value = digest(7) }}, &policy);
    try testing.expectEqual(Range{ .start = 1, .end = 3 }, range);
    try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
    try expect_op(&db, 1, .{ .update = .{ .key = digest(0), .value = digest(7) } });
    try expect_op(&db, 2, .{ .commit = .{ .metadata = null, .floor = 0 } });
}

test "store proportional move probes the snapshot once" {
    var h: Harness(CountingCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    var writes: [3]Write = undefined;
    for (&writes, 0..) |*w, i| {
        var k: Digest = .{ .bytes = @splat(0xaa) };
        k.bytes[31] = @intCast(i);
        w.* = .{ .key = k, .value = digest(i) };
    }
    try hold(&db, &writes);
    probes = 0;
    var policy: floor_mod.Proportional = .{};
    const range = try apply(&db, &.{}, &policy);
    // An empty batch moves one update for its previous commit, probing only to rewrite it.
    try testing.expectEqual(@as(u64, 2), range.end - range.start);
    try testing.expectEqual(@as(usize, 1), probes);
    try db.destroy();
}

test "store policy reads its limits once" {
    const Growing = struct {
        reads: usize = 0,
        decided: usize = 0,

        pub fn evicts(_: *const @This()) bool {
            return false;
        }

        pub fn limits(self: *const @This(), _: usize) floor_mod.Limits {
            const mutable: *@This() = @constCast(self);
            mutable.reads += 1;
            const entries: usize = if (mutable.reads == 1) 1 else max_usize;
            return .{ .entries = entries, .skips = max_u64 };
        }

        pub fn decide(
            self: *@This(),
            comptime K: type,
            comptime V: type,
            entry: floor_mod.Entry(K, V),
        ) floor_mod.Decision(V) {
            self.decided += 1;
            return entry.keep();
        }
    };
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    defer db.deinit();
    const s = seed(4);
    try hold(&db, &s);
    var policy: Growing = .{};
    _ = try apply(&db, &.{}, &policy);
    try testing.expectEqual(@as(usize, 1), policy.reads);
    try testing.expectEqual(@as(usize, 1), policy.decided);
}

fn expect_values(db: *Db, want: []const Write) !void {
    for (want) |w| try expect_get(db, w.key, w.value);
}

test "store policy keeps, evicts, and recovers across commit, reopen, and prune" {
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    const s = seed(4);
    try hold(&db, &s);
    try testing.expectEqual(@as(u64, 6), db.bounds().end);
    // Its updates follow key order from 6 (at 6 and 7) and its delete lies at 8.
    const created = digest(4);
    const writes = [_]Write{
        .{ .key = s[1].key, .value = digest(201) },
        .{ .key = s[2].key, .value = null },
        .{ .key = created, .value = digest(104) },
    };
    var written = [_]Write{ writes[0], writes[2] };
    std.mem.sort(Write, &written, {}, write_less);
    for (written) |w| try testing.expect(digest_less({}, w.key, s[2].key));
    // Four skips pass the initial commit, the two superseded locations, and the seed commit.
    var policy: Script = .{
        .entries = max_usize,
        .skips = 4,
        .rules = &.{.{ .key = s[3].key, .choice = .evict }},
    };
    defer policy.deinit();
    _ = try apply(&db, &writes, &policy);
    try expect_visits(&policy, &.{
        .{ .location = 1, .key = s[0].key, .value = s[0].value.? },
        .{ .location = 4, .key = s[3].key, .value = s[3].value.? },
        .{ .location = 6, .key = written[0].key, .value = written[0].value.? },
        .{ .location = 7, .key = written[1].key, .value = written[1].value.? },
    });
    // No skip remains for the delete at 8, one short of the writes' tip.
    try testing.expectEqual(@as(u64, 8), db.inactivity_floor());
    const expected = [_]Write{
        s[0],                                writes[0], writes[1],
        .{ .key = s[3].key, .value = null }, writes[2],
    };
    try expect_values(&db, &expected);
    try db.commit();
    const size = db.bounds().end;
    const floor = db.inactivity_floor();
    db.deinit();
    for (0..2) |round| {
        db = try h.open();
        try testing.expectEqual(size, db.bounds().end);
        try testing.expectEqual(floor, db.inactivity_floor());
        try expect_values(&db, &expected);
        if (round == 0) try db.prune(floor);
        if (round == 1) try db.destroy() else db.deinit();
    }
}

/// Commonware's `[i; 32]` digest.
fn filled(i: u8) Digest {
    return .{ .bytes = @splat(i) };
}

test "store policy decides the batch's own updates like applied ones" {
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    var seeded: [4]Write = undefined;
    for (&seeded, [_]u8{ 1, 2, 4, 5 }) |*w, i| w.* = .{ .key = filled(i), .value = digest(i) };
    try hold(&db, &seeded);
    try testing.expectEqual(@as(u64, 6), db.bounds().end);
    var writes: [5]Write = undefined;
    for (&writes, 1..) |*w, i| w.* = .{ .key = filled(@intCast(i)), .value = digest(100 + i) };
    // Six skips pass 0..6; then keep key 1, replace key 2, evict keys 3 and 4, stop at key 5.
    var policy: Script = .{ .entries = max_usize, .skips = 6, .default = .evict, .rules = &.{
        .{ .key = filled(1), .choice = .keep },
        .{ .key = filled(2), .choice = .{ .replace = digest(200) } },
        .{ .key = filled(5), .choice = .stop },
    } };
    defer policy.deinit();
    const range = try apply(&db, &writes, &policy);
    var visits: [5]Visit = undefined;
    for (&visits, writes, 6..) |*v, w, loc| v.* = visit(loc, w);
    try expect_visits(&policy, &visits);
    try testing.expectEqual(@as(u64, 10), db.inactivity_floor());
    try testing.expectEqual(Range{ .start = 6, .end = 16 }, range);
    const ops = [_]Op{
        .{ .update = .{ .key = filled(1), .value = digest(101) } },
        .{ .update = .{ .key = filled(2), .value = digest(200) } },
        .{ .delete = filled(3) },
        .{ .delete = filled(4) },
        .{ .commit = .{ .metadata = null, .floor = 10 } },
    };
    for (ops, 11..) |op, loc| try expect_op(&db, loc, op);
    const values = [_]Write{
        writes[0],                            .{ .key = filled(2), .value = digest(200) },
        .{ .key = filled(3), .value = null }, .{ .key = filled(4), .value = null },
        writes[4],
    };
    try expect_values(&db, &values);
    try testing.expectEqual(@as(usize, 3), db.active_keys);
    try db.commit();
    db.deinit();
    db = try h.open();
    defer db.deinit();
    try testing.expectEqual(@as(u64, 16), db.bounds().end);
    try testing.expectEqual(@as(u64, 10), db.inactivity_floor());
    try expect_values(&db, &values);
    // The next batch decides the stopped update without spending a skip.
    var next: Script = .{ .entries = 1, .skips = 0 };
    defer next.deinit();
    _ = try apply(&db, &.{}, &next);
    try expect_visits(&next, &.{.{ .location = 10, .key = filled(5), .value = digest(105) }});
    try testing.expectEqual(@as(u64, 11), db.inactivity_floor());
}

/// One layout of `test_store_policy_reads_reached_candidates`: `n` seeded keys, every
/// `step`th rewritten in each of `rounds` held batches.
fn check_reached_candidates(
    comptime n: usize,
    step: usize,
    rounds: usize,
    active: []const u64,
    tip: u64,
    entries_cases: []const usize,
    skips_cases: []const u64,
) !void {
    const s = seed(n);
    var rewrites: std.ArrayList(Write) = .empty;
    defer rewrites.deinit(gpa);
    var i: usize = 0;
    while (i < n) : (i += step) {
        try rewrites.append(gpa, .{ .key = s[i].key, .value = digest(500) });
    }
    for (entries_cases) |entries| for (skips_cases) |skips| {
        var h: Harness(translator.OneCap) = undefined;
        try h.init();
        defer h.deinit();
        var db = try h.open();
        defer db.deinit();
        try hold(&db, &s);
        for (0..rounds) |_| try hold(&db, rewrites.items);
        try testing.expectEqual(tip, db.bounds().end);
        // The walk decides what `walk_model` predicts and reads each decided update once.
        const before = db.log.metrics.items_read.metric().get();
        var policy: Script = .{ .entries = entries, .skips = skips };
        defer policy.deinit();
        _ = try apply(&db, &.{}, &policy);
        const reads = db.log.metrics.items_read.metric().get() - before;
        var decided: std.ArrayList(u64) = .empty;
        defer decided.deinit(gpa);
        const floor = try walk_model(active, 0, tip, entries, skips, &decided);
        try testing.expectEqual(@as(u64, decided.items.len), reads);
        const visited = try gpa.alloc(u64, policy.visited.items.len);
        defer gpa.free(visited);
        try testing.expectEqualSlices(u64, decided.items, policy.locations(visited));
        try testing.expectEqual(floor, db.inactivity_floor());
    };
}

test "store walk reads only the candidates it reaches" {
    // Seed 100 updates at 1..101, then rewrite every fourth key at 102..127.
    var sparse: std.ArrayList(u64) = .empty;
    defer sparse.deinit(gpa);
    for (1..101) |loc| if (loc % 4 != 1) try sparse.append(gpa, loc);
    for (102..127) |loc| try sparse.append(gpa, loc);
    const sparse_entries = [_]usize{ 0, 1, 10, 74, 75, 100, 200 };
    const sparse_skips = [_]u64{ 0, 1, 2, 5, 30, max_u64 };
    try check_reached_candidates(100, 4, 1, sparse.items, 128, &sparse_entries, &sparse_skips);
    // One key rewritten 19 times: its only active update lies at 39, before the commit at 40.
    const gap_skips = [_]u64{ 0, 1, 38, 39, 40, max_u64 };
    try check_reached_candidates(1, 1, 19, &.{39}, 41, &.{ 0, 1, 2 }, &gap_skips);
}

const Live = struct { location: u64, key: Digest, value: Digest };

fn live_at(location: u64, w: Write) Live {
    return .{ .location = location, .key = w.key, .value = w.value.? };
}

/// The active updates below the tip of `writes` over `test_store_policy_limits`'s layout: the
/// applied updates of keys the batch does not write, then the batch's own updates from 12.
fn limits_live(applied: []const Live, writes: []const Write, out: *std.ArrayList(Live)) !void {
    for (applied) |a| {
        var rewritten = false;
        for (writes) |w| rewritten = rewritten or w.key.eql(a.key);
        if (!rewritten) try out.append(gpa, a);
    }
    for (writes, 12..) |w, loc| {
        if (w.value) |v| try out.append(gpa, .{ .location = loc, .key = w.key, .value = v });
    }
}

/// One trial of `test_store_policy_limits` on a fresh store.
fn check_limits(
    s: []const Write,
    updates: []const Write,
    writes: []const Write,
    live: []const Live,
    entries: usize,
    skips: u64,
) !void {
    var h: Harness(translator.OneCap) = undefined;
    try h.init();
    defer h.deinit();
    var db = try h.open();
    defer db.deinit();
    try hold(&db, s);
    try hold(&db, updates);
    try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
    try testing.expectEqual(@as(u64, 12), db.bounds().end);
    const tip = 12 + @as(u64, writes.len);
    var active: [16]u64 = undefined;
    for (live, active[0..live.len]) |l, *a| a.* = l.location;
    var model: std.ArrayList(u64) = .empty;
    defer model.deinit(gpa);
    const floor = try walk_model(active[0..live.len], 0, tip, entries, skips, &model);
    var decided: [16]Visit = undefined;
    for (model.items, decided[0..model.items.len]) |loc, *d| {
        for (live) |l| if (l.location == loc) {
            d.* = .{ .location = loc, .key = l.key, .value = l.value };
        };
    }
    var policy: Script = .{ .entries = entries, .skips = skips };
    defer policy.deinit();
    const range = try apply(&db, writes, &policy);
    try expect_visits(&policy, decided[0..model.items.len]);
    try testing.expectEqual(floor, db.inactivity_floor());
    // Each decided update moves to the tip with its value, after the writes.
    const end = tip + 1 + @as(u64, model.items.len);
    try testing.expectEqual(Range{ .start = 12, .end = end }, range);
    for (decided[0..model.items.len], tip..) |d, loc| {
        try expect_op(&db, loc, .{ .update = .{ .key = d.key, .value = d.value } });
    }
    for (live) |l| try expect_get(&db, l.key, l.value);
    for (writes) |w| if (w.value == null) try expect_get(&db, w.key, null);
    try testing.expectEqual(live.len, db.active_keys);
}

test "store policy limits decide what the walk model predicts" {
    // The initial commit at 0, superseded updates at 1..4, active updates at 4..7, the seed
    // commit at 7, active updates at 8..11, and the last commit at 11.
    const s = seed(6);
    var updates: [3]Write = undefined;
    for (&updates, s[0..3], 200..) |*u, w, i| u.* = .{ .key = w.key, .value = digest(i) };
    var applied: [6]Live = undefined;
    for (applied[0..3], s[3..], 4..) |*a, w, loc| a.* = live_at(loc, w);
    for (applied[3..], updates, 8..) |*a, w, loc| a.* = live_at(loc, w);
    // Updates the keys at 4 and 8, deletes the key at 5, and creates two keys, in key order.
    var writes = [_]Write{
        .{ .key = s[3].key, .value = digest(300) },
        .{ .key = s[0].key, .value = digest(301) },
        .{ .key = s[4].key, .value = null },
        .{ .key = digest(6), .value = digest(302) },
        .{ .key = digest(7), .value = digest(303) },
    };
    std.mem.sort(Write, &writes, {}, write_less);
    for ([_][]const Write{ &.{}, &writes }) |batch| {
        var live: std.ArrayList(Live) = .empty;
        defer live.deinit(gpa);
        try limits_live(&applied, batch, &live);
        std.mem.sort(Live, live.items, {}, struct {
            fn less(_: void, a: Live, b: Live) bool {
                return a.location < b.location;
            }
        }.less);
        try testing.expectEqual(6 + @as(usize, @intFromBool(batch.len > 0)), live.items.len);
        for (0..9) |entries| {
            for (0..14) |index| {
                const skips: u64 = if (index == 13) max_u64 else index;
                try check_limits(&s, &updates, batch, live.items, entries, skips);
            }
        }
    }
}
