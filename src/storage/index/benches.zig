//! Benchmarks of the indices (commonware `storage/src/index/benches`), with commonware's names
//! and inputs: inserting, retaining, and looking up (hits and misses) across the index variants
//! and translators, the grinding distribution against a partitioned ordered index, the hash map
//! baselines, and `index_scale`'s huge-count characterization.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const storage = @import("storage");
const utils = @import("utils");
const support = @import("../bench_support.zig");
const quick = support.quick;
const cases = support.cases;

const index = storage.index;
const translator = storage.translator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const TestRng = utils.TestRng;
const EightCap = translator.EightCap;
const Cap = translator.Cap;
const Hashed = translator.Hashed;

const Kv = struct { key: Digest, value: u64 };

/// `hash(i as big-endian u64)`, commonware's key for item `i`.
fn key_of(i: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, i, .big);
    return Sha256.hash(&.{&bytes});
}

/// The keys `key_of(i)` for `i` in `0..items` with values `i`, shuffled by `test_rng`.
fn shuffled_kvs(gpa: Allocator, items: usize) ![]Kv {
    assert(items > 0);
    const kvs = try gpa.alloc(Kv, items);
    for (kvs, 0..) |*kv, i| kv.* = .{ .key = key_of(i), .value = i };
    var rng = utils.test_rng();
    utils.rng.random(&rng).shuffle(Kv, kvs);
    assert(kvs.len == items);
    return kvs;
}

fn keys_of(gpa: Allocator, items: usize) ![]Digest {
    assert(items > 0);
    const keys = try gpa.alloc(Digest, items);
    for (keys, 0..) |*key, i| key.* = key_of(i);
    return keys;
}

/// One index variant as a type: its index type, name, and translator.
fn Variant(comptime I: type, comptime name: []const u8, comptime t: I.Translator) type {
    return struct {
        pub const Index = I;
        pub const label = name;
        pub const translator_value = t;
    };
}

fn Flat(comptime T: type) type {
    return index.unordered.Index(T, u64);
}

fn PartOrdered(comptime T: type, comptime P: usize) type {
    return index.partitioned.ordered.Index(T, u64, P);
}

fn PartUnordered(comptime T: type, comptime P: usize) type {
    return index.partitioned.unordered.Index(T, u64, P);
}

const insert_variants = .{
    Variant(index.ordered.Index(EightCap, u64), "ordered", .{}),
    Variant(Flat(EightCap), "unordered", .{}),
    Variant(PartOrdered(Cap(7), 1), "partitioned_ordered_1", .init(.{})),
    Variant(PartOrdered(Cap(6), 2), "partitioned_ordered_2", .init(.{})),
    Variant(PartUnordered(Cap(7), 1), "partitioned_unordered_1", .init(.{})),
    Variant(PartUnordered(Cap(6), 2), "partitioned_unordered_2", .init(.{})),
    Variant(Flat(Hashed(EightCap)), "hashed_unordered", .from_seed(0, .{})),
    Variant(
        PartUnordered(Hashed(Cap(7)), 1),
        "hashed_partitioned_unordered_1",
        .init(.from_seed(0, .{})),
    ),
    Variant(
        PartUnordered(Hashed(Cap(6)), 2),
        "hashed_partitioned_unordered_2",
        .init(.from_seed(0, .{})),
    ),
};

/// Builds a fresh index (untimed) before each iteration, then times inserting every pair.
fn InsertWorkload(comptime I: type) type {
    return struct {
        const Self = @This();
        gpa: Allocator,
        translator: I.Translator,
        kvs: []const Kv,
        retain: bool = false,
        index: ?I = null,

        pub fn before_iter(self: *Self) !void {
            self.teardown();
            self.index = I.init(self.gpa, self.translator);
            if (!self.retain) return;
            // Seed the index, so the timed pass overwrites every key.
            for (self.kvs) |kv| try self.index.?.insert(&kv.key.bytes, kv.value);
            assert(self.index.?.items() == self.kvs.len);
        }

        pub fn iter(self: *Self) !u64 {
            const target = &self.index.?;
            if (self.retain) {
                for (self.kvs) |kv| {
                    try target.insert_and_retain(&kv.key.bytes, kv.value + 1, kv.value, differs);
                }
            } else {
                for (self.kvs) |kv| try target.insert(&kv.key.bytes, kv.value);
            }
            return target.items();
        }

        pub fn teardown(self: *Self) void {
            if (self.index) |*built| built.deinit();
            self.index = null;
        }

        fn differs(old: u64, value: *const u64) bool {
            return value.* != old;
        }
    };
}

fn bench_insert(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000, 100_000, 500_000, 1_000_000 },
    );
    for (cases(usize, runner, sizes, 1)) |items| {
        const kvs = try shuffled_kvs(gpa, items);
        defer gpa.free(kvs);
        // A quick run takes the ordered and unordered variants only.
        const variant_count: usize = if (quick(runner)) 2 else insert_variants.len;
        inline for (insert_variants, 0..) |V, variant_index| if (variant_index < variant_count) {
            const benchmark = bench.Benchmark.init("index::insert")
                .with_param("variant", V.label)
                .with_param("items", items);
            var workload: InsertWorkload(V.Index) = .{
                .gpa = gpa,
                .translator = V.translator_value,
                .kvs = kvs,
            };
            defer workload.teardown();
            try runner.run(benchmark, &workload);
        };
    }
}

fn bench_insert_and_retain(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000, 100_000, 500_000 },
    );
    for (cases(usize, runner, sizes, 1)) |items| {
        const kvs = try shuffled_kvs(gpa, items);
        defer gpa.free(kvs);
        const benchmark = bench.Benchmark.init("index::insert_and_retain")
            .with_param("items", items);
        var workload: InsertWorkload(Flat(translator.FourCap)) = .{
            .gpa = gpa,
            .translator = .{},
            .kvs = kvs,
            .retain = true,
        };
        defer workload.teardown();
        try runner.run(benchmark, &workload);
    }
}

/// Times `get` on every key of a prebuilt index: the first value only (`first`), as
/// commonware's `get(key).next()`, or every value (`all`).
fn LookupWorkload(comptime I: type, comptime n: usize) type {
    return struct {
        const Self = @This();
        target: *const I,
        keys: []const [n]u8,
        mode: enum { first, all },

        pub fn iter(self: *Self) u64 {
            var sum: u64 = 0;
            for (self.keys) |*key| {
                var values = self.target.get(key);
                switch (self.mode) {
                    .first => sum += @intFromBool(values.next() != null),
                    .all => while (values.next()) |value| {
                        sum +%= value.*;
                    },
                }
            }
            return sum;
        }
    };
}

fn digest_bytes(gpa: Allocator, keys: []const Digest) ![][32]u8 {
    const bytes = try gpa.alloc([32]u8, keys.len);
    for (bytes, keys) |*out, *key| out.* = key.bytes;
    return bytes;
}

/// Benchmarks `get` of every inserted key, in shuffled order, on the index variant `V`.
fn run_lookup(
    runner: *bench.Runner,
    comptime V: type,
    comptime param: []const u8,
    items: usize,
    keys: []const Digest,
) !void {
    const gpa = runner.allocator;
    var target = V.Index.init(gpa, V.translator_value);
    defer target.deinit();
    for (keys[0..items], 0..) |*key, i| try target.insert(&key.bytes, i);
    const lookups = try digest_bytes(gpa, keys[0..items]);
    defer gpa.free(lookups);
    var rng = TestRng.init(1);
    utils.rng.random(&rng).shuffle([32]u8, lookups);
    const benchmark = bench.Benchmark.init("index::lookup")
        .with_param(param, V.label)
        .with_param("items", items);
    var workload: LookupWorkload(V.Index, 32) = .{
        .target = &target,
        .keys = lookups,
        .mode = .first,
    };
    try runner.run(benchmark, &workload);
    assert(workload.iter() == items);
}

const lookup_translators = .{
    Variant(Flat(translator.OneCap), "one_cap", .{}),
    Variant(Flat(translator.TwoCap), "two_cap", .{}),
    Variant(Flat(translator.FourCap), "four_cap", .{}),
    Variant(Flat(EightCap), "eight_cap", .{}),
};

fn bench_lookup(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000, 100_000, 500_000, 1_000_000 },
    );
    const sizes_run = cases(usize, runner, sizes, 1);
    const keys = try keys_of(gpa, sizes_run[sizes_run.len - 1]);
    defer gpa.free(keys);
    for (sizes_run) |items| {
        // Sweep translators, and both partitioned variants at P=2. A quick run takes one cap
        // and the partitioned ordered variant.
        inline for (lookup_translators, 0..) |V, i| if (i == 0 or !quick(runner)) {
            try run_lookup(runner, V, "translator", items, keys);
        };
        try run_lookup(
            runner,
            Variant(PartOrdered(Cap(6), 2), "partitioned_ordered_2", .init(.{})),
            "variant",
            items,
            keys,
        );
        if (quick(runner)) continue;
        try run_lookup(
            runner,
            Variant(PartUnordered(Cap(6), 2), "partitioned_unordered_2", .init(.{})),
            "variant",
            items,
            keys,
        );
    }
}

/// Lookups per miss benchmark.
const N_LOOKUPS: usize = 10_000;

/// `count` keys after the inserted ones whose translated keys are distinct and absent, so no two
/// probes hit the same empty bucket.
fn translated_key_misses(
    gpa: Allocator,
    comptime T: type,
    inserted: []const Digest,
    count: usize,
) ![][32]u8 {
    const Context = index.storage.Context(T);
    var seen: std.HashMapUnmanaged(T.Key, void, Context, 80) = .empty;
    defer seen.deinit(gpa);
    const context: Context = .{ .translator = .{} };
    for (inserted) |*key| try seen.putContext(gpa, T.transform(.{}, &key.bytes), {}, context);
    const misses = try gpa.alloc([32]u8, count);
    errdefer gpa.free(misses);
    var found: usize = 0;
    var i: u64 = inserted.len;
    while (found < count) : (i += 1) {
        const key = key_of(i);
        const entry = try seen.getOrPutContext(gpa, T.transform(.{}, &key.bytes), context);
        if (entry.found_existing) continue;
        misses[found] = key.bytes;
        found += 1;
    }
    assert(found == count);
    return misses;
}

fn run_lookup_miss(
    runner: *bench.Runner,
    comptime T: type,
    comptime name: []const u8,
    items: usize,
    inserted: []const Digest,
) !void {
    const gpa = runner.allocator;
    const misses = try translated_key_misses(gpa, T, inserted[0..items], N_LOOKUPS);
    defer gpa.free(misses);
    var target = Flat(T).init(gpa, .{});
    defer target.deinit();
    for (inserted[0..items], 0..) |*key, i| try target.insert(&key.bytes, i);
    const benchmark = bench.Benchmark.init("index::lookup_miss")
        .with_param("translator", name)
        .with_param("items", items);
    var workload: LookupWorkload(Flat(T), 32) = .{
        .target = &target,
        .keys = misses,
        .mode = .first,
    };
    try runner.run(benchmark, &workload);
    assert(workload.iter() == 0);
}

fn bench_lookup_miss(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000, 100_000, 500_000, 1_000_000 },
    );
    const sizes_run = cases(usize, runner, sizes, 1);
    const inserted = try keys_of(gpa, sizes_run[sizes_run.len - 1]);
    defer gpa.free(inserted);
    for (sizes_run) |items| {
        // OneCap cannot produce translated-key misses at these sizes.
        if (items <= std.math.maxInt(u16)) {
            try run_lookup_miss(runner, translator.TwoCap, "two_cap", items, inserted);
        }
        if (quick(runner)) continue; // A quick run takes two_cap only.
        try run_lookup_miss(runner, translator.FourCap, "four_cap", items, inserted);
        try run_lookup_miss(runner, EightCap, "eight_cap", items, inserted);
    }
}

const Grinding = PartOrdered(Cap(6), 2);

/// 8-byte keys: `grinding` takes the big-endian index, so every key lands in partition 0 with a
/// distinct translated suffix; `uniform` hashes the index so keys spread across partitions.
fn grinding_keys(gpa: Allocator, items: usize, grinding: bool) ![][8]u8 {
    const keys = try gpa.alloc([8]u8, items);
    for (keys, 0..) |*key, i| {
        if (grinding) {
            std.mem.writeInt(u64, key, i, .big);
        } else {
            key.* = key_of(i).bytes[0..8].*;
        }
    }
    return keys;
}

/// Builds an empty grinding index (untimed) before each iteration, then times inserting every
/// key.
const GrindingInsert = struct {
    gpa: Allocator,
    keys: []const [8]u8,
    index: ?Grinding = null,

    pub fn before_iter(self: *GrindingInsert) !void {
        self.teardown();
        self.index = Grinding.init(self.gpa, .init(.{}));
    }

    pub fn iter(self: *GrindingInsert) !u64 {
        const target = &self.index.?;
        for (self.keys, 0..) |*key, i| try target.insert(key, i);
        return target.items();
    }

    pub fn teardown(self: *GrindingInsert) void {
        if (self.index) |*built| built.deinit();
        self.index = null;
    }
};

fn bench_grinding(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000 },
        &.{ 10_000, 50_000, 200_000 },
    );
    for (cases(usize, runner, sizes, 1)) |items| {
        for ([_]bool{ false, true }) |grinding| {
            const dist: []const u8 = if (grinding) "grinding" else "uniform";
            const keys = try grinding_keys(gpa, items, grinding);
            defer gpa.free(keys);
            const prefix = bench.Benchmark.init("index::grinding");
            var insert: GrindingInsert = .{ .gpa = gpa, .keys = keys };
            defer insert.teardown();
            const insert_name = prefix.with_param("op", "insert").with_param("dist", dist);
            try runner.run(insert_name.with_param("items", items), &insert);

            // Build once outside the timed region; the lookup bench measures only `get`.
            var target = Grinding.init(gpa, .init(.{}));
            defer target.deinit();
            for (keys, 0..) |*key, i| try target.insert(key, i);
            var lookup: LookupWorkload(Grinding, 8) = .{
                .target = &target,
                .keys = keys,
                .mode = .all,
            };
            const lookup_name = prefix.with_param("op", "lookup").with_param("dist", dist);
            try runner.run(lookup_name.with_param("items", items), &lookup);
        }
    }
}

/// The value commonware's hash map baselines store: a journal location.
const MockIndex = struct { section: u64, offset: u32, len: u32 };

/// Draws `n` keys of `k` bytes, each followed by a random `MockIndex`, from `rng`.
fn mock_entries(rng: *TestRng, keys: []u8, values: []MockIndex, k: usize) void {
    assert(keys.len == values.len * k);
    for (values, 0..) |*value, i| {
        rng.fill_bytes(keys[i * k ..][0..k]);
        value.* = .{ .section = rng.next_u64(), .offset = rng.next_u32(), .len = rng.next_u32() };
    }
}

/// Draws the entries (untimed) before each iteration, then times inserting them into an empty
/// hash map (`insert`), or builds the map untimed and times iterating it (`iterate`). Either
/// way the timed routine drops the map, as commonware's routine consumes it.
const HashMapWorkload = struct {
    gpa: Allocator,
    n: usize,
    k: usize,
    mode: enum { insert, insert_fixed, iterate },
    keys: []u8 = &.{},
    values: []MockIndex = &.{},
    map: std.StringHashMapUnmanaged(MockIndex) = .empty,

    pub fn setup(self: *HashMapWorkload) !void {
        assert(self.n > 0 and self.k > 0);
        self.keys = try self.gpa.alloc(u8, self.n * self.k);
        self.values = try self.gpa.alloc(MockIndex, self.n);
    }

    pub fn before_iter(self: *HashMapWorkload) !void {
        // Commonware seeds the fixed-key baseline with `n`, the others with `n ^ k`.
        const salt: u64 = if (self.mode == .insert_fixed) 0 else self.k;
        var rng = TestRng.init(@as(u64, self.n) ^ salt);
        mock_entries(&rng, self.keys, self.values, self.k);
        if (self.mode != .iterate) return;
        try self.map.ensureTotalCapacity(self.gpa, @intCast(self.n));
        for (self.values, 0..) |value, i| {
            self.map.putAssumeCapacity(self.keys[i * self.k ..][0..self.k], value);
        }
    }

    pub fn iter(self: *HashMapWorkload) !u64 {
        defer self.map = .empty;
        defer self.map.deinit(self.gpa);
        switch (self.mode) {
            .insert => for (self.values, 0..) |value, i| {
                try self.map.put(self.gpa, self.keys[i * self.k ..][0..self.k], value);
            },
            .insert_fixed => return self.insert_fixed(),
            .iterate => {
                var sum: u64 = 0;
                var values = self.map.valueIterator();
                while (values.next()) |value| sum +%= value.section;
                return sum;
            },
        }
        return self.map.count();
    }

    /// Commonware's fixed-key baseline: `[u8; 4]` keys hashed by value.
    fn insert_fixed(self: *HashMapWorkload) !u64 {
        assert(self.k == 4);
        var map: std.AutoHashMapUnmanaged([4]u8, MockIndex) = .empty;
        defer map.deinit(self.gpa);
        for (self.values, 0..) |value, i| try map.put(self.gpa, self.keys[i * 4 ..][0..4].*, value);
        return map.count();
    }

    pub fn teardown(self: *HashMapWorkload) void {
        self.map.deinit(self.gpa);
        self.map = .empty;
        self.gpa.free(self.keys);
        self.gpa.free(self.values);
        self.keys = &.{};
        self.values = &.{};
    }
};

fn bench_hashmaps(runner: *bench.Runner) !void {
    const sizes = runner.inputs.pick(
        []const usize,
        &.{100_000},
        &.{100_000},
        &.{ 100_000, 1_000_000, 10_000_000 },
    );
    const Case = struct { prefix: []const u8, mode: @FieldType(HashMapWorkload, "mode") };
    const hashmap_cases = [_]Case{
        .{ .prefix = "index::hashmap_iteration", .mode = .iterate },
        .{ .prefix = "index::hashmap_insert_fixed", .mode = .insert_fixed },
        .{ .prefix = "index::hashmap_insert", .mode = .insert },
    };
    for (hashmap_cases) |case| {
        for (sizes) |n| {
            const all_widths: []const usize = &.{ 4, 8, 16, 32 };
            const widths_all = if (case.mode == .insert_fixed) all_widths[0..1] else all_widths;
            const widths = cases(usize, runner, widths_all, 1);
            for (widths) |k| {
                const benchmark = bench.Benchmark.init(case.prefix).with_param("n", n)
                    .with_param("k", k);
                var workload: HashMapWorkload = .{
                    .gpa = runner.allocator,
                    .n = n,
                    .k = k,
                    .mode = case.mode,
                };
                try runner.run(benchmark, &workload);
            }
        }
    }
}

/// `index_scale`'s default tier: 20M keys gives about 1.2 entries per P=3 partition.
const scale_items_full = [_]u64{ 20_000_000, 100_000_000 };
/// A size small enough for `zig build test` to run every variant once.
const scale_items_smoke = [_]u64{10_000};
/// Default `get_many` batch size, the updates per commit in qmdb's `scale` bench.
const scale_batch: usize = 10_000;
/// Fixed seed so the insert and lookup phases replay the same keys.
const scale_seed: u64 = 0;

const scale_variants = .{
    Variant(PartOrdered(Cap(5), 3), "partitioned_ordered_3", .init(.{})),
    Variant(PartOrdered(EightCap, 3), "partitioned_ordered_3_eightcap", .init(.{})),
    Variant(Flat(EightCap), "unordered", .{}),
    Variant(PartUnordered(Cap(7), 1), "partitioned_unordered_1", .init(.{})),
    Variant(PartUnordered(Cap(6), 2), "partitioned_unordered_2", .init(.{})),
    Variant(index.ordered.Index(EightCap, u64), "ordered", .{}),
};

/// Builds index `I` once from `items` seeded keys, then looks every key up one at a time and
/// in sorted batches, timing each phase (`index_scale`'s `measure`). Keys are not stored: each
/// phase re-seeds to replay them.
fn ScaleWorkload(comptime I: type) type {
    return struct {
        const Self = @This();
        gpa: Allocator,
        io: std.Io,
        translator: I.Translator,
        items: u64,
        insert_ns: u64 = 0,
        lookup_ns: u64 = 0,
        many_ns: u64 = 0,

        pub fn iter(self: *Self) !u64 {
            var target = I.init(self.gpa, self.translator);
            defer target.deinit();
            var rng = TestRng.init(scale_seed);
            var start = now(self.io);
            for (0..self.items) |value| try target.insert(&be(rng.next_u64()), value);
            self.insert_ns = now(self.io) - start;
            assert(target.items() == self.items);

            rng = TestRng.init(scale_seed);
            var sum: u64 = 0;
            start = now(self.io);
            for (0..self.items) |_| {
                var values = target.get(&be(rng.next_u64()));
                while (values.next()) |value| sum +%= value.*;
            }
            self.lookup_ns = now(self.io) - start;
            return sum +% try self.lookup_many(&target);
        }

        fn lookup_many(self: *Self, target: *const I) !u64 {
            const keys = try self.gpa.alloc([8]u8, scale_batch);
            defer self.gpa.free(keys);
            const lookups = try self.gpa.alloc([]const u8, scale_batch);
            defer self.gpa.free(lookups);
            var rng = TestRng.init(scale_seed);
            var sum: u64 = 0;
            var remaining = self.items;
            self.many_ns = 0;
            while (remaining > 0) {
                const n: usize = @intCast(@min(remaining, scale_batch));
                for (keys[0..n]) |*key| key.* = be(rng.next_u64());
                std.sort.pdq([8]u8, keys[0..n], {}, less_bytes);
                for (lookups[0..n], keys[0..n]) |*lookup, *key| lookup.* = key;
                const start = now(self.io);
                target.get_many(lookups[0..n], &sum, add_value);
                self.many_ns += now(self.io) - start;
                remaining -= n;
            }
            return sum;
        }

        pub fn metrics(self: *const Self, buffer: []bench.Metric) []const bench.Metric {
            assert(buffer.len >= 3 and self.items > 0);
            buffer[0] = .init("insert_ns_per_op", self.insert_ns / self.items);
            buffer[1] = .init("lookup_ns_per_op", self.lookup_ns / self.items);
            buffer[2] = .init("get_many_ns_per_op", self.many_ns / self.items);
            return buffer[0..3];
        }
    };
}

fn be(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

fn now(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn less_bytes(_: void, a: [8]u8, b: [8]u8) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn add_value(sum: *u64, _: usize, value: *const u64) void {
    sum.* +%= value.*;
}

/// `index_scale`: opt-in in commonware, so standard inputs skip it. Full inputs build each
/// variant once per size and print commonware's ns/op line; smoke inputs run a tiny size once.
fn bench_scale(runner: *bench.Runner) !void {
    if (runner.inputs == .standard) return;
    const full = runner.inputs == .full;
    const sizes: []const u64 = if (full) &scale_items_full else &scale_items_smoke;
    for (sizes) |items| {
        // A quick run takes the P=3 partitioned ordered variant only.
        const variant_count: usize = if (quick(runner)) 1 else scale_variants.len;
        inline for (scale_variants, 0..) |V, variant_index| if (variant_index < variant_count) {
            const benchmark = bench.Benchmark.init("index_scale").with_param("variant", V.label)
                .with_param("items", items).with_param("batch", scale_batch);
            var workload: ScaleWorkload(V.Index) = .{
                .gpa = runner.allocator,
                .io = runner.io,
                .translator = V.translator_value,
                .items = items,
            };
            if (runner.inputs == .smoke or runner.list) {
                try runner.run(benchmark, &workload);
            } else if (runner.matches(benchmark.name())) {
                _ = try bench.criterion(runner.io, &workload, 1);
                try runner.out.print(
                    "  {s:<32} insert={d} ns/op  lookup={d} ns/op  " ++
                        "get_many(batch={d})={d} ns/op\n",
                    .{
                        V.label,                    workload.insert_ns / items,
                        workload.lookup_ns / items, scale_batch,
                        workload.many_ns / items,
                    },
                );
                try runner.out.flush();
            }
        };
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_grinding(runner);
    try bench_hashmaps(runner);
    try bench_insert(runner);
    try bench_insert_and_retain(runner);
    try bench_lookup(runner);
    try bench_lookup_miss(runner);
    try bench_scale(runner);
}
