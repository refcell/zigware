//! Benchmarks of the Merkle structures (commonware `storage/src/merkle/benches`), with
//! commonware's names and inputs, over both families (MMR and MMB): appending, bulk adds,
//! flushing a journaled structure, leaf updates, position conversion, and generating and
//! verifying single, range, and multi proofs.
//!
//! Zigware's batches hash sequentially, so commonware's parallel cases (`workers=8`,
//! `strategy=BatchedParallel`) keep their names but measure the sequential path. The proof
//! benchmarks share one tree per family and size (setup is untimed either way), so they run
//! tree by tree rather than in commonware's group order.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const Disk = @import("../bench_support.zig").Disk;
const support = @import("../bench_support.zig");
const quick = support.quick;
const cases = support.cases;

const merkle = storage.merkle;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const TestRng = utils.TestRng;
const Hasher = merkle.hasher.Standard(Sha256);
const hasher: Hasher = .init(.forward_fold);

fn Mem(comptime F: type) type {
    return merkle.mem.Mem(F, Digest);
}

const families = .{
    .{ storage.mmr.Family, "mmr" },
    .{ storage.mmb.Family, "mmb" },
};

/// Number of leaves or ranges sampled from each tree.
const SAMPLE_SIZE: usize = 100;

fn n_leaves(runner: *const bench.Runner) []const usize {
    if (quick(runner)) return &.{10_000};
    return runner.inputs.pick(
        []const usize,
        &.{ 10_000, 100_000 },
        &.{ 10_000, 100_000 },
        &.{ 10_000, 100_000, 1_000_000, 5_000_000, 10_000_000 },
    );
}

fn random_digests(gpa: Allocator, rng: *TestRng, n: usize) ![]Digest {
    const digests = try gpa.alloc(Digest, n);
    for (digests) |*digest| digest.* = .random(utils.rng.random(rng));
    return digests;
}

/// Adds `elements` to `mem` in one batch and applies it.
fn append_all(comptime F: type, gpa: Allocator, mem: *Mem(F), elements: []const Digest) !void {
    var batch = try mem.new_batch(gpa);
    errdefer batch.deinit(gpa);
    for (elements) |*element| try batch.add(gpa, &hasher, &element.bytes);
    const merkleized = try batch.merkleize(gpa, mem, &hasher);
    defer merkleized.release(gpa);
    try mem.apply_batch(gpa, merkleized);
    assert(mem.leaves() >= elements.len);
}

/// An in-memory tree of `n` random elements, its root, and the elements in location order.
fn Tree(comptime F: type) type {
    return struct {
        const Self = @This();
        mem: Mem(F) = .empty,
        root: Digest,
        elements: []Digest,

        fn build(gpa: Allocator, n: usize) !Self {
            var rng = utils.test_rng();
            const elements = try random_digests(gpa, &rng, n);
            errdefer gpa.free(elements);
            var mem: Mem(F) = .empty;
            errdefer mem.deinit(gpa);
            try append_all(F, gpa, &mem, elements);
            const root = try mem.root(&hasher, 0);
            return .{ .mem = mem, .root = root, .elements = elements };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            self.mem.deinit(gpa);
            gpa.free(self.elements);
            self.* = undefined;
        }
    };
}

/// Samples `out.len` distinct locations below `n` (Floyd's algorithm), in ascending order.
fn sample_locations(rng: *TestRng, n: u64, out: []u64) void {
    assert(out.len <= n);
    for (n - out.len..n, 0..) |bound, count| {
        const candidate = utils.rng.range_at_most(rng, u64, 0, bound);
        const taken = std.mem.indexOfScalar(u64, out[0..count], candidate) != null;
        out[count] = if (taken) bound else candidate;
    }
    std.sort.pdq(u64, out, {}, std.sort.asc(u64));
    assert(out.len < 2 or out[0] < out[out.len - 1]);
}

/// `SAMPLE_SIZE` ranges of `range` leaves with distinct starts, as commonware's
/// `range_samples`.
fn sample_ranges(rng: *TestRng, n: u64, range: u64, out: *[SAMPLE_SIZE]merkle.Range) void {
    assert(range < n);
    var count: usize = 0;
    while (count < SAMPLE_SIZE) {
        const start = utils.rng.range_less_than(rng, u64, 0, n - range);
        const taken = for (out[0..count]) |r| {
            if (r.start == start) break true;
        } else false;
        if (taken) continue;
        out[count] = .{ .start = start, .end = start + range };
        count += 1;
    }
}

const ProofKind = enum { single, range, multi, verify_single, verify_range, verify_multi };

/// Generates (`single`, `range`, `multi`) or verifies (`verify_*`) proofs of the sampled leaves
/// or ranges of one tree; the proofs a verification checks are generated in `setup`.
fn ProofWorkload(comptime F: type) type {
    return struct {
        const Self = @This();
        const Proof = Mem(F).Proof;
        gpa: Allocator,
        tree: *const Tree(F),
        kind: ProofKind,
        locations: []const u64 = &.{},
        ranges: []const merkle.Range = &.{},
        proofs: [SAMPLE_SIZE]Proof = undefined,
        proofs_len: usize = 0,
        elements: [SAMPLE_SIZE]Digest = undefined,

        pub fn setup(self: *Self) !void {
            assert(self.proofs_len == 0);
            const mem = &self.tree.mem;
            switch (self.kind) {
                .single, .range, .multi => {},
                .verify_single => for (self.locations) |location| {
                    self.proofs[self.proofs_len] = try mem.proof(self.gpa, &hasher, location, 0);
                    self.proofs_len += 1;
                },
                .verify_range => for (self.ranges) |range| {
                    self.proofs[self.proofs_len] = try mem.range_proof(self.gpa, &hasher, range, 0);
                    self.proofs_len += 1;
                },
                .verify_multi => {
                    for (self.locations, 0..) |location, i| {
                        self.elements[i] = self.tree.elements[@intCast(location)];
                    }
                    self.proofs[0] = try self.multi_proof();
                    self.proofs_len = 1;
                },
            }
        }

        fn multi_proof(self: *const Self) !Proof {
            return merkle.verification.multi_proof(F, self.gpa, &self.tree.mem, 0, self.locations);
        }

        pub fn iter(self: *Self) !usize {
            const mem = &self.tree.mem;
            var total: usize = 0;
            switch (self.kind) {
                .single => for (self.locations) |location| {
                    var proof = try mem.proof(self.gpa, &hasher, location, 0);
                    total += proof.digests.len;
                    proof.deinit(self.gpa);
                },
                .range => for (self.ranges) |range| {
                    var proof = try mem.range_proof(self.gpa, &hasher, range, 0);
                    total += proof.digests.len;
                    proof.deinit(self.gpa);
                },
                .multi => {
                    var proof = try self.multi_proof();
                    total += proof.digests.len;
                    proof.deinit(self.gpa);
                },
                .verify_single, .verify_range, .verify_multi => total += try self.verify(),
            }
            return total;
        }

        fn verify(self: *const Self) !usize {
            const root = &self.tree.root;
            const elements = self.tree.elements;
            switch (self.kind) {
                .verify_single => for (self.proofs[0..self.proofs_len], self.locations) |*p, l| {
                    const element = &elements[@intCast(l)].bytes;
                    if (!p.verify_element_inclusion(&hasher, l, element, root)) unreachable;
                },
                .verify_range => for (self.proofs[0..self.proofs_len], self.ranges) |*p, r| {
                    const proven = elements[@intCast(r.start)..@intCast(r.end)];
                    if (!p.verify_range_inclusion(&hasher, r.start, proven, root)) unreachable;
                },
                .verify_multi => {
                    const proven = self.elements[0..self.locations.len];
                    const p = &self.proofs[0];
                    const ok = try p.verify_multi_inclusion(
                        self.gpa,
                        &hasher,
                        self.locations,
                        proven,
                        root,
                    );
                    if (!ok) unreachable;
                },
                else => unreachable,
            }
            return self.proofs_len;
        }

        pub fn teardown(self: *Self) void {
            for (self.proofs[0..self.proofs_len]) |*proof| proof.deinit(self.gpa);
            self.proofs_len = 0;
        }
    };
}

const ranges_swept = [_]u64{ 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000 };

/// Every proof benchmark on one tree of `n` leaves of family `F`.
fn bench_proofs_on(
    runner: *bench.Runner,
    comptime F: type,
    comptime family: []const u8,
    n: usize,
) !void {
    const gpa = runner.allocator;
    // Listing runs no workload, so it skips building the tree.
    const unbuilt: Tree(F) = .{ .root = undefined, .elements = &.{} };
    var tree: Tree(F) = if (runner.list) unbuilt else try .build(gpa, n);
    defer tree.deinit(gpa);
    var locations: [SAMPLE_SIZE]u64 = undefined;
    var rng = utils.test_rng();
    sample_locations(&rng, n, &locations);
    var workload: ProofWorkload(F) = .{ .gpa = gpa, .tree = &tree, .kind = .multi };
    workload.locations = &locations;
    const Case = struct { prefix: []const u8, kind: ProofKind, count: []const u8 };
    const located = [_]Case{
        .{ .prefix = "merkle::multi_proof", .kind = .multi, .count = "items" },
        .{ .prefix = "merkle::proof", .kind = .single, .count = "samples" },
        .{ .prefix = "merkle::verify_single_element", .kind = .verify_single, .count = "samples" },
        .{ .prefix = "merkle::verify_multi", .kind = .verify_multi, .count = "items" },
    };
    for (located) |case| {
        workload.kind = case.kind;
        const benchmark = bench.Benchmark.init(case.prefix).with_param("n", n)
            .with_param(case.count, SAMPLE_SIZE).with_param("family", family);
        try runner.run(benchmark, &workload);
    }
    var ranges: [SAMPLE_SIZE]merkle.Range = undefined;
    for (cases(u64, runner, &ranges_swept, 1)) |range| {
        rng = utils.test_rng();
        sample_ranges(&rng, n, range, &ranges);
        workload.ranges = &ranges;
        for ([_]ProofKind{ .range, .verify_range }) |kind| {
            workload.kind = kind;
            const prefix = switch (kind) {
                .range => "merkle::range_proof",
                else => "merkle::verify_many_elements",
            };
            const benchmark = bench.Benchmark.init(prefix).with_param("n", n)
                .with_param("range", range).with_param("samples", SAMPLE_SIZE)
                .with_param("family", family);
            try runner.run(benchmark, &workload);
        }
    }
}

fn bench_proofs(runner: *bench.Runner) !void {
    inline for (families, 0..) |family, family_index| {
        // A quick run takes MMR only.
        if (family_index == 0 or !quick(runner)) {
            for (n_leaves(runner)) |n| try bench_proofs_on(runner, family[0], family[1], n);
        }
    }
}

/// Positions converted per iteration.
const SAMPLES: usize = 4096;

/// Converts `SAMPLES` leaf positions, drawn from leaf counts below a bound, back to locations.
fn PositionWorkload(comptime F: type) type {
    return struct {
        positions: [SAMPLES]u64,

        pub fn iter(self: *@This()) u64 {
            var sum: u64 = 0;
            for (self.positions) |position| sum +%= F.position_to_location(position).?;
            return sum;
        }
    };
}

fn bench_position_to_location(runner: *bench.Runner) !void {
    const sizes = runner.inputs.pick(
        []const u64,
        &.{ 1_000_000, 1_000_000_000_000 },
        &.{ 1_000_000, 1_000_000_000_000 },
        &.{ 1_000_000, 1_000_000_000_000, 1 << 62 },
    );
    const sizes_run = cases(u64, runner, sizes, 1);
    inline for (families, 0..) |family, family_index| {
        // A quick run takes MMR only.
        if (family_index == 0 or !quick(runner)) {
            const F = family[0];
            for (sizes_run) |n| {
                var rng = utils.test_rng();
                var workload: PositionWorkload(F) = undefined;
                for (&workload.positions) |*position| {
                    position.* = F.location_to_position(utils.rng.range_less_than(&rng, u64, 0, n));
                }
                const benchmark = bench.Benchmark.init("merkle::position_to_location")
                    .with_param("n", n).with_param("family", family[1]);
                try runner.run(benchmark, &workload);
            }
        }
    }
}

/// Times building a tree from `elements` in one batch (`append`), or merkleizing a batch of
/// `additional` elements on a prebuilt tree without applying it (`append_additional`).
fn AppendWorkload(comptime F: type) type {
    return struct {
        const Self = @This();
        gpa: Allocator,
        elements: []const Digest,
        base: ?*const Mem(F) = null,
        built: Mem(F) = .empty,

        pub fn before_iter(self: *Self) void {
            self.teardown();
        }

        pub fn iter(self: *Self) !u64 {
            const base = self.base orelse {
                try append_all(F, self.gpa, &self.built, self.elements);
                return self.built.size();
            };
            var batch = try base.new_batch(self.gpa);
            errdefer batch.deinit(self.gpa);
            for (self.elements) |*element| try batch.add(self.gpa, &hasher, &element.bytes);
            const merkleized = try batch.merkleize(self.gpa, base, &hasher);
            defer merkleized.release(self.gpa);
            return merkleized.size();
        }

        pub fn teardown(self: *Self) void {
            self.built.deinit(self.gpa);
            self.built = .empty;
        }
    };
}

fn bench_append(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    inline for (families, 0..) |family, family_index| {
        // A quick run takes MMR only.
        if (family_index == 0 or !quick(runner)) {
            for (n_leaves(runner)) |n| {
                var rng = utils.test_rng();
                const elements = try random_digests(gpa, &rng, n);
                defer gpa.free(elements);
                var workload: AppendWorkload(family[0]) = .{ .gpa = gpa, .elements = elements };
                defer workload.teardown();
                const benchmark = bench.Benchmark.init("merkle::append").with_param("n", n)
                    .with_param("family", family[1]);
                try runner.run(benchmark, &workload);
            }
        }
    }
}

const additions = [_]usize{ 100, 1_000, 10_000, 50_000 };

/// Commonware rebuilds the tree before each iteration; merkleizing without applying leaves it
/// unchanged, so one tree per size serves every iteration and addition count.
fn bench_append_additional(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    inline for (families, 0..) |family, family_index| {
        // A quick run takes MMR only.
        if (family_index == 0 or !quick(runner)) {
            const F = family[0];
            for (n_leaves(runner)) |n| {
                var rng = utils.test_rng();
                const elements = try random_digests(gpa, &rng, n);
                defer gpa.free(elements);
                const additional = try random_digests(gpa, &rng, additions[additions.len - 1]);
                defer gpa.free(additional);
                var base: Mem(F) = .empty;
                defer base.deinit(gpa);
                if (!runner.list) try append_all(F, gpa, &base, elements);
                for (cases(usize, runner, &additions, 1)) |a| {
                    var workload: AppendWorkload(F) = .{
                        .gpa = gpa,
                        .elements = additional[0..a],
                        .base = &base,
                    };
                    const benchmark = bench.Benchmark.init("merkle::append_additional")
                        .with_param("start", n).with_param("add", a)
                        .with_param("family", family[1]);
                    try runner.run(benchmark, &workload);
                }
            }
        }
    }
}

/// Leaves already in the tree for `add_many` (deliberately not a power of two).
const COMMITTED: u64 = 100_003;
/// Batch sizes for small items, with powers of two and not.
const ITEMS = [_]usize{ 100, 128, 1_000, 8_192, 65_536 };
/// Size of each small item in bytes.
const SMALL: usize = 64;
/// Items in each skewed batch.
const SKEWED_ITEMS: usize = 512;
/// Large items at the front of a clustered batch.
const CLUSTERED: usize = 64;
const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
/// Workers in commonware's parallel strategy (zigware hashes sequentially).
const WORKERS: usize = 8;

/// A tree of `COMMITTED` leaves, leaf `i` holding `i` as big-endian bytes.
fn committed(comptime F: type, gpa: Allocator) !Mem(F) {
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    var batch = try mem.new_batch(gpa);
    errdefer batch.deinit(gpa);
    for (0..COMMITTED) |i| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, i, .big);
        try batch.add(gpa, &hasher, &bytes);
    }
    const merkleized = try batch.merkleize(gpa, &mem, &hasher);
    defer merkleized.release(gpa);
    try mem.apply_batch(gpa, merkleized);
    assert(mem.leaves() == COMMITTED);
    return mem;
}

/// Times `add_many` of `items` on a batch over the committed tree, then `merkleize`.
fn AddManyWorkload(comptime F: type) type {
    return struct {
        gpa: Allocator,
        mem: *const Mem(F),
        items: []const []const u8,

        pub fn iter(self: *@This()) !u64 {
            var batch = try self.mem.new_batch(self.gpa);
            errdefer batch.deinit(self.gpa);
            try batch.add_many(self.gpa, &hasher, []const u8, self.items);
            const merkleized = try batch.merkleize(self.gpa, self.mem, &hasher);
            defer merkleized.release(self.gpa);
            return merkleized.size();
        }
    };
}

/// Runs `items` as commonware's one-worker and `WORKERS`-worker cases.
fn bench_workers(
    runner: *bench.Runner,
    comptime F: type,
    params: bench.Benchmark,
    family: []const u8,
    mem: *const Mem(F),
    items: []const []const u8,
) !void {
    var workload: AddManyWorkload(F) = .{ .gpa = runner.allocator, .mem = mem, .items = items };
    for (cases(usize, runner, &.{ 1, WORKERS }, 1)) |workers| {
        const benchmark = params.with_param("workers", workers).with_param("family", family);
        try runner.run(benchmark, &workload);
    }
}

/// `count` random items, item `i` of `len_of(i)` bytes, each in its own allocation.
fn random_items(
    gpa: Allocator,
    rng: *TestRng,
    count: usize,
    context: anytype,
    comptime len_of: fn (@TypeOf(context), usize) usize,
) ![][]u8 {
    const items = try gpa.alloc([]u8, count);
    var made: usize = 0;
    errdefer {
        for (items[0..made]) |item| gpa.free(item);
        gpa.free(items);
    }
    for (items, 0..) |*item, i| {
        item.* = try gpa.alloc(u8, len_of(context, i));
        made += 1;
        rng.fill_bytes(item.*);
    }
    return items;
}

fn free_items(gpa: Allocator, items: [][]u8) void {
    for (items) |item| gpa.free(item);
    gpa.free(items);
}

fn small_len(_: void, _: usize) usize {
    return SMALL;
}

fn bench_add_many_uniform(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var mmr = try committed(storage.mmr.Family, gpa);
    defer mmr.deinit(gpa);
    // A quick run skips MMB, so it skips building MMB's committed tree.
    var mmb: Mem(storage.mmb.Family) = .empty;
    if (!quick(runner)) mmb = try committed(storage.mmb.Family, gpa);
    defer mmb.deinit(gpa);
    var rng = utils.test_rng();
    for (cases(usize, runner, &ITEMS, 1)) |n| {
        const items = try random_items(gpa, &rng, n, {}, small_len);
        defer free_items(gpa, items);
        const params = bench.Benchmark.init("merkle::add_many").with_param("items", n);
        try bench_workers(runner, storage.mmr.Family, params, "mmr", &mmr, items);
        if (quick(runner)) continue;
        try bench_workers(runner, storage.mmb.Family, params, "mmb", &mmb, items);
    }
}

const Skew = struct {
    payload: []const u8,
    large: usize,
    shape: enum { clustered, spread, dominant },

    fn len_of(skew: Skew, i: usize) usize {
        const is_large = switch (skew.shape) {
            .clustered => i < CLUSTERED,
            .spread => i % 8 == 0,
            .dominant => i == 0,
        };
        return if (is_large) skew.large else SMALL;
    }
};

fn bench_add_many_skewed(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var mmr = try committed(storage.mmr.Family, gpa);
    defer mmr.deinit(gpa);
    var rng = utils.test_rng();
    const skews = [_]Skew{
        .{ .payload = "clustered", .large = MIB, .shape = .clustered },
        .{ .payload = "clustered", .large = 8 * KIB, .shape = .clustered },
        .{ .payload = "spread", .large = MIB, .shape = .spread },
        .{ .payload = "dominant", .large = 16 * MIB, .shape = .dominant },
    };
    // A quick run takes the 8 KiB clustered case, the cheapest to hash.
    const run_cases: []const Skew = if (quick(runner)) skews[1..2] else &skews;
    for (run_cases) |skew| {
        const items = try random_items(gpa, &rng, SKEWED_ITEMS, skew, Skew.len_of);
        defer free_items(gpa, items);
        const params = bench.Benchmark.init("merkle::add_many").with_param("items", SKEWED_ITEMS)
            .with_param("payload", skew.payload).with_param("large", skew.large);
        try bench_workers(runner, storage.mmr.Family, params, "mmr", &mmr, items);
    }
}

const UpdateMode = enum { BatchedSerial, BatchedParallel };
const update_modes = [_]UpdateMode{ .BatchedSerial, .BatchedParallel };

/// Times random leaf updates on a tree of `leaves` random elements: drawing `updates` random
/// (leaf, element) pairs into a map (the caller batching leaves, as in commonware), then
/// `update_leaf_batched`, `merkleize`, and `apply_batch`.
fn UpdateWorkload(comptime F: type) type {
    return struct {
        const Self = @This();
        const LeafUpdate = Mem(F).Batch.LeafUpdate;
        gpa: Allocator,
        leaves: usize,
        updates: usize,
        rng: TestRng = utils.test_rng(),
        elements: []Digest = &.{},
        mem: Mem(F) = .empty,
        map: std.AutoHashMapUnmanaged(u64, Digest) = .empty,
        list: std.ArrayList(LeafUpdate) = .empty,

        pub fn setup(self: *Self) !void {
            self.elements = try random_digests(self.gpa, &self.rng, self.leaves);
            try append_all(F, self.gpa, &self.mem, self.elements);
            assert(self.mem.leaves() == self.leaves);
        }

        pub fn iter(self: *Self) !u64 {
            const gpa = self.gpa;
            self.map.clearRetainingCapacity();
            for (0..self.updates) |_| {
                const leaf = utils.rng.range_less_than(&self.rng, usize, 0, self.leaves);
                const swap = utils.rng.range_less_than(&self.rng, usize, 0, self.elements.len);
                try self.map.put(gpa, leaf, self.elements[swap]);
            }
            self.list.clearRetainingCapacity();
            try self.list.ensureTotalCapacity(gpa, self.map.count());
            var entries = self.map.iterator();
            while (entries.next()) |entry| {
                self.list.appendAssumeCapacity(.{
                    .location = entry.key_ptr.*,
                    .digest = entry.value_ptr.*,
                });
            }
            var batch = try self.mem.new_batch(gpa);
            errdefer batch.deinit(gpa);
            try batch.update_leaf_batched(gpa, self.list.items);
            const merkleized = try batch.merkleize(gpa, &self.mem, &hasher);
            defer merkleized.release(gpa);
            try self.mem.apply_batch(gpa, merkleized);
            return self.mem.size();
        }

        pub fn teardown(self: *Self) void {
            self.mem.deinit(self.gpa);
            self.mem = .empty;
            self.gpa.free(self.elements);
            self.elements = &.{};
            self.map.deinit(self.gpa);
            self.list.deinit(self.gpa);
            self.map = .empty;
            self.list = .empty;
        }
    };
}

/// Commonware's update counts; a quick run takes only the smaller.
fn update_counts(runner: *const bench.Runner) []const usize {
    const all: []const usize = &.{ 1_000_000, 100_000 };
    return if (quick(runner)) all[1..] else all;
}

fn bench_update(runner: *bench.Runner) !void {
    const sizes = runner.inputs.pick(
        []const usize,
        &.{100_000},
        &.{100_000},
        &.{ 100_000, 1_000_000, 5_000_000, 10_000_000 },
    );
    inline for (families, 0..) |family, family_index| {
        // A quick run takes MMR only.
        if (family_index == 0 or !quick(runner)) {
            for (update_counts(runner)) |updates| {
                for (sizes) |leaves| {
                    for (cases(UpdateMode, runner, &update_modes, 1)) |mode| {
                        const benchmark = bench.Benchmark.init("merkle::update")
                            .with_param("updates", updates).with_param("leaves", leaves)
                            .with_param("strategy", mode).with_param("family", family[1]);
                        var workload: UpdateWorkload(family[0]) = .{
                            .gpa = runner.allocator,
                            .leaves = leaves,
                            .updates = updates,
                        };
                        try runner.run(benchmark, &workload);
                    }
                }
            }
        }
    }
}

const ITEMS_PER_BLOB: u64 = 10_000_000;
const PAGE_CACHE_SIZE: usize = 512;
const WRITE_BUFFER_SIZE: usize = 2 * 1024 * 1024;
const REPLAY_BUFFER_SIZE: usize = 2 * 1024 * 1024;
/// Rebuild the structure after roughly this many flushed nodes so the journal stays bounded.
const REBUILD_NODE_BUDGET: usize = 2_000_000;

/// Applies a batch of `n` random leaves to a journaled structure (untimed) before each
/// iteration, then times `flush`. The structure is destroyed and reopened every `cycles`
/// flushes so its journal never grows without bound.
fn FlushWorkload(comptime F: type, comptime family: []const u8) type {
    return struct {
        const Self = @This();
        const Merkle = merkle.full.Merkle(F, Digest);
        gpa: Allocator,
        disk: *Disk,
        n: usize,
        cycles: usize,
        rng: TestRng = utils.test_rng(),
        cache: runtime.buffer.paged.CacheRef = undefined,
        structure: ?Merkle = null,
        flushes: usize = 0,

        fn config(self: *Self) merkle.full.Config {
            return .{
                .journal_partition = "journal-bench-flush-" ++ family,
                .metadata_partition = "metadata-bench-flush-" ++ family,
                .items_per_blob = ITEMS_PER_BLOB,
                .write_buffer = WRITE_BUFFER_SIZE,
                .replay_buffer = REPLAY_BUFFER_SIZE,
                .cache_ref = &self.cache,
            };
        }

        pub fn setup(self: *Self) !void {
            const page_size = runtime.buffer.paged.page_size(runtime.storage.blob_page_size);
            self.cache = try .init(self.gpa, page_size, PAGE_CACHE_SIZE);
        }

        pub fn before_iter(self: *Self) !void {
            if (self.flushes == self.cycles) try self.destroy();
            if (self.structure == null) {
                const backend = self.disk.storage();
                self.structure = try Merkle.init(self.gpa, backend, &hasher, self.config());
            }
            const structure = &self.structure.?;
            var batch = try structure.new_batch();
            errdefer batch.deinit(self.gpa);
            for (0..self.n) |_| {
                const digest: Digest = .random(utils.rng.random(&self.rng));
                try batch.add(self.gpa, &hasher, &digest.bytes);
            }
            const merkleized = try batch.merkleize(structure, &hasher);
            defer merkleized.release(self.gpa);
            try structure.apply_batch(merkleized);
        }

        pub fn iter(self: *Self) !u64 {
            const structure = &self.structure.?;
            try structure.flush();
            self.flushes += 1;
            return structure.size();
        }

        fn destroy(self: *Self) !void {
            var structure = self.structure orelse return;
            self.structure = null;
            self.flushes = 0;
            try structure.destroy();
        }

        pub fn teardown(self: *Self) void {
            self.destroy() catch |err| std.log.warn("merkle flush bench: destroy: {t}", .{err});
            self.cache.deinit();
        }
    };
}

fn bench_flush(runner: *bench.Runner) !void {
    const sizes = runner.inputs.pick(
        []const usize,
        &.{ 10_000, 100_000 },
        &.{ 10_000, 100_000 },
        &.{ 10_000, 100_000, 1_000_000 },
    );
    const sizes_run = cases(usize, runner, sizes, 1);
    var disk: Disk = .init(runner);
    try disk.open(runner.allocator, "merkle-bench-flush");
    defer disk.close();
    inline for (families, 0..) |family, family_index| {
        // A quick run takes MMR only.
        if (family_index == 0 or !quick(runner)) {
            for (sizes_run) |n| {
                const benchmark = bench.Benchmark.init("merkle::flush").with_param("n", n)
                    .with_param("family", family[1]);
                var workload: FlushWorkload(family[0], family[1]) = .{
                    .gpa = runner.allocator,
                    .disk = &disk,
                    .n = n,
                    .cycles = @max(REBUILD_NODE_BUDGET / (2 * n), 1),
                };
                try runner.run(benchmark, &workload);
            }
        }
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_add_many_uniform(runner);
    try bench_add_many_skewed(runner);
    try bench_append(runner);
    try bench_append_additional(runner);
    try bench_flush(runner);
    try bench_position_to_location(runner);
    try bench_proofs(runner);
    try bench_update(runner);
}
