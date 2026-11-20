//! Benchmarks of the binary Merkle tree (commonware `storage/src/bmt/benches`): building,
//! proving, and verifying, with commonware's names and tree sizes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const storage = @import("storage");
const utils = @import("utils");

const bmt = storage.bmt;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Proof = bmt.Proof(Digest);
const Tree = bmt.Tree(Digest);
const TestRng = utils.TestRng;

/// Positions proven or verified by each multi-proof, range proof, or verification batch.
const SAMPLE_SIZE: u32 = 100;

const build_sizes = [_]usize{ 100, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000 };
const proof_sizes = [_]usize{ 250, 1_000, 100_000 };
const verify_sizes = [_]usize{ 250, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000 };

fn random_digests(gpa: Allocator, rng: *TestRng, n: usize) ![]Digest {
    assert(n > 0);
    const digests = try gpa.alloc(Digest, n);
    for (digests) |*digest| digest.* = .random(utils.rng.random(rng));
    assert(digests.len == n);
    return digests;
}

/// The tree over leaves `hash(i as little-endian u64)` for `i` in `0..n`.
fn indexed_tree(gpa: Allocator, n: usize) !Tree {
    assert(n > 0);
    const leaves = try gpa.alloc(Digest, n);
    defer gpa.free(leaves);
    for (leaves, 0..) |*leaf, i| {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, i));
        leaf.* = Sha256.hash(&.{&bytes});
    }
    return build_tree(gpa, leaves);
}

fn build_tree(gpa: Allocator, leaves: []const Digest) !Tree {
    assert(leaves.len > 0);
    var builder: bmt.Builder(Sha256) = try .init(gpa, leaves.len);
    defer builder.deinit(gpa);
    for (leaves) |*leaf| _ = try builder.add(gpa, leaf);
    const tree = try builder.build(gpa);
    assert(tree.level(0).len == leaves.len);
    return tree;
}

/// Samples `out.len` distinct positions below `n` (Floyd's algorithm), in ascending order.
fn sample_positions(rng: *TestRng, n: usize, out: []u32) void {
    assert(out.len <= n);
    assert(n <= std.math.maxInt(u32));
    for (n - out.len..n, 0..) |bound, count| {
        const candidate: u32 = @intCast(utils.rng.range_at_most(rng, usize, 0, bound));
        const taken = std.mem.indexOfScalar(u32, out[0..count], candidate) != null;
        out[count] = if (taken) @intCast(bound) else candidate;
    }
    std.sort.pdq(u32, out, {}, std.sort.asc(u32));
    assert(out.len < 2 or out[0] < out[out.len - 1]);
}

const BuildWorkload = struct {
    gpa: Allocator,
    elements: []const Digest,

    pub fn iter(workload: *BuildWorkload) !u8 {
        var tree = try build_tree(workload.gpa, workload.elements);
        defer tree.deinit(workload.gpa);
        return tree.root().bytes[0];
    }
};

fn bench_build(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick([]const usize, build_sizes[0..1], &build_sizes, &build_sizes);
    for (sizes) |n| {
        var rng = utils.test_rng();
        const elements = try random_digests(gpa, &rng, n);
        defer gpa.free(elements);
        var workload: BuildWorkload = .{ .gpa = gpa, .elements = elements };
        try runner.run(bench.Benchmark.init("bmt::build").with_param("n", n), &workload);
    }
}

/// Generates one proof per iteration: a single leaf, a range, or a multi-proof.
const ProveWorkload = struct {
    gpa: Allocator,
    tree: *const Tree,
    kind: enum { single, range, multi },
    positions: []const u32,

    pub fn iter(workload: *ProveWorkload) !usize {
        const positions = workload.positions;
        assert(positions.len > 0);
        const tree = workload.tree;
        var proof = switch (workload.kind) {
            .single => try tree.proof(workload.gpa, positions[0], null),
            .range => try tree.range_proof(
                workload.gpa,
                positions[0],
                positions[positions.len - 1],
                null,
            ),
            .multi => try tree.multi_proof(workload.gpa, positions, null),
        };
        defer proof.deinit(workload.gpa);
        return proof.siblings.len;
    }
};

fn bench_prove(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick([]const usize, proof_sizes[0..1], &proof_sizes, &proof_sizes);
    for (sizes) |n| {
        const single = bench.Benchmark.init("bmt::proof").with_param("n", n);
        const range = bench.Benchmark.init("bmt::range_proof").with_param("n", n)
            .with_param("items", SAMPLE_SIZE);
        const multi = bench.Benchmark.init("bmt::multi_proof").with_param("n", n)
            .with_param("items", SAMPLE_SIZE);
        // A filtered run builds only the trees its benchmarks use.
        const wanted = runner.matches(single.name()) or runner.matches(range.name()) or
            runner.matches(multi.name());
        if (!runner.list and !wanted) continue;
        var tree = try indexed_tree(gpa, n);
        defer tree.deinit(gpa);
        // Prove one leaf, and a range, away from the edges of the tree.
        const start: u32 = @intCast(n / 3);
        var workload: ProveWorkload = .{
            .gpa = gpa,
            .tree = &tree,
            .kind = .single,
            .positions = &.{start},
        };
        try runner.run(single, &workload);

        workload.kind = .range;
        workload.positions = &.{ start, start + SAMPLE_SIZE - 1 };
        try runner.run(range, &workload);

        var positions: [SAMPLE_SIZE]u32 = undefined;
        var rng = utils.test_rng();
        sample_positions(&rng, n, &positions);
        workload.kind = .multi;
        workload.positions = &positions;
        try runner.run(multi, &workload);
    }
}

/// Verifies proofs generated (untimed) before each iteration: `SAMPLE_SIZE` single-leaf
/// proofs, one multi-proof, or one range proof at a random start.
const VerifyWorkload = struct {
    gpa: Allocator,
    tree: *const Tree,
    leaves: []const Digest,
    root: Digest,
    rng: TestRng,
    kind: enum { single, multi, range },
    positions: [SAMPLE_SIZE]u32 = undefined,
    elements: [SAMPLE_SIZE]Proof.Element = undefined,
    proofs: [SAMPLE_SIZE]Proof = @splat(.{}),
    proofs_len: usize = 0,

    pub fn before_iter(workload: *VerifyWorkload) !void {
        workload.teardown();
        const n = workload.leaves.len;
        const tree = workload.tree;
        const gpa = workload.gpa;
        switch (workload.kind) {
            .single => {
                sample_positions(&workload.rng, n, &workload.positions);
                for (workload.positions) |position| {
                    const proof = try tree.proof(gpa, position, null);
                    workload.proofs[workload.proofs_len] = proof;
                    workload.proofs_len += 1;
                }
            },
            .multi => {
                sample_positions(&workload.rng, n, &workload.positions);
                for (workload.positions, &workload.elements) |position, *element| {
                    element.* = .{ .position = position, .digest = workload.leaves[position] };
                }
                workload.proofs[0] = try tree.multi_proof(gpa, &workload.positions, null);
                workload.proofs_len = 1;
            },
            .range => {
                const start = utils.rng.range_at_most(&workload.rng, usize, 0, n - SAMPLE_SIZE);
                workload.positions[0] = @intCast(start);
                const end: u32 = @intCast(start + SAMPLE_SIZE - 1);
                workload.proofs[0] = try tree.range_proof(gpa, @intCast(start), end, null);
                workload.proofs_len = 1;
            },
        }
        assert(workload.proofs_len > 0);
    }

    pub fn iter(workload: *VerifyWorkload) !usize {
        assert(workload.proofs_len > 0);
        const root = &workload.root;
        const proofs = workload.proofs[0..workload.proofs_len];
        switch (workload.kind) {
            .single => for (proofs, workload.positions) |*proof, position| {
                const leaf = &workload.leaves[position];
                try proof.verify_element_inclusion(Sha256, position, leaf, root, null);
            },
            .multi => {
                const elements = &workload.elements;
                try proofs[0].verify_multi_inclusion(Sha256, workload.gpa, elements, root, null);
            },
            .range => {
                const start = workload.positions[0];
                const leaves = workload.leaves[start..][0..SAMPLE_SIZE];
                try proofs[0].verify_range_inclusion(
                    Sha256,
                    workload.gpa,
                    start,
                    leaves,
                    root,
                    null,
                );
            },
        }
        return proofs.len;
    }

    pub fn teardown(workload: *VerifyWorkload) void {
        assert(workload.proofs_len <= SAMPLE_SIZE);
        for (workload.proofs[0..workload.proofs_len]) |*proof| proof.deinit(workload.gpa);
        workload.proofs_len = 0;
    }
};

fn bench_verify(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = runner.inputs.pick(
        []const usize,
        verify_sizes[0..1],
        &verify_sizes,
        &verify_sizes,
    );
    const Kind = @FieldType(VerifyWorkload, "kind");
    const names = [_]struct { Kind, []const u8 }{
        .{ .single, "bmt::verify_single" },
        .{ .multi, "bmt::verify_multi" },
        .{ .range, "bmt::verify_range" },
    };
    for (names) |entry| {
        for (sizes) |n| {
            const benchmark = bench.Benchmark.init(entry[1]).with_param("n", n)
                .with_param("items", SAMPLE_SIZE);
            // A filtered run builds only the trees its benchmarks use.
            if (!runner.list and !runner.matches(benchmark.name())) continue;
            var rng = utils.test_rng();
            const leaves = try random_digests(gpa, &rng, n);
            defer gpa.free(leaves);
            var tree = try build_tree(gpa, leaves);
            defer tree.deinit(gpa);
            var workload: VerifyWorkload = .{
                .gpa = gpa,
                .tree = &tree,
                .leaves = leaves,
                .root = tree.root(),
                .rng = rng,
                .kind = entry[0],
            };
            defer workload.teardown();
            try runner.run(benchmark, &workload);
        }
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_build(runner);
    try bench_prove(runner);
    try bench_verify(runner);
}
