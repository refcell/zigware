//! Batch verification of BLS12-381 signatures (commonware `ops::batch`): every signature
//! must be valid, not only the aggregate.
//!
//! Each signature gets a random 128-bit weight r_i before aggregate verification. Without
//! weights, two invalid signatures that err by opposite amounts cancel; with them, the errors
//! must satisfy `sum(r_i err_i) = 0`, which happens with probability at most 2^-128.

const std = @import("std");
const assert = std.debug.assert;
const parallel = @import("parallel");
const ops = @import("../ops.zig");
const group = @import("../group.zig");
const variant = @import("../variant.zig");

const Allocator = std.mem.Allocator;
const SmallScalar = group.SmallScalar;
const Error = variant.Error;

/// Points per stack chunk in the allocation-free weighted sums.
const chunk_length = 64;

/// One signer's public key and signature over the shared message.
pub fn Entry(comptime V: type) type {
    return struct { public: V.Public, signature: V.Signature };
}

/// One signature over a namespaced message from the shared signer.
pub fn SignerEntry(comptime V: type) type {
    return struct { namespace: []const u8, message: []const u8, signature: V.Signature };
}

/// Verifies signatures over one message from many keys and returns the indices of the
/// invalid ones in ascending order (empty when all are valid); the caller frees the slice.
///
/// Weighted sums of the keys and signatures are checked first. When that fails, a segment
/// tree over the weighted entries is bisected into its failing subtrees. Keys and
/// signatures must be group-checked; duplicate keys are safe. As in commonware, `strategy`
/// joins the two sums, weights the entries, and bisects each batch it splits them into.
pub fn verify_same_message(
    comptime V: type,
    gpa: Allocator,
    rng: anytype,
    namespace: []const u8,
    message: []const u8,
    entries: []const Entry(V),
    strategy: anytype,
) Allocator.Error![]usize {
    assert(entries.len > 0);
    const hm = ops.hash_with_namespace(V, V.message, namespace, message);
    const publics = try gpa.alloc(V.Public, entries.len);
    defer gpa.free(publics);
    const signatures = try gpa.alloc(V.Signature, entries.len);
    defer gpa.free(signatures);
    const scalars = try gpa.alloc(SmallScalar, entries.len);
    defer gpa.free(scalars);
    for (entries, publics, signatures) |entry, *public, *signature| {
        public.* = entry.public;
        signature.* = entry.signature;
    }
    // Scalars are drawn in index order, like commonware.
    for (scalars) |*scalar| scalar.* = SmallScalar.random(rng);
    const sums = strategy.join(
        Msm(V.Public){ .points = publics, .scalars = scalars },
        Msm(V.Signature){ .points = signatures, .scalars = scalars },
    );
    if (V.verify(sums[0], hm, sums[1])) |_| {
        return gpa.alloc(usize, 0);
    } else |_| {}
    // Bisect over the weighted entries.
    strategy.map_into(publics, publics, Weigh(V.Public){ .points = publics, .scalars = scalars });
    strategy.map_into(
        signatures,
        signatures,
        Weigh(V.Signature){ .points = signatures, .scalars = scalars },
    );
    return bisect(V, gpa, publics, signatures, hm, strategy);
}

/// `point * scalar` for each point, in place (a `map_into` operation over `points`).
fn Weigh(comptime G: type) type {
    return struct {
        points: []const G,
        scalars: []const SmallScalar,

        pub fn map(self: @This(), point: *const G) G {
            const offset = @intFromPtr(point) - @intFromPtr(self.points.ptr);
            const index = offset / @sizeOf(G);
            assert(index < self.scalars.len);
            return point.mul(self.scalars[index]);
        }
    };
}

/// `msm(points, scalars)` as a `join` arm.
fn Msm(comptime G: type) type {
    return struct {
        points: []const G,
        scalars: []const SmallScalar,

        pub fn call(self: @This()) G {
            assert(self.points.len == self.scalars.len);
            return G.msm(self.points, self.scalars);
        }
    };
}

/// The indices of invalid weighted entries, ascending, found by bisecting each batch
/// `strategy` splits the entries into (commonware `bisect`). The aggregate of all entries is
/// known to be invalid, so only a whole-input batch skips its root; batches cover ascending
/// ranges in order, so their indices concatenate without a sort.
fn bisect(
    comptime V: type,
    gpa: Allocator,
    publics: []const V.Public,
    signatures: []const V.Signature,
    hm: V.Signature,
    strategy: anytype,
) Allocator.Error![]usize {
    assert(publics.len == signatures.len and publics.len > 0);
    const Op = struct {
        gpa: Allocator,
        publics: []const V.Public,
        signatures: []const V.Signature,
        hm: V.Signature,
        root_invalid: bool = true,

        pub fn run(op: @This(), batches: anytype) Allocator.Error![]usize {
            if (batches.is_whole()) return op.map(0, .init(0, op.publics.len));
            var split = op;
            split.root_invalid = false;
            var found: [parallel.max_chunks][]usize = undefined;
            const out = found[0..batches.count()];
            try batches.try_map_collect(out, split);
            defer for (out) |indices| op.gpa.free(indices);
            var total: usize = 0;
            for (out) |indices| total += indices.len;
            const invalid = try op.gpa.alloc(usize, total);
            var cursor: usize = 0;
            for (out) |indices| {
                @memcpy(invalid[cursor..][0..indices.len], indices);
                cursor += indices.len;
            }
            assert(cursor == total);
            return invalid;
        }

        /// The invalid indices of `range`, offset into the whole input.
        pub fn map(op: @This(), _: usize, range: parallel.Range) Allocator.Error![]usize {
            const publics_range = op.publics[range.start..range.end];
            const signatures_range = op.signatures[range.start..range.end];
            var tree = try SegmentTree(V).build(op.gpa, publics_range, signatures_range);
            defer tree.deinit(op.gpa);
            const invalid = try tree.find_invalid(op.gpa, op.hm, op.root_invalid);
            for (invalid) |*index| index.* += range.start;
            return invalid;
        }

        pub fn discard(op: @This(), indices: []usize) void {
            op.gpa.free(indices);
        }
    };
    const op: Op = .{ .gpa = gpa, .publics = publics, .signatures = signatures, .hm = hm };
    return strategy.try_run_batches(publics.len, 1, 1, op);
}

/// Sums of (public key, signature) pairs over ranges of entries, in a 1-indexed array where
/// node i has children 2i and 2i + 1, so k invalid entries are found in O(k log n) checks.
fn SegmentTree(comptime V: type) type {
    return struct {
        const Self = @This();
        const Node = struct { public: V.Public, signature: V.Signature };
        const Task = struct { node: usize, start: usize, end: usize };

        length: usize,
        nodes: []Node,

        fn build(
            gpa: Allocator,
            publics: []const V.Public,
            signatures: []const V.Signature,
        ) Allocator.Error!Self {
            const length = publics.len;
            assert(length > 0 and signatures.len == length);
            const nodes = try gpa.alloc(Node, 4 * length);
            errdefer gpa.free(nodes);
            // Post-order with an explicit stack: children are built before their parent.
            const Visit = struct { task: Task, children_built: bool };
            var stack: std.ArrayList(Visit) = .empty;
            defer stack.deinit(gpa);
            try stack.append(gpa, .{
                .task = .{ .node = 1, .start = 0, .end = length },
                .children_built = false,
            });
            while (stack.pop()) |visit| {
                const task = visit.task;
                if (task.end - task.start == 1) {
                    nodes[task.node] = .{
                        .public = publics[task.start],
                        .signature = signatures[task.start],
                    };
                } else if (!visit.children_built) {
                    const mid = task.start + (task.end - task.start) / 2;
                    try stack.append(gpa, .{ .task = task, .children_built = true });
                    try stack.append(gpa, .{
                        .task = .{ .node = 2 * task.node + 1, .start = mid, .end = task.end },
                        .children_built = false,
                    });
                    try stack.append(gpa, .{
                        .task = .{ .node = 2 * task.node, .start = task.start, .end = mid },
                        .children_built = false,
                    });
                } else {
                    const left = nodes[2 * task.node];
                    const right = nodes[2 * task.node + 1];
                    nodes[task.node] = .{
                        .public = left.public.add(right.public),
                        .signature = left.signature.add(right.signature),
                    };
                }
            }
            return .{ .length = length, .nodes = nodes };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.nodes);
            self.* = undefined;
        }

        /// Indices of invalid leaves in ascending order. When `root_invalid` the root is
        /// known to be invalid and is not checked again.
        fn find_invalid(
            self: *const Self,
            gpa: Allocator,
            hm: V.Signature,
            root_invalid: bool,
        ) Allocator.Error![]usize {
            var invalid: std.ArrayList(usize) = .empty;
            errdefer invalid.deinit(gpa);
            if (!root_invalid) {
                const root = self.nodes[1];
                if (V.verify(root.public, hm, root.signature)) |_| {
                    return invalid.toOwnedSlice(gpa);
                } else |_| {}
            }
            if (self.length == 1) {
                try invalid.append(gpa, 0);
                return invalid.toOwnedSlice(gpa);
            }
            var stack: std.ArrayList(Task) = .empty;
            defer stack.deinit(gpa);
            // Skip the root; the right child is pushed first so leaves come out ascending.
            const mid = self.length / 2;
            try stack.append(gpa, .{ .node = 3, .start = mid, .end = self.length });
            try stack.append(gpa, .{ .node = 2, .start = 0, .end = mid });
            while (stack.pop()) |task| {
                const node = self.nodes[task.node];
                if (V.verify(node.public, hm, node.signature)) |_| continue else |_| {}
                if (task.end - task.start == 1) {
                    try invalid.append(gpa, task.start);
                    continue;
                }
                const split = task.start + (task.end - task.start) / 2;
                const left: Task = .{ .node = 2 * task.node, .start = task.start, .end = split };
                const right: Task = .{ .node = 2 * task.node + 1, .start = split, .end = task.end };
                try stack.append(gpa, right);
                try stack.append(gpa, left);
            }
            assert(invalid.items.len > 0);
            return invalid.toOwnedSlice(gpa);
        }
    };
}

/// Hashes an entry's namespaced message (a `map_into` operation).
fn HashEntry(comptime V: type) type {
    return struct {
        pub fn map(_: @This(), entry: *const SignerEntry(V)) V.Signature {
            return ops.hash_with_namespace(V, V.message, entry.namespace, entry.message);
        }
    };
}

/// Verifies signatures over many namespaced messages from one key: `e(public, sum_i r_i
/// hm_i) == e(generator, sum_i r_i sig_i)`. `public` and the signatures must be
/// group-checked; duplicate messages are safe. As in commonware, `strategy` hashes the
/// messages and joins the two sums.
pub fn verify_same_signer(
    comptime V: type,
    rng: anytype,
    public: V.Public,
    entries: []const SignerEntry(V),
    strategy: anytype,
) Error!void {
    assert(entries.len > 0);
    // Scalars are drawn in index order, the order commonware draws them up front.
    var weighted_hm = V.Signature.zero;
    var weighted_signature = V.Signature.zero;
    var start: usize = 0;
    while (start < entries.len) : (start += chunk_length) {
        const count = @min(chunk_length, entries.len - start);
        var scalars: [chunk_length]SmallScalar = undefined;
        var hms: [chunk_length]V.Signature = undefined;
        var signatures: [chunk_length]V.Signature = undefined;
        const chunk = entries[start..][0..count];
        for (chunk, 0..) |entry, index| {
            scalars[index] = SmallScalar.random(rng);
            signatures[index] = entry.signature;
        }
        strategy.map_into(chunk, hms[0..count], HashEntry(V){});
        const sums = strategy.join(
            Msm(V.Signature){ .points = hms[0..count], .scalars = scalars[0..count] },
            Msm(V.Signature){ .points = signatures[0..count], .scalars = scalars[0..count] },
        );
        weighted_hm = weighted_hm.add(sums[0]);
        weighted_signature = weighted_signature.add(sums[1]);
    }
    return V.verify(public, weighted_hm, weighted_signature);
}
