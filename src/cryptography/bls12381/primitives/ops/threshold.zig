//! Threshold BLS signatures (commonware `ops::threshold`): partial signing and
//! verification against a `Sharing`, batch verification of partials, and recovery of the
//! group signature from at least `sharing.required()` partials.
//!
//! Batch verification and recovery take commonware's `parallel` Strategy, which may run their
//! independent work on several threads; results never depend on it. A single recovery's
//! interpolation sum runs through the strategy's tiled MSM (`G.msm_strategy`).

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const ops = @import("../ops.zig");
const batch = @import("batch.zig");
const group = @import("../group.zig");
const variant = @import("../variant.zig");
const sharing_mod = @import("../sharing.zig");

const Allocator = std.mem.Allocator;
const Participant = utils.Participant;
const Share = group.Share;
const Error = variant.Error;
const PartialSignature = variant.PartialSignature;
const Sharing = sharing_mod.Sharing;

/// Signs `message` in `namespace` with a key share.
pub fn sign_message(
    comptime V: type,
    share: Share,
    namespace: []const u8,
    message: []const u8,
) PartialSignature(V) {
    const value = ops.sign_message(V, share.private, namespace, message);
    return .{ .index = share.index, .value = value };
}

/// Signs a proof of possession of the *group* public key with a key share, so the
/// recovered signature verifies with `ops.verify_proof_of_possession`.
pub fn sign_proof_of_possession(
    comptime V: type,
    sharing: Sharing(V),
    share: Share,
    namespace: []const u8,
) PartialSignature(V) {
    const encoded = sharing.public().to_bytes();
    const hm = ops.hash_with_namespace(V, V.proof_of_possession, namespace, &encoded);
    return .{ .index = share.index, .value = hm.mul(share.private.scalar) };
}

/// Verifies a partial signature against its signer's partial public key. Assumes the
/// signature passed its group check.
pub fn verify_message(
    comptime V: type,
    sharing: Sharing(V),
    namespace: []const u8,
    message: []const u8,
    partial: PartialSignature(V),
) Error!void {
    const public = try sharing.partial_public(partial.index);
    return ops.verify_message(V, public, namespace, message, partial.value);
}

/// Verifies a partial proof of possession of the group public key.
pub fn verify_proof_of_possession(
    comptime V: type,
    sharing: Sharing(V),
    namespace: []const u8,
    partial: PartialSignature(V),
) Error!void {
    const public = try sharing.partial_public(partial.index);
    const encoded = sharing.public().to_bytes();
    const hm = ops.hash_with_namespace(V, V.proof_of_possession, namespace, &encoded);
    return V.verify(public, hm, partial.value);
}

/// One partial signature over a namespaced message.
pub fn SignerEntry(comptime V: type) type {
    return struct { namespace: []const u8, message: []const u8, partial: PartialSignature(V) };
}

/// Verifies partial signatures over many messages from the signer `index`; every partial
/// must carry `index`. Random weights make this agree with checking each one.
pub fn batch_verify_same_signer(
    comptime V: type,
    gpa: Allocator,
    rng: anytype,
    sharing: Sharing(V),
    index: Participant,
    entries: []const SignerEntry(V),
    strategy: anytype,
) (Error || Allocator.Error)!void {
    assert(entries.len > 0);
    const combined = try gpa.alloc(batch.SignerEntry(V), entries.len);
    defer gpa.free(combined);
    for (combined, entries) |*out, entry| {
        if (entry.partial.index.get() != index.get()) return error.InvalidSignature;
        out.* = .{
            .namespace = entry.namespace,
            .message = entry.message,
            .signature = entry.partial.value,
        };
    }
    const public = try sharing.partial_public(index);
    return batch.verify_same_signer(V, rng, public, combined, strategy);
}

/// Verifies partial signatures over one message and returns the positions (in `partials`)
/// of the invalid ones: first those whose index is out of range, in input order, then the
/// ones that fail verification, ascending. Empty when all are valid; the caller frees it.
/// Duplicate signers are safe.
pub fn batch_verify_same_message(
    comptime V: type,
    gpa: Allocator,
    rng: anytype,
    sharing: Sharing(V),
    namespace: []const u8,
    message: []const u8,
    partials: []const PartialSignature(V),
    strategy: anytype,
) Allocator.Error![]usize {
    assert(partials.len > 0);
    var invalid: std.ArrayList(usize) = .empty;
    errdefer invalid.deinit(gpa);
    var pending: std.ArrayList(batch.Entry(V)) = .empty;
    defer pending.deinit(gpa);
    var pending_positions: std.ArrayList(usize) = .empty;
    defer pending_positions.deinit(gpa);
    for (partials, 0..) |partial, position| {
        if (sharing.partial_public(partial.index)) |public| {
            try pending.append(gpa, .{ .public = public, .signature = partial.value });
            try pending_positions.append(gpa, position);
        } else |_| try invalid.append(gpa, position);
    }
    if (pending.items.len > 0) {
        const bad = try batch.verify_same_message(
            V,
            gpa,
            rng,
            namespace,
            message,
            pending.items,
            strategy,
        );
        defer gpa.free(bad);
        for (bad) |index| try invalid.append(gpa, pending_positions.items[index]);
    }
    return invalid.toOwnedSlice(gpa);
}

/// Evaluations selected for recovery: the lowest `threshold` distinct indices (the first
/// partial wins for a repeated index), sorted by index.
fn Evaluations(comptime V: type) type {
    return struct {
        const Self = @This();
        keys: []Participant,
        values: []V.Signature,

        fn less(_: void, a: PartialSignature(V), b: PartialSignature(V)) bool {
            return a.index.get() < b.index.get();
        }

        fn prepare(
            gpa: Allocator,
            threshold: u32,
            partials: []const PartialSignature(V),
        ) (Error || Allocator.Error)!Self {
            const sorted = try gpa.dupe(PartialSignature(V), partials);
            defer gpa.free(sorted);
            std.mem.sort(PartialSignature(V), sorted, {}, less); // Stable: first wins.
            var count: usize = 0;
            for (sorted) |partial| {
                if (count == threshold) break;
                if (count > 0 and sorted[count - 1].index.get() == partial.index.get()) continue;
                sorted[count] = partial;
                count += 1;
            }
            if (count < threshold) return error.NotEnoughPartialSignatures;
            const keys = try gpa.alloc(Participant, count);
            errdefer gpa.free(keys);
            const values = try gpa.alloc(V.Signature, count);
            for (keys, values, sorted[0..count]) |*key, *value, partial| {
                key.* = partial.index;
                value.* = partial.value;
            }
            return .{ .keys = keys, .values = values };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.keys);
            gpa.free(self.values);
            self.* = undefined;
        }
    };
}

/// Interpolates a candidate group signature from at least `sharing.required()` partials
/// with distinct indices, using the lowest ones. Recovery verifies nothing: verify the
/// result against the group key before accepting it. For valid partials every quorum
/// recovers the same signature.
pub fn recover(
    comptime V: type,
    gpa: Allocator,
    sharing: Sharing(V),
    partials: []const PartialSignature(V),
    strategy: anytype,
) (Error || Allocator.Error)!V.Signature {
    var evals = try Evaluations(V).prepare(gpa, sharing.required(), partials);
    defer evals.deinit(gpa);
    var interpolator = try sharing.interpolator(gpa, evals.keys);
    defer interpolator.deinit(gpa);
    const keys = evals.keys;
    const signature = try interpolator.interpolate_strategy(
        V.Signature,
        gpa,
        keys,
        evals.values,
        strategy,
    );
    return signature orelse error.InvalidRecovery;
}

/// Recovers one signature per set of partials into `out`. Every set must select the same
/// indices (`InvalidIndex` otherwise), so one interpolator serves them all. `strategy`
/// interpolates the sets in parallel, as commonware does.
pub fn recover_multiple(
    comptime V: type,
    gpa: Allocator,
    sharing: Sharing(V),
    sets: []const []const PartialSignature(V),
    out: []V.Signature,
    strategy: anytype,
) (Error || Allocator.Error)!void {
    assert(sets.len == out.len);
    if (sets.len == 0) return;
    const prepared = try gpa.alloc(Evaluations(V), sets.len);
    defer gpa.free(prepared);
    var built: usize = 0;
    defer for (prepared[0..built]) |*evals| evals.deinit(gpa);
    while (built < sets.len) : (built += 1) {
        prepared[built] = try Evaluations(V).prepare(gpa, sharing.required(), sets[built]);
    }
    const first = prepared[0].keys;
    for (prepared[1..]) |evals| {
        if (evals.keys.len != first.len) return error.InvalidIndex;
        for (evals.keys, first) |a, b| if (a.get() != b.get()) return error.InvalidIndex;
    }
    var interpolator = try sharing.interpolator(gpa, first);
    defer interpolator.deinit(gpa);
    const Interpolate = struct {
        interpolator: *const @TypeOf(interpolator),

        pub fn map(self: @This(), evals: *const Evaluations(V)) ?V.Signature {
            return self.interpolator.interpolate(V.Signature, evals.keys, evals.values);
        }
    };
    const recovered = try gpa.alloc(?V.Signature, sets.len);
    defer gpa.free(recovered);
    strategy.map_into(prepared, recovered, Interpolate{ .interpolator = &interpolator });
    for (out, recovered) |*signature, value| {
        signature.* = value orelse return error.InvalidRecovery;
    }
}

/// Recovers two signatures from two sets of partials (`recover_multiple` for a pair).
pub fn recover_pair(
    comptime V: type,
    gpa: Allocator,
    sharing: Sharing(V),
    first: []const PartialSignature(V),
    second: []const PartialSignature(V),
    strategy: anytype,
) (Error || Allocator.Error)![2]V.Signature {
    var out: [2]V.Signature = undefined;
    try recover_multiple(V, gpa, sharing, &.{ first, second }, &out, strategy);
    return out;
}

test {
    _ = @import("threshold_tests.zig");
}
