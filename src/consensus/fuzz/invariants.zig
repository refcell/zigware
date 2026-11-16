//! The safety invariants the engine fuzzers check after a run (commonware
//! `consensus/fuzz/src/invariants.rs` `check`), over the certificates each honest replica
//! reported.
//!
//! commonware panics with a message on the first violation; here `find` returns the first
//! violation as a `Kind` and a view, and `check` turns it into `error.InvariantViolation`.
//! The checks run in commonware's order. Where commonware iterates a `HashMap`, the order
//! among views here is ascending instead, which commonware leaves unspecified.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const consensus_types = @import("../types.zig");
const bounds = @import("bounds.zig");
const fuzz_types = @import("types.zig");

const TermLength = consensus_types.TermLength;
const Configuration = fuzz_types.Configuration;
const Replica = fuzz_types.Replica;
const Certified = fuzz_types.Certified;
const Nullification = fuzz_types.Nullification;
const Digest = fuzz_types.Digest;

/// Which invariant failed (commonware's panic messages, in check order).
pub const Kind = enum {
    /// "finalized digest mismatch in view {view}"
    finalized_digest_mismatch,
    /// "finalized parent mismatch in view {view}" (honest quorum only)
    finalized_parent_mismatch,
    /// "view {view} finalized with parent {parent} not strictly below it"
    parent_not_below,
    /// "view {view} finalized strictly between parent {parent} and finalized child"
    finalized_between_parent_and_child,
    /// "intra-term view {view} finalized with non-immediate parent"
    non_immediate_parent,
    /// "finalized over view {view} ... with no nullification"
    unnullified_skip,
    /// "view {view} is nullified but view ... is finalized in the same term"
    same_term_nullification,
    /// "replica ... notarized view {view} with ... but finalized with ..."
    notarization_finalization_mismatch,
    /// "conflicting quorum notarizations in view {view}"
    conflicting_quorum_notarizations,
    /// "finalization without notarization: view {view}"
    finalization_without_notarization,
    /// "view {view} has both nullification and finalization"
    nullified_and_finalized,
    /// "... in view {view} has {count} < {threshold} signatures"
    insufficient_signatures,
    /// "non-attributable scheme should not expose signature count"
    unexpected_signature_count,
};

pub const Violation = struct {
    kind: Kind,
    view: u64,

    pub fn format(self: Violation, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{t} (view {d})", .{ self.kind, self.view });
    }
};

/// Checks every invariant; fails with `error.InvariantViolation` on the first violation.
/// `attributable` is the scheme's `is_attributable()`.
pub fn check(
    gpa: Allocator,
    attributable: bool,
    configuration: Configuration,
    term_length: TermLength,
    replicas: []const Replica,
) !void {
    const violation = try find(gpa, attributable, configuration, term_length, replicas) orelse
        return;
    std.debug.print("invariant violation: {f}\n", .{violation});
    return error.InvariantViolation;
}

/// The first invariant violation, or null when every invariant holds.
pub fn find(
    gpa: Allocator,
    attributable: bool,
    configuration: Configuration,
    term_length: TermLength,
    replicas: []const Replica,
) Allocator.Error!?Violation {
    const threshold = bounds.quorum(configuration.n);
    if (check_agreement(configuration, replicas)) |violation| return violation;
    if (configuration.can_finalize()) {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const merged = try Merged.init(arena.allocator(), replicas, threshold);
        if (check_ancestry(&merged, term_length)) |violation| return violation;
        if (check_exclusion(&merged, replicas, term_length)) |violation| return violation;
    }
    return check_signature_counts(replicas, attributable, threshold);
}

fn same_proposal(a: anytype, b: anytype) bool {
    assert(a.view == b.view);
    return a.payload.order(b.payload) == .eq and a.parent == b.parent;
}

/// The index of the first item whose view is at least `view` (items sorted by view).
fn lower_bound(items: anytype, view: u64) usize {
    var low: usize = 0;
    var high: usize = items.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (items[middle].view < view) low = middle + 1 else high = middle;
    }
    assert(low <= items.len);
    return low;
}

fn find_view(items: []const Certified, view: u64) ?Certified {
    const index = lower_bound(items, view);
    if (index == items.len or items[index].view != view) return null;
    return items[index];
}

/// Finalizations of a view agree across replicas: the payload always, the parent with an
/// honest quorum (a Byzantine quorum can mint a mutated parent beside the honest one).
fn check_agreement(configuration: Configuration, replicas: []const Replica) ?Violation {
    for (replicas, 0..) |replica, index| {
        for (replica.finalizations) |finalization| {
            for (replicas[0..index]) |earlier| {
                const first = find_view(earlier.finalizations, finalization.view) orelse continue;
                const view = finalization.view;
                if (first.payload.order(finalization.payload) != .eq) {
                    return .{ .kind = .finalized_digest_mismatch, .view = view };
                }
                if (configuration.can_finalize() and first.parent != finalization.parent) {
                    return .{ .kind = .finalized_parent_mismatch, .view = view };
                }
                break;
            }
        }
    }
    return null;
}

/// A notarized proposal, and whether some replica holds a quorum certificate for it.
const Notarized = struct {
    view: u64,
    payload: Digest,
    parent: u64,
    quorum: bool,

    fn order(a: Notarized, b: Notarized) std.math.Order {
        if (a.view != b.view) return std.math.order(a.view, b.view);
        const payload = a.payload.order(b.payload);
        if (payload != .eq) return payload;
        return std.math.order(a.parent, b.parent);
    }

    fn less_than(_: void, a: Notarized, b: Notarized) bool {
        return a.order(b) == .lt;
    }
};

/// Every replica's certificates merged: finalizations one per view (the last replica's, as
/// commonware's map collection keeps), nullified views, and distinct notarized proposals.
const Merged = struct {
    finalizations: []Certified,
    nullified: []u64,
    notarizations: []Notarized,

    fn init(arena: Allocator, replicas: []const Replica, threshold: u32) !Merged {
        var finalizations: std.ArrayList(Certified) = .empty;
        var nullified: std.ArrayList(u64) = .empty;
        var notarizations: std.ArrayList(Notarized) = .empty;
        for (replicas) |replica| {
            try finalizations.appendSlice(arena, replica.finalizations);
            for (replica.nullifications) |nullification| {
                try nullified.append(arena, nullification.view);
            }
            for (replica.notarizations) |n| {
                const quorum = if (n.signature_count) |count| count >= threshold else true;
                const item: Notarized =
                    .{ .view = n.view, .payload = n.payload, .parent = n.parent, .quorum = quorum };
                try notarizations.append(arena, item);
            }
        }
        return .{
            .finalizations = dedup_finalizations(finalizations.items),
            .nullified = dedup_views(nullified.items),
            .notarizations = dedup_notarizations(notarizations.items),
        };
    }

    /// Sorted by view (stable), keeping the last finalization of each view.
    fn dedup_finalizations(items: []Certified) []Certified {
        std.sort.block(Certified, items, {}, struct {
            fn less_than(_: void, a: Certified, b: Certified) bool {
                return a.view < b.view;
            }
        }.less_than);
        var count: usize = 0;
        for (items) |item| {
            if (count > 0 and items[count - 1].view == item.view) {
                items[count - 1] = item;
            } else {
                items[count] = item;
                count += 1;
            }
        }
        assert(count <= items.len);
        return items[0..count];
    }

    fn dedup_views(items: []u64) []u64 {
        std.sort.block(u64, items, {}, std.sort.asc(u64));
        var count: usize = 0;
        for (items) |item| {
            if (count > 0 and items[count - 1] == item) continue;
            items[count] = item;
            count += 1;
        }
        return items[0..count];
    }

    fn dedup_notarizations(items: []Notarized) []Notarized {
        std.sort.block(Notarized, items, {}, Notarized.less_than);
        var count: usize = 0;
        for (items) |item| {
            if (count > 0 and items[count - 1].order(item) == .eq) {
                items[count - 1].quorum = items[count - 1].quorum or item.quorum;
                continue;
            }
            items[count] = item;
            count += 1;
        }
        return items[0..count];
    }

    fn notarized(self: *const Merged, finalization: Certified) bool {
        const key: Notarized = .{
            .view = finalization.view,
            .payload = finalization.payload,
            .parent = finalization.parent,
            .quorum = false,
        };
        var index = lower_bound(self.notarizations, key.view);
        while (index < self.notarizations.len) : (index += 1) {
            const order = self.notarizations[index].order(key);
            if (order == .eq) return true;
            if (order == .gt) return false;
        }
        return false;
    }
};

fn term_of(view: u64, term_length: TermLength) u64 {
    if (view == 0) return 0;
    return 1 + (view - 1) / term_length.get();
}

fn is_term_start(view: u64, term_length: TermLength) bool {
    return view == 0 or (view - 1) % term_length.get() == 0;
}

/// Whether a nullification at `nullified` excludes finalizing `finalized` (same term, and
/// not after it).
fn nullification_conflicts(nullified: u64, finalized: u64, term_length: TermLength) bool {
    if (nullified > finalized) return false;
    if (nullified == 0) return finalized == 0;
    assert(finalized > 0);
    const length = term_length.get();
    return (nullified - 1) / length == (finalized - 1) / length;
}

/// The highest nullified view at or below `view`.
fn last_nullified_at_most(nullified: []const u64, view: u64) ?u64 {
    // The first index holding a view above `view`.
    var low: usize = 0;
    var high: usize = nullified.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (nullified[middle] <= view) low = middle + 1 else high = middle;
    }
    assert(low == nullified.len or nullified[low] > view);
    return if (low == 0) null else nullified[low - 1];
}

/// Finalized views form one chain: each parent lies strictly below its view and at or above
/// the previous finalized view; inside a term the parent is the view before, and a term start
/// skips only views whose terms were nullified.
fn check_ancestry(merged: *const Merged, term_length: TermLength) ?Violation {
    var previous: ?u64 = null;
    for (merged.finalizations) |finalization| {
        const view = finalization.view;
        const parent = finalization.parent;
        if (parent >= view) return .{ .kind = .parent_not_below, .view = view };
        if (previous) |previous_view| if (parent < previous_view) {
            return .{ .kind = .finalized_between_parent_and_child, .view = previous_view };
        };
        previous = view;
        if (!is_term_start(view, term_length)) {
            if (parent + 1 != view) return .{ .kind = .non_immediate_parent, .view = view };
            continue;
        }
        // Each step needs a nullification in the cursor's term, so the loop runs at most
        // once per nullified view, plus one.
        var cursor = parent + 1;
        while (cursor < view) {
            const term = term_of(cursor, term_length);
            const nullified = last_nullified_at_most(merged.nullified, cursor);
            const covered = if (nullified) |n| term_of(n, term_length) == term else false;
            if (!covered) return .{ .kind = .unnullified_skip, .view = cursor };
            const next = term * term_length.get() + 1;
            assert(next > cursor);
            cursor = next;
        }
    }
    return null;
}

/// With an honest quorum: no nullification shares a term with a later finalization, every
/// notarization of a finalized view names the finalized proposal, quorum notarizations of a
/// view agree, every finalization was notarized, and no replica nullified a finalized view.
fn check_exclusion(
    merged: *const Merged,
    replicas: []const Replica,
    term_length: TermLength,
) ?Violation {
    for (merged.finalizations) |finalization| for (merged.nullified) |nullified| {
        if (nullification_conflicts(nullified, finalization.view, term_length)) {
            return .{ .kind = .same_term_nullification, .view = nullified };
        }
    };
    for (replicas) |replica| for (replica.notarizations) |notarization| {
        const finalized = find_view(merged.finalizations, notarization.view) orelse continue;
        if (!same_proposal(finalized, notarization)) {
            return .{ .kind = .notarization_finalization_mismatch, .view = notarization.view };
        }
    };
    var quorum_view: ?u64 = null;
    for (merged.notarizations) |notarization| {
        if (!notarization.quorum) continue;
        if (quorum_view == notarization.view) {
            return .{ .kind = .conflicting_quorum_notarizations, .view = notarization.view };
        }
        quorum_view = notarization.view;
    }
    for (replicas) |replica| for (replica.finalizations) |finalization| {
        if (!merged.notarized(finalization)) {
            return .{ .kind = .finalization_without_notarization, .view = finalization.view };
        }
    };
    for (replicas) |replica| for (replica.nullifications) |nullification| {
        if (find_view(replica.finalizations, nullification.view) != null) {
            return .{ .kind = .nullified_and_finalized, .view = nullification.view };
        }
    };
    return null;
}

fn check_count(view: u64, count: ?u32, attributable: bool, threshold: u32) ?Violation {
    if (!attributable) {
        if (count != null) return .{ .kind = .unexpected_signature_count, .view = view };
        return null;
    }
    // Proof: `extract` counts the signers of every attributable certificate.
    const signers = count orelse unreachable;
    if (signers < threshold) return .{ .kind = .insufficient_signatures, .view = view };
    return null;
}

/// Every certificate of an attributable scheme carries at least a quorum of signers; a
/// non-attributable scheme exposes no count.
fn check_signature_counts(
    replicas: []const Replica,
    attributable: bool,
    threshold: u32,
) ?Violation {
    for (replicas) |replica| {
        for (replica.nullifications) |n| {
            if (check_count(n.view, n.signature_count, attributable, threshold)) |v| return v;
        }
        for (replica.notarizations) |n| {
            if (check_count(n.view, n.signature_count, attributable, threshold)) |v| return v;
        }
        for (replica.finalizations) |f| {
            if (check_count(f.view, f.signature_count, attributable, threshold)) |v| return v;
        }
    }
    return null;
}

// commonware's `invariants::tests`, all with ed25519 (attributable) and three signers.

const n4f1c3 = fuzz_types.n4f1c3;
const n4f3c1 = fuzz_types.n4f3c1;
const term_five: TermLength = .{ .length = 5 };

fn certified(view: u64, byte: u8, parent: u64) Certified {
    return .{ .view = view, .payload = .fill(byte), .parent = parent, .signature_count = 3 };
}

fn nullified_at(view: u64) Nullification {
    return .{ .view = view, .signature_count = 3 };
}

fn expect_violation(
    kind: Kind,
    configuration: Configuration,
    term_length: TermLength,
    replicas: []const Replica,
) !void {
    const violation = try find(testing.allocator, true, configuration, term_length, replicas);
    try testing.expectEqual(kind, violation.?.kind);
}

fn expect_none(
    configuration: Configuration,
    term_length: TermLength,
    replicas: []const Replica,
) !void {
    const violation = try find(testing.allocator, true, configuration, term_length, replicas);
    try testing.expectEqual(null, violation);
}

test "same-term nullification blocks a later finalization" {
    // Parent 2 keeps the ancestry rules satisfied, so only the same-term rule can fire.
    const replica: Replica = .{
        .notarizations = &.{certified(3, 7, 2)},
        .nullifications = &.{nullified_at(1)},
        .finalizations = &.{certified(3, 7, 2)},
    };
    try expect_violation(.same_term_nullification, n4f1c3, term_five, &.{replica});
}

test "a parent mismatch requires an honest quorum" {
    const replicas = [_]Replica{
        .{ .notarizations = &.{certified(3, 9, 1)}, .finalizations = &.{certified(3, 9, 1)} },
        .{ .notarizations = &.{certified(3, 9, 2)}, .finalizations = &.{certified(3, 9, 2)} },
    };
    // A Byzantine quorum can mint a certificate with a mutated parent beside the honest one.
    try expect_none(n4f3c1, term_five, &replicas);
    try expect_violation(.finalized_parent_mismatch, n4f1c3, term_five, &replicas);
}

test "a same-term nullification requires an honest quorum" {
    const replica: Replica = .{
        .nullifications = &.{nullified_at(1)},
        .finalizations = &.{certified(3, 8, 2)},
    };
    try expect_none(n4f3c1, term_five, &.{replica});
}

test "a finalization between a parent and its child fires" {
    // View 5 builds on view 1 although view 2 is finalized: view 2 is forked around.
    const replica: Replica = .{
        .notarizations = &.{ certified(2, 2, 1), certified(5, 5, 1) },
        .finalizations = &.{ certified(2, 2, 1), certified(5, 5, 1) },
    };
    try expect_violation(.finalized_between_parent_and_child, n4f1c3, .one, &.{replica});
}

test "an intra-term parent skip fires" {
    // View 4 is not a term start, so it must build on view 3.
    const replica: Replica = .{
        .notarizations = &.{certified(4, 4, 2)},
        .finalizations = &.{certified(4, 4, 2)},
    };
    try expect_violation(.non_immediate_parent, n4f1c3, term_five, &.{replica});
    try expect_none(n4f3c1, term_five, &.{replica});
}

/// View 11 finalized over view 3 (a container-level constant, so replicas can borrow it).
const skip_certified = [_]Certified{certified(11, 6, 3)};

fn skip_replica(nullifications: []const Nullification) Replica {
    return .{
        .notarizations = &skip_certified,
        .nullifications = nullifications,
        .finalizations = &skip_certified,
    };
}

test "a term-start skip requires nullifications" {
    // View 11 starts a term; skipping back to view 3 needs the terms of views 4 and 6
    // nullified.
    const fire = expect_violation;
    try fire(.unnullified_skip, n4f1c3, term_five, &.{skip_replica(&.{})});
    // Nullifying only the first skipped term leaves the second uncovered.
    try fire(.unnullified_skip, n4f1c3, term_five, &.{skip_replica(&.{nullified_at(4)})});
    // A nullification covers only its view and the rest of its term: late nullifications
    // (views 5 and 10) leave view 4 uncovered.
    const late = [_]Nullification{ nullified_at(5), nullified_at(10) };
    const replicas = [_]Replica{skip_replica(&late)};
    const violation = try find(testing.allocator, true, n4f1c3, term_five, &replicas);
    try testing.expectEqual(Violation{ .kind = .unnullified_skip, .view = 4 }, violation.?);
    const both = [_]Nullification{ nullified_at(4), nullified_at(6) };
    try expect_none(n4f1c3, term_five, &.{skip_replica(&both)});
}

test "a parent at or above its child fires" {
    const replica: Replica = .{ .finalizations = &.{certified(3, 3, 3)} };
    try expect_violation(.parent_not_below, n4f1c3, term_five, &.{replica});
}

test "a finalization without notarization fires" {
    const replica: Replica = .{ .finalizations = &.{certified(3, 10, 2)} };
    try expect_violation(.finalization_without_notarization, n4f1c3, term_five, &.{replica});
}

test "a notarization naming another parent than the finalization fires" {
    const replica: Replica = .{
        .notarizations = &.{certified(3, 11, 1)},
        .finalizations = &.{certified(3, 11, 2)},
    };
    try expect_violation(.notarization_finalization_mismatch, n4f1c3, term_five, &.{replica});
}

test "quorum notarizations with conflicting parents fire" {
    const replicas = [_]Replica{
        .{ .notarizations = &.{certified(3, 12, 1)} },
        .{ .notarizations = &.{certified(3, 12, 2)} },
    };
    try expect_none(n4f3c1, term_five, &replicas);
    try expect_violation(.conflicting_quorum_notarizations, n4f1c3, term_five, &replicas);
}

test "signature counts" {
    var short = certified(3, 1, 2);
    short.signature_count = 2;
    const replica: Replica = .{ .notarizations = &.{short} };
    try expect_violation(.insufficient_signatures, n4f1c3, term_five, &.{replica});
    // A non-attributable scheme exposes no count.
    const exposed = try find(testing.allocator, false, n4f1c3, term_five, &.{replica});
    try testing.expectEqual(Kind.unexpected_signature_count, exposed.?.kind);
    short.signature_count = null;
    const hidden: Replica = .{ .notarizations = &.{short} };
    const none = try find(testing.allocator, false, n4f1c3, term_five, &.{hidden});
    try testing.expectEqual(null, none);
}
