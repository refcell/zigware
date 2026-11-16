//! commonware `actors/resolver/state.rs` tests: the effects every certificate and verdict
//! produces, what the state serves, and how background asks open and retire.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ed25519 = @import("../../scheme/ed25519.zig");
const ask = @import("../ask.zig");
const state_mod = @import("state.zig");

const gpa = testing.allocator;
const Digest = cryptography.Sha256.Digest;
const Scheme = ed25519.Scheme(Digest);
const State = state_mod.State(Scheme, Digest);
const Effect = state_mod.Effect;
const FetchReason = state_mod.FetchReason;
const Certificate = types.Certificate(Scheme, Digest);
const Notarization = types.Notarization(Scheme, Digest);
const View = consensus_types.View;
const TermLength = consensus_types.TermLength;
const Epoch = consensus_types.Epoch;
const epoch: Epoch = .new(9);

fn term(length: u32) TermLength {
    return .new(utils.NonZero(u32).init(length).?);
}

fn fetch(view: u64, cause: u64, reason: FetchReason) Effect {
    return .{ .fetch = .{ .view = .new(view), .cause = .new(cause), .reason = reason } };
}

fn settled(kind: ask.Kind, start: u64, end: u64) Effect {
    return .{ .settled = .{ .kind = kind, .start = .new(start), .end = .new(end) } };
}

fn finalized(view: u64) Effect {
    return .{ .finalized = .new(view) };
}

fn raised(view: u64) Effect {
    return .{ .raised = .new(view) };
}

fn expect_effects(expected: []const Effect, actual: []const Effect) !void {
    try testing.expectEqualDeep(expected, actual);
}

/// Views of outstanding background (nullification) asks, maintained from effects as the
/// resolver actor would.
const Outstanding = struct {
    views: std.ArrayList(u64) = .empty,

    fn deinit(self: *Outstanding) void {
        self.views.deinit(gpa);
    }

    fn insert(self: *Outstanding, view: u64) !void {
        const index = std.sort.lowerBound(u64, self.views.items, view, order_u64);
        const items = self.views.items;
        if (index < items.len and items[index] == view) return;
        try self.views.insert(gpa, index, view);
    }

    fn order_u64(target: u64, item: u64) std.math.Order {
        return std.math.order(target, item);
    }

    /// Keeps the views `keep` admits.
    fn retain(self: *Outstanding, keep: anytype) void {
        var kept: usize = 0;
        for (self.views.items) |view| {
            if (!keep.call(view)) continue;
            self.views.items[kept] = view;
            kept += 1;
        }
        self.views.shrinkRetainingCapacity(kept);
    }

    fn apply(self: *Outstanding, effects: []const Effect) !void {
        for (effects) |effect| switch (effect) {
            .fetch => |missing| try self.insert(missing.view.get()),
            .settled => |range| {
                if (range.kind != .nullification) continue;
                self.retain(Outside{ .start = range.start.get(), .end = range.end.get() });
            },
            .finalized, .raised => |floor| self.retain(Above{ .floor = floor.get() }),
        };
    }

    const Outside = struct {
        start: u64,
        end: u64,
        fn call(self: Outside, view: u64) bool {
            return view < self.start or view > self.end;
        }
    };

    const Above = struct {
        floor: u64,
        fn call(self: Above, view: u64) bool {
            return view > self.floor;
        }
    };

    fn expect(self: *const Outstanding, expected: []const u64) !void {
        try testing.expectEqualSlices(u64, expected, self.views.items);
    }
};

/// Five ed25519 signers, an arena for the certificates they build, and the effect buffer.
const Env = struct {
    arena: std.heap.ArenaAllocator,
    fixture: cryptography.certificate.mocks.Fixture(Scheme),
    effects: std.ArrayList(Effect) = .empty,
    outstanding: Outstanding = .{},

    fn init(self: *Env) !void {
        var rng = utils.rng.test_rng();
        const fixture = try ed25519.fixture(Digest, gpa, &rng, "resolver-state", 5);
        self.* = .{ .arena = .init(gpa), .fixture = fixture };
        assert(self.fixture.schemes.len == 5);
    }

    fn deinit(self: *Env) void {
        self.outstanding.deinit();
        self.effects.deinit(gpa);
        self.fixture.deinit(gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    fn allocator(self: *Env) Allocator {
        return self.arena.allocator();
    }

    /// A state past journal replay, so every update scans at once.
    fn live(self: *Env, length: u32) !State {
        var state = State.init(gpa, term(length));
        errdefer state.deinit();
        try expect_effects(&.{}, try self.replayed(&state));
        return state;
    }

    fn proposal(view: u64) types.Proposal(Digest) {
        const parent: View = View.new(view).previous() orelse .zero();
        return .init(.new(epoch, .new(view)), parent, .fill(@truncate(view)));
    }

    fn nullification(self: *Env, view: u64) !Certificate {
        const Nullify = types.Nullify(Scheme);
        var votes: [5]Nullify = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Nullify.sign(gpa, scheme, .new(epoch, .new(view)))).?;
        }
        const Nullification = types.Nullification(Scheme);
        const verifier = &self.fixture.verifier;
        const sequential = parallel.sequential;
        const built = try Nullification.from_votes(self.allocator(), verifier, &votes, sequential);
        return .{ .nullification = built };
    }

    fn notarization(self: *Env, view: u64) !Notarization {
        const Notarize = types.Notarize(Scheme, Digest);
        var votes: [5]Notarize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Notarize.sign(gpa, scheme, proposal(view))).?;
        }
        const verifier = &self.fixture.verifier;
        return Notarization.from_votes(self.allocator(), verifier, &votes, parallel.sequential);
    }

    fn finalization(self: *Env, view: u64) !Certificate {
        const Finalize = types.Finalize(Scheme, Digest);
        const Finalization = types.Finalization(Scheme, Digest);
        var votes: [5]Finalize = undefined;
        for (&votes, self.fixture.schemes) |*vote, *scheme| {
            vote.* = (try Finalize.sign(gpa, scheme, proposal(view))).?;
        }
        const verifier = &self.fixture.verifier;
        const sequential = parallel.sequential;
        const built = try Finalization.from_votes(self.allocator(), verifier, &votes, sequential);
        return .{ .finalization = built };
    }

    fn encode(self: *Env, certificate: Certificate) ![]const u8 {
        return codec.encode(Certificate, self.allocator(), certificate);
    }

    /// The effects of recording `certificate` (valid until the next call).
    fn updated(self: *Env, state: *State, certificate: Certificate) ![]const Effect {
        self.effects.clearRetainingCapacity();
        try state.updated(&certificate, &self.effects);
        return self.effects.items;
    }

    fn updated_notarization(self: *Env, state: *State, value: Notarization) ![]const Effect {
        return self.updated(state, .{ .notarization = value });
    }

    fn certified(
        self: *Env,
        state: *State,
        value: Notarization,
        success: bool,
    ) ![]const Effect {
        self.effects.clearRetainingCapacity();
        try state.certified(&value, success, &self.effects);
        return self.effects.items;
    }

    fn replayed(self: *Env, state: *State) ![]const Effect {
        self.effects.clearRetainingCapacity();
        try state.replayed(&self.effects);
        return self.effects.items;
    }
};

fn expect_produce(state: *const State, view: u64, expected: ?[]const u8) !void {
    const actual = state.produce(.new(view));
    const bytes = expected orelse return testing.expectEqual(null, actual);
    try testing.expectEqualSlices(u8, bytes, actual orelse return error.TestExpectedEqual);
}

test "nullification requests missing views" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    var effects = try env.updated(&state, try env.nullification(4));
    try expect_effects(&.{
        settled(.nullification, 4, 4),
        fetch(1, 4, .missing_nullification),
        fetch(2, 4, .missing_nullification),
        fetch(3, 4, .missing_nullification),
    }, effects);
    try env.outstanding.apply(effects);
    try testing.expectEqual(View.new(4), state.current_view);
    try testing.expect(state.nullifications.contains(.new(4)));
    try env.outstanding.expect(&.{ 1, 2, 3 });

    effects = try env.updated(&state, try env.nullification(2));
    try expect_effects(&.{settled(.nullification, 2, 2)}, effects);
    try env.outstanding.apply(effects);
    try testing.expectEqual(View.new(4), state.current_view);
    try testing.expect(state.nullifications.contains(.new(2)));
    try env.outstanding.expect(&.{ 1, 3 });

    effects = try env.updated(&state, try env.nullification(1));
    try expect_effects(&.{settled(.nullification, 1, 1)}, effects);
    try env.outstanding.apply(effects);
    try testing.expect(state.nullifications.contains(.new(1)));
    try env.outstanding.expect(&.{3});
}

test "replay defers fetches until replayed" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = State.init(gpa, .one);
    defer state.deinit();
    // A notarization at view 4 with no floor would scan 1..4 when live.
    const pending = try env.notarization(4);
    try expect_effects(
        &.{settled(.notarization, 4, 4)},
        try env.updated_notarization(&state, pending),
    );
    try expect_effects(&.{settled(.notarization, 4, 4)}, try env.certified(&state, pending, false));
    const effects = try env.updated(&state, try env.finalization(5));
    try expect_effects(&.{ finalized(5), raised(5) }, effects);
    // Above the floor, a failed certification and a gap stay open.
    const failed = try env.notarization(7);
    try expect_effects(
        &.{settled(.notarization, 7, 7)},
        try env.updated_notarization(&state, failed),
    );
    try expect_effects(&.{settled(.notarization, 7, 7)}, try env.certified(&state, failed, false));
    const nullification_9 = try env.nullification(9);
    try expect_effects(&.{settled(.nullification, 9, 9)}, try env.updated(&state, nullification_9));
    try expect_effects(&.{
        fetch(6, 9, .missing_nullification),
        fetch(7, 9, .missing_nullification),
        fetch(8, 9, .missing_nullification),
        fetch(7, 7, .certification_failed),
    }, try env.replayed(&state));
    // Later updates scan at once.
    try expect_effects(&.{
        settled(.nullification, 11, 11),
        fetch(10, 11, .missing_nullification),
    }, try env.updated(&state, try env.nullification(11)));
}

test "replay repairs failures above a certified floor" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = State.init(gpa, term(5));
    defer state.deinit();
    const failed = try env.notarization(5);
    try expect_effects(
        &.{settled(.notarization, 5, 5)},
        try env.updated_notarization(&state, failed),
    );
    try expect_effects(&.{settled(.notarization, 5, 5)}, try env.certified(&state, failed, false));
    const good = try env.notarization(6);
    try expect_effects(
        &.{settled(.notarization, 6, 6)},
        try env.updated_notarization(&state, good),
    );
    try expect_effects(
        &.{ settled(.notarization, 6, 6), raised(6) },
        try env.certified(&state, good, true),
    );
    for ([_]u64{ 8, 9 }) |view| {
        const value = try env.notarization(view);
        const expected = &.{settled(.notarization, view, view)};
        try expect_effects(expected, try env.updated_notarization(&state, value));
        try expect_effects(expected, try env.certified(&state, value, false));
    }
    try expect_effects(&.{
        fetch(7, 9, .missing_nullification),
        fetch(8, 8, .certification_failed),
        fetch(9, 9, .certification_failed),
    }, try env.replayed(&state));
}

test "fetch requests only term-anchor nullifications" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    const effects = try env.updated(&state, try env.nullification(14));
    try expect_effects(&.{
        settled(.nullification, 14, 15),
        fetch(1, 14, .missing_nullification),
        fetch(6, 14, .missing_nullification),
        fetch(11, 14, .missing_nullification),
    }, effects);
    try env.outstanding.apply(effects);
    try env.outstanding.expect(&.{ 1, 6, 11 });
    try env.outstanding.apply(try env.updated(&state, try env.nullification(1)));
    try env.outstanding.expect(&.{ 6, 11 });
    try env.outstanding.apply(try env.updated(&state, try env.nullification(6)));
    try env.outstanding.expect(&.{11});
}

test "same-term nullification covers later views until finalized" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    const nullification_2 = try env.nullification(2);
    _ = try env.updated(&state, nullification_2);
    const bytes = try env.encode(nullification_2);
    try expect_produce(&state, 2, bytes);
    try expect_produce(&state, 5, bytes);
    try testing.expectEqual(null, state.covering_nullification(.new(6)));
    _ = try env.updated(&state, try env.finalization(3));
    try testing.expectEqual(1, state.nullifications.len());
    try expect_produce(&state, 4, bytes);
    _ = try env.updated(&state, try env.finalization(5));
    try testing.expectEqual(0, state.nullifications.len());
}

test "nullification below the floor can cover unresolved term views" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    try env.outstanding.apply(try env.updated(&state, try env.finalization(3)));
    try env.outstanding.apply(try env.updated(&state, try env.nullification(6)));
    try env.outstanding.expect(&.{4});
    const nullification_2 = try env.nullification(2);
    try env.outstanding.apply(try env.updated(&state, nullification_2));
    try env.outstanding.expect(&.{});
    const bytes = try env.encode(nullification_2);
    try expect_produce(&state, 4, bytes);
    try expect_produce(&state, 5, bytes);
}

test "nullification admission matches the pruning boundary" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    try expect_effects(
        &.{ finalized(3), raised(3) },
        try env.updated(&state, try env.finalization(3)),
    );
    const nullification_2 = try env.nullification(2);
    try expect_effects(&.{settled(.nullification, 2, 5)}, try env.updated(&state, nullification_2));
    try testing.expect(state.covering_nullification(.new(4)) != null);
    try expect_effects(
        &.{ finalized(5), raised(5) },
        try env.updated(&state, try env.finalization(5)),
    );
    try testing.expectEqual(0, state.nullifications.len());
    try expect_effects(&.{}, try env.updated(&state, nullification_2));
    try testing.expectEqual(0, state.nullifications.len());
}

test "floor retires outstanding requests" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    for (4..7) |view| {
        try env.outstanding.apply(try env.updated(&state, try env.nullification(view)));
    }
    try testing.expectEqual(View.new(6), state.current_view);
    try env.outstanding.expect(&.{ 1, 2, 3 });
    try env.outstanding.apply(try env.updated_notarization(&state, try env.notarization(6)));
    try testing.expectEqual(View.zero(), state.floor);
    try testing.expectEqual(3, state.nullifications.len());
    try env.outstanding.expect(&.{ 1, 2, 3 });
    const effects = try env.updated(&state, try env.finalization(6));
    try expect_effects(&.{ finalized(6), raised(6) }, effects);
    try env.outstanding.apply(effects);
    try testing.expectEqual(View.new(6), state.floor);
    try testing.expectEqual(0, state.nullifications.len());
    try env.outstanding.expect(&.{});
}

test "produce serves the finalization, then a nullification, then the floor" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    // A finalization is served at and below its view.
    const finalization_3 = try env.finalization(3);
    _ = try env.updated(&state, finalization_3);
    const final_bytes = try env.encode(finalization_3);
    for (1..4) |view| try expect_produce(&state, view, final_bytes);
    // A nullification above the finalization is served; one below it is not retained.
    const nullification_4 = try env.nullification(4);
    _ = try env.updated(&state, nullification_4);
    _ = try env.updated(&state, try env.nullification(1));
    try testing.expect(!state.nullifications.contains(.new(1)));
    try expect_produce(&state, 1, final_bytes);
    const null_bytes = try env.encode(nullification_4);
    try expect_produce(&state, 4, null_bytes);
    try expect_produce(&state, 5, null);
    // A certified notarization becomes the floor, served for itself and uncovered views.
    const notarization_6 = try env.notarization(6);
    _ = try env.updated_notarization(&state, notarization_6);
    _ = try env.certified(&state, notarization_6, true);
    const floor = try env.encode(.{ .notarization = notarization_6 });
    try expect_produce(&state, 4, null_bytes);
    try expect_produce(&state, 5, floor);
    try expect_produce(&state, 6, floor);
    try expect_produce(&state, 7, null);
    // A stale lower finalization does not replace the served one.
    _ = try env.updated(&state, try env.finalization(2));
    try expect_produce(&state, 2, final_bytes);
}

test "produce tracks preferred ancestry when certificates coexist" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    const nullification_3 = try env.nullification(3);
    _ = try env.updated(&state, nullification_3);
    const notarization_3 = try env.notarization(3);
    _ = try env.updated_notarization(&state, notarization_3);
    // A pending notarization is never served.
    try expect_produce(&state, 3, try env.encode(nullification_3));
    _ = try env.certified(&state, notarization_3, true);
    try expect_produce(&state, 3, try env.encode(.{ .notarization = notarization_3 }));
}

fn expect_same_views(a: anytype, b: @TypeOf(a)) !void {
    try testing.expectEqual(a.len(), b.len());
    for (a.entries.items, b.entries.items) |left, right| {
        try testing.expectEqual(left.view, right.view);
        if (@TypeOf(left.value) == []u8) try testing.expectEqualSlices(u8, left.value, right.value);
    }
}

fn expect_same_state(first: *const State, second: *const State) !void {
    try expect_same_views(&first.pending_notarizations, &second.pending_notarizations);
    try expect_same_views(&first.certified_notarizations, &second.certified_notarizations);
    try expect_same_views(
        &first.uncertifiable_notarizations,
        &second.uncertifiable_notarizations,
    );
    try testing.expectEqual(first.floor, second.floor);
    for (1..9) |probe| try expect_produce(second, probe, first.produce(.new(probe)));
}

test "a verdict and its notarization commute" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    const notarization_7 = try env.notarization(7);
    for ([_]bool{ true, false }) |success| {
        var first = try env.live(5);
        defer first.deinit();
        var first_outstanding: Outstanding = .{};
        defer first_outstanding.deinit();
        try first_outstanding.apply(try env.updated_notarization(&first, notarization_7));
        try first_outstanding.apply(try env.certified(&first, notarization_7, success));

        var second = try env.live(5);
        defer second.deinit();
        var second_outstanding: Outstanding = .{};
        defer second_outstanding.deinit();
        try second_outstanding.apply(try env.certified(&second, notarization_7, success));
        try second_outstanding.apply(try env.updated_notarization(&second, notarization_7));

        try expect_same_state(&first, &second);
        try second_outstanding.expect(first_outstanding.views.items);
        try testing.expectEqual(success, first.certified_notarizations.contains(.new(7)));
        try testing.expectEqual(success, first.floor == View.new(7));
    }
}

test "reapplied certificates emit no fetches" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    const nullification_20 = try env.nullification(20);
    const notarization_22 = try env.notarization(22);
    const finalization_23 = try env.finalization(23);
    _ = try env.updated(&state, nullification_20);
    _ = try env.updated_notarization(&state, notarization_22);
    _ = try env.certified(&state, notarization_22, false);
    // Above finalization, copies open no fetch and the failed notarization stays failed.
    try expect_effects(
        &.{settled(.nullification, 20, 20)},
        try env.updated(&state, nullification_20),
    );
    try expect_effects(&.{}, try env.updated_notarization(&state, notarization_22));
    try testing.expect(!state.pending_notarizations.contains(.new(22)));
    try testing.expect(!state.certified_notarizations.contains(.new(22)));
    // After finalization prunes them, copies still open no fetch.
    _ = try env.updated(&state, finalization_23);
    try expect_effects(&.{finalized(23)}, try env.updated(&state, finalization_23));
    try expect_effects(&.{}, try env.updated(&state, nullification_20));
    try expect_effects(&.{}, try env.updated_notarization(&state, notarization_22));
    try testing.expectEqual(0, state.nullifications.len());
    try testing.expectEqual(0, state.pending_notarizations.len());
}

test "a certified notarization's copy is not pending" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    const notarization_3 = try env.notarization(3);
    _ = try env.updated_notarization(&state, notarization_3);
    _ = try env.certified(&state, notarization_3, true);
    const effects = try env.updated_notarization(&state, notarization_3);
    try expect_effects(&.{settled(.notarization, 3, 3)}, effects);
    try testing.expectEqual(0, state.pending_notarizations.len());
}

test "a late verdict after finalization promotes nothing" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    const notarization_5 = try env.notarization(5);
    _ = try env.updated_notarization(&state, notarization_5);
    try testing.expect(state.pending_notarizations.contains(.new(5)));
    _ = try env.updated(&state, try env.finalization(6));
    try testing.expectEqual(0, state.pending_notarizations.len());
    _ = try env.certified(&state, notarization_5, true);
    try testing.expectEqual(0, state.certified_notarizations.len());
}

test "finalization prunes retained certificates" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    _ = try env.updated(&state, try env.nullification(2));
    const pending = try env.notarization(6);
    const good = try env.notarization(7);
    const failed = try env.notarization(8);
    for ([_]Notarization{ pending, good, failed }) |value| {
        _ = try env.updated_notarization(&state, value);
    }
    _ = try env.certified(&state, good, true);
    _ = try env.certified(&state, failed, false);
    try testing.expectEqual(1, state.nullifications.len());
    try testing.expectEqual(1, state.pending_notarizations.len());
    try testing.expectEqual(1, state.certified_notarizations.len());
    try testing.expectEqual(1, state.uncertifiable_notarizations.len());
    _ = try env.updated(&state, try env.finalization(10));
    try testing.expectEqual(0, state.nullifications.len());
    try testing.expectEqual(0, state.pending_notarizations.len());
    try testing.expectEqual(0, state.certified_notarizations.len());
    try testing.expectEqual(0, state.uncertifiable_notarizations.len());
}

/// Records the notarization at view 5 on a term-1 state and checks the scan it opens.
fn notarization_5_scans(env: *Env, state: *State) !Notarization {
    const notarization_5 = try env.notarization(5);
    try expect_effects(&.{
        settled(.notarization, 5, 5),
        fetch(1, 5, .missing_nullification),
        fetch(2, 5, .missing_nullification),
        fetch(3, 5, .missing_nullification),
        fetch(4, 5, .missing_nullification),
    }, try env.updated_notarization(state, notarization_5));
    return notarization_5;
}

test "certification failure re-requests the failed view" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    const notarization_5 = try notarization_5_scans(&env, &state);
    // Only the failed view gets a new background request.
    try expect_effects(&.{
        settled(.notarization, 5, 5),
        fetch(5, 5, .certification_failed),
    }, try env.certified(&state, notarization_5, false));
}

test "certification success sets the floor" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(1);
    defer state.deinit();
    const notarization_5 = try notarization_5_scans(&env, &state);
    const effects = try env.certified(&state, notarization_5, true);
    try testing.expectEqual(View.new(5), state.floor);
    try expect_effects(&.{ settled(.notarization, 5, 5), raised(5) }, effects);
}

/// A term-5 state that saw a nullification at view 14, with its anchors outstanding.
fn live_with_anchors(env: *Env) !State {
    var state = try env.live(5);
    errdefer state.deinit();
    try env.outstanding.apply(try env.updated(&state, try env.nullification(14)));
    try env.outstanding.expect(&.{ 1, 6, 11 });
    return state;
}

test "certification success preserves the remaining anchor requests" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try live_with_anchors(&env);
    defer state.deinit();
    // The pending notarization duplicates no outstanding anchor.
    const notarization_5 = try env.notarization(5);
    const effects = try env.updated_notarization(&state, notarization_5);
    try expect_effects(&.{settled(.notarization, 5, 5)}, effects);
    try env.outstanding.apply(effects);
    try env.outstanding.expect(&.{ 1, 6, 11 });
    // Certification raises the floor past anchor 1 and leaves the higher anchors.
    try env.outstanding.apply(try env.certified(&state, notarization_5, true));
    try testing.expectEqual(View.new(5), state.floor);
    try testing.expectEqual(View.new(14), state.current_view);
    try env.outstanding.expect(&.{ 6, 11 });
}

test "certification success at a mid-term floor refetches the term tail" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try live_with_anchors(&env);
    defer state.deinit();
    const notarization_3 = try env.notarization(3);
    try env.outstanding.apply(try env.updated_notarization(&state, notarization_3));
    try env.outstanding.expect(&.{ 1, 6, 11 });
    // Views 4 and 5 still need a nullification from term [1, 5].
    try env.outstanding.apply(try env.certified(&state, notarization_3, true));
    try testing.expectEqual(View.new(3), state.floor);
    try env.outstanding.expect(&.{ 4, 6, 11 });
}

test "a mid-term floor at the current view refetches the term tail later" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    const notarization_4 = try env.notarization(4);
    try env.outstanding.apply(try env.updated_notarization(&state, notarization_4));
    try env.outstanding.expect(&.{1});
    // The floor rises to the current view, mid-term: nothing above it to fetch yet.
    try env.outstanding.apply(try env.certified(&state, notarization_4, true));
    try testing.expectEqual(View.new(4), state.floor);
    try env.outstanding.expect(&.{});
    // Once the current view grows, the scan resumes just above the mid-term floor.
    try env.outstanding.apply(try env.updated(&state, try env.nullification(14)));
    try env.outstanding.expect(&.{ 5, 6, 11 });
}

test "fetch requests each anchor once" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    try expect_effects(&.{
        settled(.nullification, 14, 15),
        fetch(1, 14, .missing_nullification),
        fetch(6, 14, .missing_nullification),
        fetch(11, 14, .missing_nullification),
    }, try env.updated(&state, try env.nullification(14)));
    // A pending notarization answering anchor 1 never re-requests it.
    const notarization_5 = try env.notarization(5);
    for (0..3) |_| {
        const effects = try env.updated_notarization(&state, notarization_5);
        try expect_effects(&.{settled(.notarization, 5, 5)}, effects);
    }
    // A later certificate requests only newly uncovered anchors.
    try expect_effects(&.{
        settled(.nullification, 20, 20),
        fetch(16, 20, .missing_nullification),
    }, try env.updated(&state, try env.nullification(20)));
}

test "certification failure skips covered re-requests" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try env.live(5);
    defer state.deinit();
    _ = try env.updated(&state, try env.nullification(14));
    const notarization_5 = try env.notarization(5);
    _ = try env.updated_notarization(&state, notarization_5);
    // A nullification at view 1 covers the whole term [1, 5].
    _ = try env.updated(&state, try env.nullification(1));
    const effects = try env.certified(&state, notarization_5, false);
    try expect_effects(&.{settled(.notarization, 5, 5)}, effects);
}

test "finalization at the certified floor serves without refetching" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    var state = try live_with_anchors(&env);
    defer state.deinit();
    const notarization_3 = try env.notarization(3);
    try env.outstanding.apply(try env.updated_notarization(&state, notarization_3));
    try env.outstanding.apply(try env.certified(&state, notarization_3, true));
    try env.outstanding.expect(&.{ 4, 6, 11 });
    const finalization_3 = try env.finalization(3);
    try expect_effects(&.{finalized(3)}, try env.updated(&state, finalization_3));
    try expect_effects(&.{finalized(3)}, try env.updated(&state, try env.finalization(2)));
    const bytes = try env.encode(finalization_3);
    for (1..4) |view| try expect_produce(&state, view, bytes);
}
