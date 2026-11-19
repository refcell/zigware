//! Marshal's durable floors (commonware `marshal/core/floor.rs`).
//!
//! `Processed` is the durable processed height and the stored block behind it. `Cutoff` is
//! the durable round floor: a round, or a whole epoch. `State` holds both, the newest
//! witnessed finalization round, the configured floor until startup takes it, and a floor
//! finalization waiting for its anchor block. It also gates resolver fetches: a request at or
//! below either floor is denied without reaching the resolver.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");
const handler = @import("../resolver/handler.zig");
const resolver_api = @import("resolver");

const Epoch = types.Epoch;
const EpochDelta = types.EpochDelta;
const Height = types.Height;
const HeightDelta = types.HeightDelta;
const Round = types.Round;
const ViewDelta = types.ViewDelta;

/// Marshal's durable processed height and the stored block that backs it.
pub const Processed = union(enum) {
    /// The block at this height is processed and stored.
    block: Height,
    /// This height is processed but its block is not stored. A floor was installed at the next
    /// height, and the floor block backs this position.
    absent: Height,

    /// The processed height.
    pub fn height(self: Processed) Height {
        return switch (self) {
            .block, .absent => |value| value,
        };
    }

    /// The height of the stored block that backs the processed height.
    pub fn anchor(self: Processed) Height {
        return switch (self) {
            .block => |value| value,
            .absent => |value| value.next(),
        };
    }
};

/// An inclusive bound on finalization rounds: a round, or the end of an epoch.
///
/// Cutoffs are ordered by the rounds they cover. A cutoff in an earlier epoch sits below one in
/// a later epoch, and within one epoch `.epoch` sits above every `.round`.
pub const Cutoff = union(enum) {
    /// Covers this round and every earlier round.
    round: Round,
    /// Covers every round of this epoch and of every earlier epoch.
    epoch: Epoch,

    /// The cutoff that covers only the zero round.
    pub fn zero() Cutoff {
        return .{ .round = .zero() };
    }

    /// Whether `round` is at or below the cutoff, that is, `self >= .{ .round = round }`.
    pub fn covers(self: Cutoff, round: Round) bool {
        return switch (self) {
            .round => |last| round.order(last) != .gt,
            .epoch => |epoch| round.epoch.get() <= epoch.get(),
        };
    }

    pub fn order(a: Cutoff, b: Cutoff) std.math.Order {
        return switch (a) {
            .round => |left| switch (b) {
                .round => |right| left.order(right),
                .epoch => |right| tie(left.epoch.order(right), .lt),
            },
            .epoch => |left| switch (b) {
                .round => |right| tie(left.order(right.epoch), .gt),
                .epoch => |right| left.order(right),
            },
        };
    }

    fn tie(order_value: std.math.Order, then: std.math.Order) std.math.Order {
        return if (order_value == .eq) then else order_value;
    }

    pub fn max(a: Cutoff, b: Cutoff) Cutoff {
        return if (a.order(b) == .lt) b else a;
    }

    pub fn eql(a: Cutoff, b: Cutoff) bool {
        return std.meta.eql(a, b);
    }

    pub fn format(self: Cutoff, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .round => |round| try round.format(writer),
            .epoch => |epoch| try epoch.format(writer),
        }
    }
};

/// Durable height and round bounds restored when marshal initializes.
///
/// The components are independent retention bounds and need not identify the same
/// finalization.
pub const Floor = struct {
    /// The latest durably processed position, if any.
    processed: ?Processed,
    /// The durable round floor. Every finalization at a covered round names a block at or below
    /// the processed height, or the stored block just above it.
    cutoff: Cutoff,

    pub fn init(processed: ?Processed, cutoff: Cutoff) Floor {
        return .{ .processed = processed, .cutoff = cutoff };
    }

    pub fn eql(a: Floor, b: Floor) bool {
        return std.meta.eql(a, b);
    }
};

/// The newest epoch whose last block is at or below `anchor`, or null when no epoch ends at or
/// below `anchor` or `epocher` cannot place `anchor`.
///
/// Verification requires every proposal, re-proposals included, to carry a block of its own
/// epoch, and the epocher places every height as the validators do. So every finalization an
/// honest quorum produces in the returned epoch or an earlier one names a block at or below
/// `anchor`.
pub fn closed_epoch(epocher: anytype, anchor: Height) ?Epoch {
    comptime types.assert_epocher(@TypeOf(epocher));
    const info = epocher.containing(anchor) orelse return null;
    if (info.last.get() == anchor.get()) return info.epoch;
    return info.epoch.previous();
}

/// The lowest round whose view-indexed cache data must stay to keep `retention` views behind
/// `witnessed`.
///
/// Views restart with each epoch, so the views the window lacks in `witnessed`'s epoch are
/// counted one per height below that epoch, and the epoch containing the lowest such height is
/// kept whole. Where `epocher` cannot place those heights, each earlier epoch counts for one
/// view.
///
/// Verification requires each block to be proposed in a round of its own epoch, at a later view
/// than its parent. Every epoch therefore spans at least as many views as it has heights above
/// genesis, so counting heights keeps at least the window.
pub fn retained_from(epocher: anytype, witnessed: Round, retention: ViewDelta) Round {
    comptime types.assert_epocher(@TypeOf(epocher));
    const view = witnessed.view.saturating_sub(retention);
    const owed = retention.get() -| witnessed.view.get();
    const epoch = epoch: {
        const first = epocher.first(witnessed.epoch) orelse break :epoch null;
        const info = epocher.containing(first.saturating_sub(.new(owed))) orelse
            break :epoch null;
        break :epoch info.epoch;
    } orelse witnessed.epoch.saturating_sub(.new(owed));
    return .new(epoch, view);
}

/// Whether floor admission issued at least one resolver fetch.
pub const FetchAdmission = enum { issued, denied };

/// Durable floor state, the configured floor until startup takes it, and any update awaiting
/// its anchor block.
///
/// The processed position and the round floor mirror the stream metadata. The arm that raises
/// one syncs the stream before the actor handles its next event, so the value here is durable
/// whenever another arm or a mailbox caller reads it.
///
/// `Aborter` cancels the buffer waiter of a pending floor: `abort(*Aborter) void` (commonware
/// `Aborter`, which aborts on drop).
pub fn State(comptime S: type, comptime C: type, comptime Aborter: type) type {
    comptime assert(@hasDecl(Aborter, "abort"));
    return struct {
        const Self = @This();
        pub const Finalization = simplex_types.Finalization(S, C);
        pub const Request = handler.Request(C);
        pub const Key = handler.Key(C);
        pub const Fetch = resolver_api.Fetch(Key, handler.Annotation);

        /// A floor finalization awaiting its anchor block. Dropping it aborts its buffer
        /// waiter, if one exists.
        const Pending = struct {
            finalization: Finalization,
            aborter: ?Aborter,
        };

        /// The durable processed position, if any.
        processed: ?Processed,
        /// The durable round floor. Start restores it from the stream metadata or derives a
        /// higher one from the archives and the epocher.
        cutoff: Cutoff,
        /// The newest finalization round witnessed for a processed block or an installed floor
        /// anchor. Cache retention follows this round because a round floor that covers a
        /// whole epoch has no view to measure retention from.
        witnessed: Round,
        /// The configured floor until startup takes it (owned).
        configured: ?Finalization,
        /// A floor finalization awaiting its anchor block (owned).
        pending: ?Pending,

        /// Floor state from the configured floor, if any (taking ownership), the restored floor,
        /// and the newest finalization round recovered from the archives.
        pub fn init(configured: ?Finalization, restored: Floor, witnessed: Round) Self {
            return .{
                .processed = restored.processed,
                .cutoff = restored.cutoff,
                .witnessed = witnessed,
                .configured = configured,
                .pending = null,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.configured) |*configured| configured.deinit(gpa);
            self.clear_pending(gpa);
            self.* = undefined;
        }

        /// Takes the configured floor, if any; the caller owns it.
        pub fn take_configured(self: *Self) ?Finalization {
            const configured = self.configured;
            self.configured = null;
            return configured;
        }

        /// The durable floor, without the configured or pending floor.
        pub fn snapshot(self: *const Self) Floor {
            return .init(self.processed, self.cutoff);
        }

        /// The inclusive height floor: finalized blocks at or below it are neither stored nor
        /// repaired. Nothing processed maps to zero, since genesis never carries a
        /// finalization; delivery uses the stream cursor, which keeps that state distinct.
        pub fn processed_height(self: *const Self) Height {
            const processed = self.processed orelse return .zero();
            return processed.height();
        }

        /// Sets the processed position. The caller buffers the same height in the stream
        /// metadata and syncs the stream before the actor handles its next event.
        pub fn set_processed(self: *Self, processed: Processed) void {
            self.processed = processed;
        }

        /// Sets the round floor, with the same durability contract as `set_processed`.
        pub fn set_cutoff(self: *Self, cutoff: Cutoff) void {
            self.cutoff = cutoff;
        }

        /// Records `round` as the newest witnessed finalization round and returns the previous
        /// one, or null when `round` is not newer.
        pub fn witness(self: *Self, round: Round) ?Round {
            if (round.order(self.witnessed) != .gt) return null;
            const previous = self.witnessed;
            self.witnessed = round;
            return previous;
        }

        /// Whether repair and application dispatch must wait for the floor anchor.
        pub fn blocks_progress(self: *const Self) bool {
            return self.pending != null;
        }

        /// The pending floor, if one awaits its anchor block.
        pub fn pending_finalization(self: *const Self) ?*const Finalization {
            if (self.pending) |*pending| return &pending.finalization;
            return null;
        }

        /// Drops the pending floor and aborts any buffer waiter it holds.
        pub fn clear_pending(self: *Self, gpa: Allocator) void {
            var pending = self.pending orelse return;
            self.pending = null;
            if (pending.aborter) |*aborter| aborter.abort();
            pending.finalization.deinit(gpa);
        }

        /// Records a verified floor finalization (taking ownership) whose block anchor still
        /// needs to arrive. Replacing the pending floor aborts the old buffer waiter.
        pub fn set_pending(
            self: *Self,
            gpa: Allocator,
            finalization: Finalization,
            aborter: ?Aborter,
        ) void {
            self.clear_pending(gpa);
            self.pending = .{ .finalization = finalization, .aborter = aborter };
        }

        /// Takes the pending floor if `commitment` is its payload; the caller owns it. Taking
        /// the pending floor aborts its buffer waiter.
        pub fn take_matching(self: *Self, commitment: C) ?Finalization {
            var pending = self.pending orelse return null;
            if (!pending.finalization.proposal.payload.eql(commitment)) return null;
            self.pending = null;
            if (pending.aborter) |*aborter| aborter.abort();
            return pending.finalization;
        }

        /// Whether the resolver request is above all processed floors.
        pub fn permits(self: *const Self, request: Request) bool {
            if (self.processed) |processed| {
                if (!request.above_height_floor(processed.height())) return false;
            }
            return request.above_round_floor(self.cutoff);
        }

        /// Fetches `request` through `backfill` (a `Resolver`, by pointer or value) unless a
        /// floor covers it.
        pub fn fetch_if_permitted(
            self: *const Self,
            backfill: anytype,
            request: Request,
        ) Allocator.Error!FetchAdmission {
            if (!self.permits(request)) return .denied;
            const key, const annotation = request.split();
            _ = try backfill.fetch(.{ .key = key, .subscriber = annotation });
            return .issued;
        }

        /// Fetches `request` from `targets` (non-empty) unless a floor covers it.
        pub fn fetch_targeted_if_permitted(
            self: *const Self,
            backfill: anytype,
            request: Request,
            targets: anytype,
        ) Allocator.Error!FetchAdmission {
            assert(targets.len > 0);
            if (!self.permits(request)) return .denied;
            const key, const annotation = request.split();
            _ = try backfill.fetch_targeted(.{ .key = key, .subscriber = annotation }, targets);
            return .issued;
        }

        /// Fetches finalizations for each of `heights` above the floors in one batch, or
        /// reports denied when the floors cover them all.
        pub fn fetch_finalizations_if_permitted(
            self: *const Self,
            gpa: Allocator,
            backfill: anytype,
            heights: []const Height,
        ) Allocator.Error!FetchAdmission {
            var fetches: std.ArrayList(Fetch) = try .initCapacity(gpa, heights.len);
            defer fetches.deinit(gpa);
            for (heights) |height| {
                const request: Request = .{ .finalized = height };
                if (!self.permits(request)) continue;
                const key, const annotation = request.split();
                fetches.appendAssumeCapacity(.{ .key = key, .subscriber = annotation });
            }
            if (fetches.items.len == 0) return .denied;
            _ = try backfill.fetch_all(fetches.items);
            return .issued;
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const utils = @import("utils");
const simplex_scheme = @import("../../simplex/root.zig").scheme;

const TestDigest = cryptography.Sha256.Digest;
const TestScheme = simplex_scheme.ed25519.Scheme(TestDigest);
/// Counts aborts.
const TestAborter = struct {
    aborts: *u32,

    pub fn abort(self: *TestAborter) void {
        self.aborts.* += 1;
    }
};
const TestState = State(TestScheme, TestDigest, TestAborter);
const TestFetch = TestState.Fetch;

/// Records what it is asked to fetch.
const TestResolver = struct {
    pub const Key = TestState.Key;
    pub const Subscriber = handler.Annotation;
    pub const PublicKey = cryptography.ed25519.PublicKey;

    gpa: Allocator,
    fetches: std.ArrayList(TestFetch) = .empty,
    targeted: std.ArrayList(Key) = .empty,

    fn deinit(self: *TestResolver) void {
        self.fetches.deinit(self.gpa);
        self.targeted.deinit(self.gpa);
    }

    pub fn fetch(self: *TestResolver, item: TestFetch) Allocator.Error!resolver_api.Feedback {
        return self.fetch_all(&.{item});
    }

    pub fn fetch_all(
        self: *TestResolver,
        items: []const TestFetch,
    ) Allocator.Error!resolver_api.Feedback {
        try self.fetches.appendSlice(self.gpa, items);
        return .ok;
    }

    pub fn retain(
        _: *TestResolver,
        _: resolver_api.Predicate(Key, Subscriber),
    ) Allocator.Error!resolver_api.Feedback {
        return .ok;
    }

    pub fn fetch_targeted(
        self: *TestResolver,
        item: TestFetch,
        targets: []const PublicKey,
    ) Allocator.Error!resolver_api.Feedback {
        assert(targets.len > 0);
        try self.targeted.append(self.gpa, item.key);
        return .ok;
    }

    pub fn fetch_all_targeted(
        self: *TestResolver,
        items: []const resolver_api.Targeted(Key, Subscriber, PublicKey),
    ) Allocator.Error!resolver_api.Feedback {
        for (items) |item| try self.targeted.append(self.gpa, item.fetch.key);
        return .ok;
    }

    comptime {
        resolver_api.assert_targeted_resolver(TestResolver);
    }
};

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn at(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

fn expect_fetch(fetch: TestFetch, expected: TestState.Request) !void {
    const key, const annotation = expected.split();
    try testing.expect(fetch.key.eql(key));
    try testing.expect(fetch.subscriber.eql(annotation));
}

test "cutoff orders by covered rounds" {
    const epoch: Epoch = .new(3);
    const last_view: Cutoff = .{ .round = .new(epoch, .new(std.math.maxInt(u64))) };
    const next_first: Cutoff = .{ .round = .new(epoch.next(), .zero()) };
    const whole: Cutoff = .{ .epoch = epoch };

    // An epoch cutoff sits above every round of its epoch and below the next epoch.
    try testing.expectEqual(.gt, whole.order(last_view));
    try testing.expectEqual(.lt, whole.order(next_first));
    try testing.expectEqual(.gt, whole.order(.{ .round = .zero() }));
    try testing.expectEqual(.gt, (Cutoff{ .epoch = .zero() }).order(.zero()));

    // Cutoffs of one kind follow their round or epoch order.
    try testing.expectEqual(.gt, last_view.order(.{ .round = .new(epoch, .new(7)) }));
    try testing.expectEqual(.lt, whole.order(.{ .epoch = epoch.next() }));
    try testing.expectEqual(.eq, whole.order(whole));
    try testing.expect(whole.max(last_view).eql(whole));
    try testing.expect(whole.max(next_first).eql(next_first));
}

test "cutoff covers matches its order" {
    const epoch: Epoch = .new(3);
    const max = std.math.maxInt(u64);
    const at_round: Cutoff = .{ .round = .new(epoch, .new(10)) };
    const whole: Cutoff = .{ .epoch = epoch };
    const rounds = [_]Round{
        .zero(),
        .new(epoch.previous().?, .new(max)),
        .new(epoch, .zero()),
        .new(epoch, .new(10)),
        .new(epoch, .new(11)),
        .new(epoch, .new(max)),
        .new(epoch.next(), .zero()),
    };

    // A round cutoff covers its round and every earlier round.
    try testing.expect(at_round.covers(.new(epoch, .new(10))));
    try testing.expect(!at_round.covers(.new(epoch, .new(11))));
    try testing.expect(at_round.covers(.new(.zero(), .new(max))));

    // An epoch cutoff covers every view of its epoch and nothing of the next epoch.
    try testing.expect(whole.covers(.new(epoch, .new(max))));
    try testing.expect(!whole.covers(.new(epoch.next(), .zero())));

    // The zero cutoff covers only the zero round.
    try testing.expect(Cutoff.zero().covers(.zero()));
    try testing.expect(!Cutoff.zero().covers(round_at(1)));

    // Coverage equals the order against a round cutoff.
    for ([_]Cutoff{ .zero(), at_round, whole }) |cutoff| {
        for (rounds) |round| {
            const ordered = cutoff.order(.{ .round = round }) != .lt;
            try testing.expectEqual(ordered, cutoff.covers(round));
        }
    }
}

test "processed reports its height and anchor" {
    const block: Processed = .{ .block = .new(7) };
    const absent: Processed = .{ .absent = .new(7) };
    try testing.expectEqual(7, block.height().get());
    try testing.expectEqual(7, block.anchor().get());
    try testing.expectEqual(7, absent.height().get());
    try testing.expectEqual(8, absent.anchor().get());
}

test "fetch if permitted denies covered epoch and admits the next" {
    const restored: Floor = .init(.{ .block = .new(10) }, .{ .epoch = .zero() });
    var state: TestState = .init(null, restored, round_at(10));
    defer state.deinit(testing.allocator);
    var resolver: TestResolver = .{ .gpa = testing.allocator };
    defer resolver.deinit();
    const commitment = TestDigest.fill(1);

    // Every round of the covered epoch is denied, including its last view.
    const denied = [_]TestState.Request{
        .{ .notarized = round_at(40) },
        .{ .notarized = round_at(std.math.maxInt(u64)) },
        .{ .finalized_by_round = .{ .commitment = commitment, .bound = round_at(40) } },
    };
    for (denied) |request| {
        try testing.expectEqual(.denied, try state.fetch_if_permitted(&resolver, request));
    }
    try testing.expectEqual(0, resolver.fetches.items.len);

    // The next epoch's first round and height-bound requests above the floor are admitted.
    const next: Round = .new(.new(1), .zero());
    try testing.expectEqual(.issued, try state.fetch_if_permitted(&resolver, .{
        .notarized = next,
    }));
    try testing.expectEqual(.issued, try state.fetch_if_permitted(&resolver, .{
        .finalized = .new(11),
    }));
    try testing.expectEqual(2, resolver.fetches.items.len);
}

test "closed epoch returns ended epochs only" {
    const epocher: types.FixedEpocher = .new(utils.NonZero(u64).init(11).?);

    // Epoch zero ends at height 10. An anchor inside it closes nothing.
    try testing.expectEqual(null, closed_epoch(epocher, .zero()));
    try testing.expectEqual(null, closed_epoch(epocher, .new(9)));
    try testing.expectEqual(0, closed_epoch(epocher, .new(10)).?.get());

    // An anchor inside epoch one closes epoch zero, and its last block closes epoch one.
    try testing.expectEqual(0, closed_epoch(epocher, .new(11)).?.get());
    try testing.expectEqual(0, closed_epoch(epocher, .new(20)).?.get());
    try testing.expectEqual(1, closed_epoch(epocher, .new(21)).?.get());

    // Heights the epocher cannot place close nothing.
    try testing.expectEqual(null, closed_epoch(epocher, .new(std.math.maxInt(u64))));
}

test "retained from counts views below an epoch in heights" {
    // Epochs hold three heights, and the window is ten views.
    const epocher: types.FixedEpocher = .new(utils.NonZero(u64).init(3).?);
    const window: ViewDelta = .new(10);
    const max = std.math.maxInt(u64);

    // The window fits in the witnessed epoch once that round is ten views in.
    try testing.expectEqual(at(3, 5), retained_from(epocher, at(3, 15), window));
    try testing.expectEqual(at(3, 0), retained_from(epocher, at(3, 10), window));

    // Epoch 8 holds three of the ten views. The seven heights below its first height reach
    // down to height 17, in epoch 5.
    try testing.expectEqual(at(5, 0), retained_from(epocher, at(8, 3), window));

    // The owed heights run out at genesis.
    try testing.expectEqual(at(0, 0), retained_from(epocher, at(2, 1), window));
    try testing.expectEqual(at(0, 0), retained_from(epocher, at(0, 0), window));

    // The epocher cannot place the heights of the last epoch, so each of the seven epochs
    // below it stands in for one view.
    try testing.expectEqual(at(max - 7, 0), retained_from(epocher, at(max, 3), window));
}

/// An epocher over listed epoch lengths.
const ListedEpocher = struct {
    bounds: [9]struct { u64, u64 },

    fn init(lengths: [9]u64) ListedEpocher {
        var self: ListedEpocher = undefined;
        var start: u64 = 0;
        for (lengths, &self.bounds) |length, *bounds| {
            bounds.* = .{ start, start + length - 1 };
            start += length;
        }
        return self;
    }

    pub fn containing(self: ListedEpocher, height: Height) ?types.EpochInfo {
        for (self.bounds, 0..) |bounds, epoch| {
            if (height.get() > bounds[1]) continue;
            return .new(.new(epoch), height, .new(bounds[0]), .new(bounds[1]));
        }
        return null;
    }

    pub fn first(self: ListedEpocher, epoch: Epoch) ?Height {
        if (epoch.get() >= self.bounds.len) return null;
        return .new(self.bounds[epoch.get()][0]);
    }

    pub fn last(self: ListedEpocher, epoch: Epoch) ?Height {
        if (epoch.get() >= self.bounds.len) return null;
        return .new(self.bounds[epoch.get()][1]);
    }

    fn heights(self: ListedEpocher, epoch: u64) u64 {
        return self.bounds[epoch][1] - self.bounds[epoch][0] + 1;
    }
};

fn expect_fewest_epochs(lengths: [9]u64) !void {
    const epocher: ListedEpocher = .init(lengths);
    const epochs: u64 = lengths.len;
    const largest = epocher.first(.new(epochs - 1)).?.get() + 1;
    for (1..largest + 1) |window| {
        for (0..epochs) |epoch| {
            for (0..largest + 1) |view| {
                const witnessed = at(epoch, view);
                const retained = retained_from(epocher, witnessed, .new(window));
                if (view >= window) {
                    try testing.expectEqual(at(epoch, view - window), retained);
                    continue;
                }
                try testing.expectEqual(0, retained.view.get());
                const missing = window - view;
                const lowest = retained.epoch.get();
                var covered: u64 = 0;
                for (lowest..epoch) |kept| covered += epocher.heights(kept);
                // The kept epochs span the window, and the lowest kept epoch is needed.
                try testing.expect(lowest == 0 or covered >= missing);
                try testing.expect(lowest == epoch or covered - epocher.heights(lowest) < missing);
            }
        }
    }
}

test "retained from keeps the fewest epochs that cover the window" {
    try expect_fewest_epochs(@splat(2));
    try expect_fewest_epochs(@splat(3));
    try expect_fewest_epochs(@splat(4));
    try expect_fewest_epochs(@splat(5));
    try expect_fewest_epochs(@splat(6));
    try expect_fewest_epochs(.{ 3, 1, 6, 1, 1, 4, 14, 2, 5 });
    try expect_fewest_epochs(.{ 2, 1, 1, 1, 1, 1, 1, 1, 1 });
}

fn test_floor() TestState {
    return .init(null, .init(.{ .block = .new(5) }, .{ .round = round_at(5) }), round_at(5));
}

test "fetch if permitted applies height and round floors" {
    var state = test_floor();
    defer state.deinit(testing.allocator);
    var resolver: TestResolver = .{ .gpa = testing.allocator };
    defer resolver.deinit();

    const denied = [_]TestState.Request{
        .{ .finalized = .new(5) },
        .{ .finalized_by_height = .{ .commitment = TestDigest.fill(1), .bound = .new(4) } },
        .{ .notarized = round_at(5) },
    };
    for (denied) |request| {
        try testing.expectEqual(.denied, try state.fetch_if_permitted(&resolver, request));
    }
    try testing.expectEqual(0, resolver.fetches.items.len);

    const issued = [_]TestState.Request{ .{ .finalized = .new(6) }, .{ .notarized = round_at(6) } };
    for (issued) |request| {
        try testing.expectEqual(.issued, try state.fetch_if_permitted(&resolver, request));
    }
    try testing.expectEqual(2, resolver.fetches.items.len);
    for (issued, resolver.fetches.items) |request, fetch| try expect_fetch(fetch, request);
}

// commonware `fetch_if_permitted_applies_both_floors_to_untrusted_requests` (#5717).
test "fetch if permitted applies both floors to untrusted requests" {
    var state = test_floor();
    defer state.deinit(testing.allocator);
    var resolver: TestResolver = .{ .gpa = testing.allocator };
    defer resolver.deinit();
    const untrusted = struct {
        fn of(height: u64, round: ?Round) TestState.Request {
            return .{ .untrusted = .{
                .commitment = TestDigest.fill(1),
                .bound = .{ .height = .new(height), .round = round },
            } };
        }
    }.of;
    // Either floor denies the request, whatever the other bound says.
    const denied = [_]TestState.Request{
        untrusted(6, round_at(5)),
        untrusted(5, round_at(6)),
        untrusted(5, null),
    };
    for (denied) |request| {
        try testing.expectEqual(.denied, try state.fetch_if_permitted(&resolver, request));
    }
    try testing.expectEqual(0, resolver.fetches.items.len);
    // Above the height floor, a round above the round floor or no round is issued.
    const issued = [_]TestState.Request{ untrusted(6, round_at(6)), untrusted(6, null) };
    for (issued) |request| {
        try testing.expectEqual(.issued, try state.fetch_if_permitted(&resolver, request));
    }
    try testing.expectEqual(2, resolver.fetches.items.len);
    for (issued, resolver.fetches.items) |request, fetch| try expect_fetch(fetch, request);
}

test "fetch targeted if permitted returns denied without fetching" {
    var state = test_floor();
    defer state.deinit(testing.allocator);
    var resolver: TestResolver = .{ .gpa = testing.allocator };
    defer resolver.deinit();
    const target = cryptography.ed25519.PrivateKey.from_seed(0).public_key();

    try testing.expectEqual(.denied, try state.fetch_targeted_if_permitted(&resolver, .{
        .finalized = .new(5),
    }, &[_]TestResolver.PublicKey{target}));
    try testing.expectEqual(0, resolver.targeted.items.len);

    try testing.expectEqual(.issued, try state.fetch_targeted_if_permitted(&resolver, .{
        .finalized = .new(6),
    }, &[_]TestResolver.PublicKey{target}));
    try testing.expectEqual(1, resolver.targeted.items.len);
    try testing.expect(resolver.targeted.items[0].eql(.{ .finalized = .new(6) }));
}

test "fetch finalizations if permitted filters denied requests" {
    const gpa = testing.allocator;
    var state = test_floor();
    defer state.deinit(gpa);
    var resolver: TestResolver = .{ .gpa = gpa };
    defer resolver.deinit();

    const heights = [_]Height{ .new(5), .new(6), .new(4), .new(7) };
    try testing.expectEqual(.issued, try state.fetch_finalizations_if_permitted(
        gpa,
        &resolver,
        &heights,
    ));
    try testing.expectEqual(2, resolver.fetches.items.len);
    try testing.expect(resolver.fetches.items[0].key.eql(.{ .finalized = .new(6) }));
    try testing.expect(resolver.fetches.items[1].key.eql(.{ .finalized = .new(7) }));

    var denied: TestResolver = .{ .gpa = gpa };
    defer denied.deinit();
    const covered = [_]Height{ .new(5), .new(4) };
    try testing.expectEqual(.denied, try state.fetch_finalizations_if_permitted(
        gpa,
        &denied,
        &covered,
    ));
    try testing.expectEqual(0, denied.fetches.items.len);
}

test "fetch if permitted without height floor allows genesis height" {
    var state: TestState = .init(null, .init(null, .{ .round = round_at(5) }), round_at(5));
    defer state.deinit(testing.allocator);
    var resolver: TestResolver = .{ .gpa = testing.allocator };
    defer resolver.deinit();

    try testing.expectEqual(.issued, try state.fetch_if_permitted(&resolver, .{
        .finalized = .zero(),
    }));
    try testing.expectEqual(1, resolver.fetches.items.len);
    try expect_fetch(resolver.fetches.items[0], .{ .finalized = .zero() });
}

test "witness records only newer rounds" {
    var state = test_floor();
    defer state.deinit(testing.allocator);
    try testing.expectEqual(null, state.witness(round_at(5)));
    try testing.expectEqual(null, state.witness(round_at(4)));
    try testing.expectEqual(round_at(5), state.witness(round_at(6)).?);
    try testing.expectEqual(round_at(6), state.witnessed);
    try testing.expectEqual(5, state.processed_height().get());
    try testing.expect(!state.blocks_progress());
    try testing.expect(state.snapshot().eql(.init(.{ .block = .new(5) }, .{
        .round = round_at(5),
    })));
}

/// A scheme whose certificates are plain integers, enough to hold pending floors.
const PlainScheme = struct {
    pub const Certificate = u64;
};
const PendingState = State(PlainScheme, TestDigest, TestAborter);

fn plain_finalization(view: u64, payload: TestDigest) PendingState.Finalization {
    return .{ .proposal = .init(round_at(view), .new(view - 1), payload), .certificate = view };
}

test "pending floor aborts its waiter when replaced, taken, or cleared" {
    const gpa = testing.allocator;
    const restored: Floor = .init(.{ .block = .new(5) }, .{ .round = round_at(5) });
    var state: PendingState = .init(null, restored, round_at(5));
    defer state.deinit(gpa);
    var aborts: u32 = 0;
    const first = TestDigest.fill(1);
    const second = TestDigest.fill(2);

    state.set_pending(gpa, plain_finalization(6, first), .{ .aborts = &aborts });
    try testing.expect(state.blocks_progress());
    try testing.expect(state.pending_finalization().?.proposal.payload.eql(first));
    try testing.expectEqual(null, state.take_matching(second));
    try testing.expectEqual(0, aborts);

    // Replacing the pending floor aborts the old waiter.
    state.set_pending(gpa, plain_finalization(7, second), .{ .aborts = &aborts });
    try testing.expectEqual(1, aborts);
    var taken = state.take_matching(second).?;
    defer taken.deinit(gpa);
    try testing.expectEqual(2, aborts);
    try testing.expect(!state.blocks_progress());

    // A pending floor without a waiter clears without aborting.
    state.set_pending(gpa, plain_finalization(8, first), null);
    state.clear_pending(gpa);
    try testing.expectEqual(2, aborts);
    try testing.expectEqual(null, state.pending_finalization());
}
