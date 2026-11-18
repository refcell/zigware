//! The inclusion window of the reshare actor (commonware `reshare/actor/inclusion.rs`).
//!
//! From the epoch midpoint through its final block, each dealer posts its signed log, the
//! actor records finalized logs, and final-block requests are answered with the `EpochInfo`
//! derived from the logs: finalized ones first, then the pending ones a request's ancestry
//! carries. Ported so far: the pending-log scan, the request queue, verification retention,
//! and the future-participant check.
//!
//! Rust's shutdown signal ends a scan with `None`; here the scan runs on the caller's task and
//! a canceled task ends it with `error.Canceled`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const setup = @import("setup.zig");

const Epoch = consensus.Epoch;
const FixedEpocher = consensus.types.FixedEpocher;
const Height = consensus.Height;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const oneshot = utils.channel.oneshot;
const log = std.log.scoped(.dkg_reshare);

/// Dealer logs indexed by dealer for an epoch-info request or verification, sorted by key.
pub fn PendingLogs(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { key: P, log: fd.DealerLog(V, P) };

        entries: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.entries.items) |*entry| entry.log.deinit(gpa);
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        /// A copy of `entries` (sorted by key, as the store keeps them).
        pub fn from_sorted(gpa: Allocator, entries: anytype) Allocator.Error!Self {
            var result: Self = .empty;
            errdefer result.deinit(gpa);
            try result.entries.ensureTotalCapacity(gpa, entries.len);
            for (entries) |entry| {
                const copy = try entry.log.clone(gpa);
                result.entries.appendAssumeCapacity(.{ .key = entry.key, .log = copy });
            }
            result.assert_sorted();
            return result;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return from_sorted(gpa, self.entries.items);
        }

        pub fn len(self: Self) usize {
            return self.entries.items.len;
        }

        /// Records `value` (taken) for `key` unless one is recorded; false (and `value`
        /// freed) when it is.
        pub fn put_first(self: *Self, gpa: Allocator, key: P, value: fd.DealerLog(V, P)) !bool {
            var owned = value;
            const index = std.sort.lowerBound(Entry, self.entries.items, key, order);
            const items = self.entries.items;
            if (index < items.len and codec.order(P, items[index].key, key) == .eq) {
                owned.deinit(gpa);
                return false;
            }
            errdefer owned.deinit(gpa);
            try self.entries.insert(gpa, index, .{ .key = key, .log = owned });
            self.assert_sorted();
            return true;
        }

        pub fn eql(a: Self, b: Self) bool {
            if (a.entries.items.len != b.entries.items.len) return false;
            for (a.entries.items, b.entries.items) |left, right| {
                if (codec.order(P, left.key, right.key) != .eq) return false;
                if (!left.log.eql(right.log)) return false;
            }
            return true;
        }

        fn order(key: P, entry: Entry) std.math.Order {
            return codec.order(P, key, entry.key);
        }

        fn assert_sorted(self: Self) void {
            const items = self.entries.items;
            for (1..@max(items.len, 1)) |i| {
                assert(codec.order(P, items[i - 1].key, items[i].key) == .lt);
            }
        }
    };
}

/// What a pending-log scan needs to know about the epoch.
pub fn PendingLogScan(comptime V: type, comptime P: type, comptime D: type) type {
    return struct {
        epoch: Epoch,
        info: *const fd.Info(V, P),
        epocher: FixedEpocher,
        finalized_tip: ?setup.FinalizedTip(D),
        final_height: Height,
    };
}

/// The valid dealer logs in `ancestry` above the finalized tip, keeping each dealer's
/// earliest. Null if `ancestry` ends early or does not extend the finalized tip; a canceled
/// task returns `error.Canceled`. Reads `ancestry` (borrowed) only as far as it must.
pub fn pending_logs(
    comptime B: type,
    gpa: Allocator,
    scan: PendingLogScan(B.Variant, B.PublicKey, B.Digest),
    ancestry: anytype,
) !?PendingLogs(B.Variant, B.PublicKey) {
    const midpoint = scan.epocher.midpoint(scan.epoch) orelse @panic("epoch midpoint unknown");
    // Scan only unfinalized blocks from the midpoint on, and require them to extend the tip.
    const tip = scan.finalized_tip;
    const first_pending = if (tip != null and tip.?.height.get() >= midpoint.get())
        tip.?.height.next()
    else
        midpoint;
    const anchored = tip != null and tip.?.height.next().get() == first_pending.get();
    const anchor: ?B.Digest = if (anchored) tip.?.digest else null;
    const Logs = PendingLogs(B.Variant, B.PublicKey);
    const cursor = scan.final_height.previous() orelse return Logs.empty;

    // Verification ancestry starts at the final block and proposal ancestry at its parent.
    var first = try ancestry.next() orelse {
        truncated(scan.epoch, cursor);
        return null;
    };
    if (first.inner().height().get() == scan.final_height.get()) {
        first.deinit();
        first = try ancestry.next() orelse {
            truncated(scan.epoch, cursor);
            return null;
        };
    }
    assert(first.inner().height().get() < scan.final_height.get());
    var blocks: std.ArrayList(@TypeOf(first)) = .empty;
    defer {
        for (blocks.items) |*block| block.deinit();
        blocks.deinit(gpa);
    }
    var attachment = first.digest();
    if (first_pending.get() <= cursor.get()) {
        blocks.append(gpa, first) catch |err| {
            first.deinit();
            return err;
        };
        attachment = try collect(gpa, ancestry, &blocks, first_pending, cursor) orelse
            return null;
    } else first.deinit();

    // Ancestry guarantees parent links between the blocks it yields, but not that they
    // extend the finalized chain.
    if (anchor) |digest| if (!digest.eql(attachment)) {
        log.warn("epoch info ancestry is detached from finalized prefix", .{});
        return null;
    };
    return try authenticate(B, gpa, scan, blocks.items);
}

/// Reads blocks below `cursor` down to `first_pending` into `blocks`, returning the parent
/// digest of the lowest one (null if the ancestry ends first).
fn collect(
    gpa: Allocator,
    ancestry: anytype,
    blocks: anytype,
    first_pending: Height,
    cursor_start: Height,
) !?@TypeOf(blocks.items[0].digest()) {
    assert(blocks.items.len == 1);
    var cursor = cursor_start;
    var attachment = blocks.items[0].inner().parent();
    // Each pass lowers `cursor` by one: at most `cursor_start - first_pending` passes.
    while (cursor.get() > first_pending.get()) {
        cursor = cursor.previous() orelse @panic("pending ancestry must remain above genesis");
        var block = try ancestry.next() orelse {
            truncated(Epoch.zero(), cursor);
            return null;
        };
        attachment = block.inner().parent();
        blocks.append(gpa, block) catch |err| {
            block.deinit();
            return err;
        };
    }
    assert(blocks.items.len == 1 + cursor_start.get() - cursor.get());
    return attachment;
}

/// Logs a scan whose ancestry ended early.
fn truncated(epoch: Epoch, cursor: Height) void {
    log.warn("epoch {d} ancestry ended before covering pending dealer logs at {d}", .{
        epoch.get(),
        cursor.get(),
    });
}

/// Authenticates the logs `blocks` (newest first) carry, in chain order, so each dealer's
/// earliest valid log wins, matching the journal's first-log rule.
fn authenticate(
    comptime B: type,
    gpa: Allocator,
    scan: PendingLogScan(B.Variant, B.PublicKey, B.Digest),
    blocks: anytype,
) !PendingLogs(B.Variant, B.PublicKey) {
    var logs: PendingLogs(B.Variant, B.PublicKey) = .empty;
    errdefer logs.deinit(gpa);
    var index = blocks.len;
    while (index > 0) {
        index -= 1;
        var payload = try blocks[index].inner().payload(gpa) orelse continue;
        if (payload != .dealer_log) {
            payload.deinit(gpa);
            continue;
        }
        var signed = payload.dealer_log;
        if (!try fd.check_log(B.Variant, B.PublicKey, gpa, scan.info, &signed)) {
            log.warn("ignoring invalid pending dealer log", .{});
            signed.deinit(gpa);
            continue;
        }
        _ = try logs.put_first(gpa, signed.dealer, signed.log);
    }
    assert(logs.len() <= blocks.len);
    return logs;
}

/// Fails when a provider-supplied future participant set is empty or exceeds
/// `max_participants` (commonware panics).
pub fn validate_future_participants(
    participants: anytype,
    max_participants: u32,
) error{ EmptyFutureParticipants, OversizedFutureParticipants }!void {
    assert(max_participants > 0);
    if (participants.len() == 0) return error.EmptyFutureParticipants;
    if (participants.len() > max_participants) return error.OversizedFutureParticipants;
}

/// Queued epoch-info requests in arrival order. Ancestries stay unread until a request is
/// selected, so waiting requests do not each hold a dealer-log map.
pub fn ArtifactRequests(comptime A: type, comptime R: type) type {
    return struct {
        const Self = @This();
        pub const Request = struct { ancestry: A, response: oneshot.Sender(R) };

        inner: std.Deque(Request) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            while (self.inner.popFront()) |request| discard(request);
            self.inner.deinit(gpa);
            self.* = undefined;
        }

        /// Retains a request (taken) without reading its ancestry. False, with the request
        /// dropped, when its requester already canceled it.
        pub fn push(self: *Self, gpa: Allocator, request: Request) !bool {
            if (request.response.is_closed()) {
                discard(request);
                return false;
            }
            errdefer discard(request);
            try self.inner.pushBack(gpa, request);
            assert(self.inner.len > 0);
            return true;
        }

        /// Restores the oldest request after finalization invalidates its scan.
        pub fn push_front(self: *Self, gpa: Allocator, request: Request) !void {
            errdefer discard(request);
            try self.inner.pushFront(gpa, request);
            assert(self.inner.len > 0);
        }

        /// The oldest request whose requester still waits; canceled ones are dropped.
        pub fn pop(self: *Self) ?Request {
            while (self.inner.popFront()) |request| {
                if (!request.response.is_closed()) return request;
                discard(request);
            }
            assert(self.inner.len == 0);
            return null;
        }

        pub fn discard(request: Request) void {
            var dropped = request;
            dropped.response.deinit();
            dropped.ancestry.deinit();
        }
    };
}

/// The output of successful dealer-log verification: `share` is present when this node
/// participated as a player.
pub fn Ceremony(comptime V: type, comptime P: type) type {
    return struct {
        output: fd.Output(V, P),
        share: ?Share,

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            self.output.deinit(gpa);
            if (self.share) |*share| share.private.zeroize();
            self.* = undefined;
        }
    };
}

/// A verification result and the dealer logs it was computed from (`ceremony` is null if
/// they yield no output).
pub fn VerifiedLogs(comptime V: type, comptime P: type) type {
    return struct {
        logs: PendingLogs(V, P),
        ceremony: ?Ceremony(V, P),

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            self.logs.deinit(gpa);
            if (self.ceremony) |*ceremony| ceremony.deinit(gpa);
            self.* = undefined;
        }
    };
}

/// The last retained verification result (never persisted).
pub fn Verification(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        const Logs = PendingLogs(V, P);

        result: ?VerifiedLogs(V, P) = null,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.result) |*result| result.deinit(gpa);
            self.* = undefined;
        }

        /// Retains `result` (taken) unless that would replace a result for the `canonical`
        /// (finalized) logs with one for other logs.
        pub fn retain(
            self: *Self,
            gpa: Allocator,
            result: VerifiedLogs(V, P),
            canonical: Logs,
        ) void {
            var incoming = result;
            const retained_is_canonical = if (self.result) |*retained|
                retained.logs.eql(canonical)
            else
                false;
            if (incoming.logs.eql(canonical) or !retained_is_canonical) {
                if (self.result) |*retained| retained.deinit(gpa);
                self.result = incoming;
                assert(self.result != null);
            } else incoming.deinit(gpa);
        }

        /// Null if no result for exactly `logs` is retained; otherwise the retained outcome,
        /// whose `ceremony` is null when those logs yield no output.
        pub fn ready(self: *const Self, logs: Logs) ?*const ?Ceremony(V, P) {
            const retained = if (self.result) |*result| result else return null;
            if (!retained.logs.eql(logs)) return null;
            return &retained.ceremony;
        }
    };
}

test {
    _ = @import("inclusion_test.zig");
}
