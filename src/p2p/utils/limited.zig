//! Rate-limited `UnlimitedSender` wrapper (commonware `p2p/src/utils/limited.rs`).
//!
//! `LimitedSender(S, C)` wraps an unlimited sender `S` with a per-peer `KeyedRateLimiter`
//! shared by every clone. `check` filters recipients down to those within their quota and
//! returns a `CheckedSender` for them, or the earliest time all of them are available.
//! `Recipients.all` expands to the latest peer list from the `Connected` source `C`.
//!
//! A `Connected` source has `C.PublicKey`, `C.Subscription`, `peers(gpa) ![]PublicKey` (the
//! current snapshot, owned by the caller), and `subscribe() Subscription`, whose
//! `try_recv(gpa) !?[]PublicKey` returns a newer peer list when there is one
//! (commonware's `ring::Receiver<Vec<P>>`; see `watch.zig`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils_pkg = @import("utils");

const p2p = @import("../root.zig");
const rate_limit = @import("../rate_limit.zig");
const Quota = rate_limit.Quota;
const SystemTime = utils_pkg.SystemTime;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// Asserts `C` implements `Connected`.
pub fn assert_connected(comptime C: type) void {
    comptime {
        for (.{ "PublicKey", "Subscription", "peers", "subscribe" }) |decl| {
            if (!@hasDecl(C, decl)) @compileError(@typeName(C) ++ " lacks Connected." ++ decl);
        }
        assert(@hasDecl(C.Subscription, "try_recv"));
    }
}

/// An exclusive reference to an unlimited sender with pre-checked recipients that are within
/// their rate limit. `send` consumes it; an unsent one is released with `deinit`.
pub fn CheckedSender(comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        sender: *S,
        gpa: Allocator,
        /// Never `all`; a `some` slice is owned by this checked sender.
        checked: p2p.Recipients(P),

        /// The recipients retained by the check.
        pub fn recipients(self: *const Self) []const P {
            assert(self.checked != .all);
            return self.checked.peers();
        }

        /// Sends `parts` (concatenated) to the checked recipients.
        pub fn send(self: Self, parts: []const []const u8, priority: bool) Unreliable(Feedback) {
            defer self.deinit();
            return self.sender.send(self.checked, parts, priority);
        }

        /// The inner sender. Messages sent through it bypass the rate limiter.
        pub fn into_inner(self: Self) *S {
            self.deinit();
            return self.sender;
        }

        pub fn deinit(self: Self) void {
            self.checked.deinit(self.gpa);
        }
    };
}

pub fn LimitedSender(comptime S: type, comptime C: type) type {
    p2p.assert_unlimited_sender(S);
    assert_connected(C);
    comptime assert(C.PublicKey == S.PublicKey);
    const P = S.PublicKey;
    const Limiter = rate_limit.KeyedRateLimiter(P);
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Checked = CheckedSender(S);

        sender: S,
        peers: C,
        state: *State,

        const State = struct {
            gpa: Allocator,
            io: Io,
            mutex: Io.Mutex = .init,
            handles: u32,
            limiter: Limiter,
            subscription: C.Subscription,
            known_peers: []P,
        };

        pub fn init(gpa: Allocator, io: Io, sender: S, quota: Quota, peers: C) !Self {
            const state = try gpa.create(State);
            errdefer gpa.destroy(state);
            const known_peers = try peers.peers(gpa);
            state.* = .{
                .gpa = gpa,
                .io = io,
                .handles = 1,
                .limiter = .init(gpa, io, quota),
                .subscription = peers.subscribe(),
                .known_peers = known_peers,
            };
            return .{ .sender = sender, .peers = peers, .state = state };
        }

        /// A handle sharing this sender's rate limiter and peer snapshot.
        pub fn clone(self: *const Self) Self {
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            assert(state.handles > 0);
            state.handles += 1;
            const sender = if (@hasDecl(S, "clone")) self.sender.clone() else self.sender;
            return .{ .sender = sender, .peers = self.peers, .state = state };
        }

        pub fn deinit(self: *Self) void {
            if (@hasDecl(S, "deinit")) self.sender.deinit();
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            assert(state.handles > 0);
            state.handles -= 1;
            const last = state.handles == 0;
            state.mutex.unlock(state.io);
            if (last) {
                state.limiter.deinit();
                state.gpa.free(state.known_peers);
                state.gpa.destroy(state);
            }
            self.* = undefined;
        }

        /// Checks which recipients are within their rate limit. Returns a checked sender for
        /// them, or, when every recipient is limited, the earliest time all are available.
        pub fn check(self: *Self, recipients: p2p.Recipients(P)) !p2p.Check(Checked) {
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (recipients == .all) {
                if (try state.subscription.try_recv(state.gpa)) |peers| {
                    state.gpa.free(state.known_peers);
                    state.known_peers = peers;
                    state.limiter.retain_recent();
                }
            }
            const candidates: []const P = switch (recipients) {
                .one => |peer| {
                    if (try state.limiter.check_key(peer)) |retry| return .{ .limited = retry };
                    return .{ .checked = self.checked_for(.{ .one = peer }) };
                },
                .some => |peers| peers,
                .all => state.known_peers,
            };
            const allowed, const retry =
                try filter_rate_limited(state.gpa, candidates, &state.limiter);
            if (allowed.len == 0) {
                if (retry) |time| {
                    state.gpa.free(allowed);
                    return .{ .limited = time };
                }
            }
            return .{ .checked = self.checked_for(.{ .some = allowed }) };
        }

        /// Sends to the recipients within their rate limit (commonware's blanket
        /// `Sender::send`). Returns the recipients it attempted, owned by the caller: empty when
        /// every recipient is limited, the sender is closed, or the send is not accepted.
        pub fn send(
            self: *Self,
            recipients: p2p.Recipients(P),
            parts: []const []const u8,
            priority: bool,
        ) ![]P {
            const gpa = self.state.gpa;
            const checked = switch (try self.check(recipients)) {
                .limited => return gpa.alloc(P, 0),
                .checked => |checked| checked,
            };
            const attempted = gpa.dupe(P, checked.recipients()) catch |err| {
                checked.deinit();
                return err;
            };
            if (checked.send(parts, priority).accepted()) return attempted;
            gpa.free(attempted);
            return gpa.alloc(P, 0);
        }

        fn checked_for(self: *Self, recipients: p2p.Recipients(P)) Checked {
            assert(recipients != .all);
            return .{ .sender = &self.sender, .gpa = self.state.gpa, .checked = recipients };
        }
    };
}

/// Filters `peers` by rate limit: the peers within their quota (owned by the caller), and the
/// latest retry time among those that are not.
pub fn filter_rate_limited(
    gpa: Allocator,
    peers: anytype,
    limiter: anytype,
) !struct { []@TypeOf(peers[0]), ?SystemTime } {
    const P = @TypeOf(peers[0]);
    var allowed: std.ArrayList(P) = try .initCapacity(gpa, peers.len);
    errdefer allowed.deinit(gpa);
    var max_retry: ?SystemTime = null;
    for (peers) |peer| {
        if (try limiter.check_key(peer)) |earliest| {
            const later = max_retry == null or earliest.order(max_retry.?) == .gt;
            if (later) max_retry = earliest;
        } else {
            allowed.appendAssumeCapacity(peer);
        }
    }
    assert(allowed.items.len <= peers.len);
    return .{ try allowed.toOwnedSlice(gpa), max_retry };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const Watch = @import("watch.zig").Watch;
const Key = cryptography.ed25519.PublicKey;

fn key(seed: u64) Key {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

const Sent = struct { recipients: []Key, message: []u8, priority: bool };

const MockSender = struct {
    pub const PublicKey = Key;
    sent: *std.ArrayList(Sent),

    pub fn send(
        sender: MockSender,
        recipients: p2p.Recipients(Key),
        parts: []const []const u8,
        priority: bool,
    ) Unreliable(Feedback) {
        const gpa = testing.allocator;
        const peers = gpa.dupe(Key, recipients.peers()) catch return .rejected;
        const message = std.mem.concat(gpa, u8, parts) catch return .rejected;
        const sent: Sent = .{ .recipients = peers, .message = message, .priority = priority };
        sender.sent.append(gpa, sent) catch return .rejected;
        return .new(.ok);
    }
};

const MockPeers = struct {
    pub const PublicKey = Key;
    pub const Subscription = Watch(Key).Subscription;
    list: []const Key,
    watch: *Watch(Key),

    pub fn peers(self: MockPeers, gpa: Allocator) ![]Key {
        return gpa.dupe(Key, self.list);
    }

    pub fn subscribe(self: MockPeers) Subscription {
        return self.watch.subscribe(false);
    }
};

const Fixture = struct {
    runner: runtime.deterministic.Runner,
    sent: std.ArrayList(Sent) = .empty,
    watch: Watch(Key),

    fn init(fixture: *Fixture) !void {
        fixture.runner = try .init(testing.allocator, .{});
        fixture.sent = .empty;
        fixture.watch = .init(testing.allocator, fixture.runner.io());
    }

    fn deinit(fixture: *Fixture) void {
        for (fixture.sent.items) |sent| {
            testing.allocator.free(sent.recipients);
            testing.allocator.free(sent.message);
        }
        fixture.sent.deinit(testing.allocator);
        fixture.watch.deinit();
        fixture.runner.deinit();
    }

    fn limited(fixture: *Fixture, per_second: u32, list: []const Key) !Limited {
        const sender: MockSender = .{ .sent = &fixture.sent };
        const peers: MockPeers = .{ .list = list, .watch = &fixture.watch };
        const quota = Quota.per_second(per_second);
        return Limited.init(testing.allocator, fixture.runner.io(), sender, quota, peers);
    }

    fn expect_sent_to(fixture: *Fixture, index: usize, expected: []const Key) !void {
        const sent = fixture.sent.items[index].recipients;
        try testing.expectEqual(expected.len, sent.len);
        for (expected, sent) |a, b| try testing.expect(a.eql(b));
    }
};

const Limited = LimitedSender(MockSender, MockPeers);

fn send_one(limited: *Limited, peer: Key, message: []const u8) !void {
    const result = try limited.check(.{ .one = peer });
    try testing.expect(result.checked.send(&.{message}, false).accepted());
}

test "check one not rate limited" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited = try f.limited(10, &.{});
    defer limited.deinit();
    const result = try limited.check(.{ .one = key(1) });
    try testing.expect(result.checked.send(&.{"hello"}, false).eql(.new(.ok)));
}

test "check one rate limited" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited = try f.limited(1, &.{});
    defer limited.deinit();
    try send_one(&limited, key(1), "first");
    try testing.expect(try limited.check(.{ .one = key(1) }) == .limited);
}

test "check some: none limited, filtered, all limited, empty" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited = try f.limited(1, &.{});
    defer limited.deinit();
    const all_three = [_]Key{ key(1), key(2), key(3) };
    const first = try limited.check(.{ .some = &all_three });
    try testing.expect(first.checked.send(&.{"hello"}, false).eql(.new(.ok)));
    try f.expect_sent_to(0, &all_three);

    // Every peer is now limited.
    try testing.expect(try limited.check(.{ .some = &all_three }) == .limited);
    // Empty recipients pass through.
    const empty = try limited.check(.{ .some = &.{} });
    try testing.expectEqual(@as(usize, 0), empty.checked.recipients().len);
    empty.checked.deinit();

    // A fresh peer passes alongside limited ones.
    const mixed = [_]Key{ key(1), key(4), key(2), key(5) };
    const result = try limited.check(.{ .some = &mixed });
    _ = result.checked.send(&.{"filtered"}, false);
    try f.expect_sent_to(1, &.{ key(4), key(5) });
}

test "check all uses known peers and filters limited ones" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var empty_peers = try f.limited(10, &.{});
    defer empty_peers.deinit();
    const none = try empty_peers.check(.all);
    try testing.expectEqual(@as(usize, 0), none.checked.recipients().len);
    _ = none.checked.send(&.{"empty"}, false);
    try f.expect_sent_to(0, &.{});

    const known = [_]Key{ key(1), key(2) };
    var limited = try f.limited(1, &known);
    defer limited.deinit();
    try send_one(&limited, key(1), "limit");
    const result = try limited.check(.all);
    _ = result.checked.send(&.{"filtered"}, false);
    try f.expect_sent_to(2, &.{key(2)});
    try testing.expect(try limited.check(.all) == .limited);
}

test "clones share peer updates (clone_shares_peer_updates)" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited1 = try f.limited(10, &.{key(1)});
    defer limited1.deinit();
    var limited2 = limited1.clone();
    defer limited2.deinit();
    try testing.expect(try f.watch.publish(&.{key(2)}));

    const second = try limited2.check(.all);
    try testing.expectEqual(@as(usize, 1), second.checked.recipients().len);
    try testing.expect(second.checked.recipients()[0].eql(key(2)));
    second.checked.deinit();
    const first = try limited1.check(.all);
    try testing.expect(first.checked.recipients()[0].eql(key(2)));
    first.checked.deinit();
}

test "rate limit shared across clones" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited1 = try f.limited(1, &.{});
    defer limited1.deinit();
    var limited2 = limited1.clone();
    defer limited2.deinit();
    try send_one(&limited1, key(1), "limit");
    try testing.expect(try limited2.check(.{ .one = key(1) }) == .limited);
}

test "checked sender sends with priority" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited = try f.limited(10, &.{});
    defer limited.deinit();
    const result = try limited.check(.{ .one = key(1) });
    _ = result.checked.send(&.{ "prio", "rity" }, true);
    try testing.expectEqual(@as(usize, 1), f.sent.items.len);
    try testing.expect(f.sent.items[0].priority);
    try testing.expectEqualStrings("priority", f.sent.items[0].message);
}

test "retry time is the latest earliest-possible time" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var limited = try f.limited(1, &.{});
    defer limited.deinit();
    try send_one(&limited, key(1), "a");
    try send_one(&limited, key(2), "b");
    const result = try limited.check(.{ .some = &.{ key(1), key(2) } });
    const expected = SystemTime{ .nanos_since_epoch = std.time.ns_per_s };
    try testing.expect(result.limited.order(expected) == .eq);
}
