//! p2p: Communicate with authenticated peers.
//!
//! Zig port of commonware's `commonware-p2p` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/p2p). docs/lanes/p2p.md tracks what
//! is ported.
//!
//! The lib.rs traits are comptime interfaces, checked with the `assert_*` functions below:
//!
//! - `UnlimitedSender`: `S.PublicKey`, `s.send(recipients, message, priority)
//!   Unreliable(Feedback)`.
//! - `LimitedSender`: `S.PublicKey`, `s.check(recipients) Check(S.Checked)`, where the checked
//!   sender (`CheckedSender`) has `recipients()` and `send(message, priority)`. commonware's
//!   blanket `Sender` is `send` in this file.
//! - `Receiver`: `R.PublicKey`, `r.recv() !Message(PublicKey)`, `r.capacity() usize`.
//! - `Provider`/`Manager`: `peer_set(id)`, `subscribe()`, `track(id, TrackedPeers) Feedback`.
//! - `Blocker`: `B.PublicKey`, `b.block(peer) Feedback`, `b.blocked()`.
//!
//! Public keys are any type with `order(a, b) std.math.Order` that encodes through codec
//! (`cryptography.signer.assert_public_key`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils_pkg = @import("utils");
const actor = @import("actor");

pub const types = @import("types.zig");
pub const Address = types.Address;
pub const Ingress = types.Ingress;
pub const sizing = @import("sizing.zig");
pub const max_message_size = sizing.max_message_size;
pub const fuzz = @import("fuzz.zig");
pub const utils = @import("utils/mod.zig");
pub const simulated = @import("simulated/mod.zig");
pub const authenticated = @import("authenticated/mod.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const Quota = rate_limit.Quota;
pub const KeyedRateLimiter = rate_limit.KeyedRateLimiter;

pub const Feedback = actor.Feedback;
pub const Unreliable = actor.Unreliable;

/// Alias for identifying communication channels.
pub const Channel = u64;

/// A message received from a given public key: authenticated and within the channel's limits.
/// When `gpa` is set the message owns `payload`; release it with `deinit`.
pub fn Message(comptime P: type) type {
    return struct {
        peer: P,
        payload: []const u8,
        gpa: ?Allocator = null,

        pub fn deinit(message: *@This()) void {
            if (message.gpa) |gpa| gpa.free(message.payload);
            message.* = undefined;
        }
    };
}

/// The set of recipients to send a message to.
pub fn Recipients(comptime P: type) type {
    return union(enum) {
        const Self = @This();

        all,
        some: []const P,
        one: P,

        /// The union of `left` and `right` (commonware `union_with`). `all` absorbs any other
        /// set; two equal `one`s stay `one`; every other explicit union is `some` with sorted,
        /// deduplicated peers, including when empty. The inputs are borrowed; a `some` result
        /// is a new allocation the caller frees with `deinit`.
        pub fn union_with(gpa: Allocator, left: Self, right: Self) Allocator.Error!Self {
            if (left == .all or right == .all) return .all;
            if (left == .one and right == .one and P.order(left.one, right.one) == .eq) {
                return left;
            }
            const left_peers = left.peers();
            const right_peers = right.peers();
            const merged = try gpa.alloc(P, left_peers.len + right_peers.len);
            @memcpy(merged[0..left_peers.len], left_peers);
            @memcpy(merged[left_peers.len..], right_peers);
            std.sort.pdq(P, merged, {}, less_than);
            var unique: usize = 0;
            for (merged) |peer| {
                if (unique > 0 and P.order(merged[unique - 1], peer) == .eq) continue;
                merged[unique] = peer;
                unique += 1;
            }
            assert(unique <= merged.len);
            const result = gpa.realloc(merged, unique) catch merged[0..unique];
            return .{ .some = result };
        }

        /// The explicit peers (`one` as a one-element slice). Not valid for `all`.
        pub fn peers(self: *const Self) []const P {
            return switch (self.*) {
                .all => unreachable, // Proof: callers handle `all` before asking for peers.
                .some => |list| list,
                .one => |*peer| peer[0..1],
            };
        }

        /// Frees a `some` slice allocated by `union_with`.
        pub fn deinit(self: Self, gpa: Allocator) void {
            if (self == .some) gpa.free(self.some);
        }

        fn less_than(_: void, a: P, b: P) bool {
            return P.order(a, b) == .lt;
        }
    };
}

/// Result of `LimitedSender.check`: a checked sender for the recipients within their rate
/// limit, or, when every recipient is limited, the earliest time all of them are available.
pub fn Check(comptime Checked: type) type {
    return union(enum) {
        checked: Checked,
        limited: utils_pkg.SystemTime,
    };
}

/// Primary and secondary peers provided together to `Manager.track`. The same key may appear
/// in both; `track` stores overlapping keys as primary only.
pub fn TrackedPeers(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PeerSet = codec.Set(P);

        /// Peers eligible for primary-only policies.
        primary: PeerSet,
        /// Peers eligible for secondary-only policies.
        secondary: PeerSet,

        pub const empty: Self = .{ .primary = .{ .items = &.{} }, .secondary = .{ .items = &.{} } };

        pub fn init_primary(primary: PeerSet) Self {
            return .{ .primary = primary, .secondary = .{ .items = &.{} } };
        }

        /// The deduplicated union of primary and secondary peers, allocated from `gpa`.
        pub fn @"union"(self: Self, gpa: Allocator) Allocator.Error![]P {
            const all = try gpa.alloc(P, self.primary.items.len + self.secondary.items.len);
            var p: usize = 0;
            var s: usize = 0;
            var count: usize = 0;
            while (p < self.primary.items.len or s < self.secondary.items.len) : (count += 1) {
                const take_primary = s == self.secondary.items.len or
                    (p < self.primary.items.len and
                        P.order(self.primary.items[p], self.secondary.items[s]) != .gt);
                const peer = if (take_primary) self.primary.items[p] else self.secondary.items[s];
                all[count] = peer;
                if (p < self.primary.items.len and P.order(self.primary.items[p], peer) == .eq) {
                    p += 1;
                }
                const secondary = self.secondary.items;
                if (s < secondary.len and P.order(secondary[s], peer) == .eq) s += 1;
            }
            assert(count <= all.len);
            return gpa.realloc(all, count) catch all[0..count];
        }
    };
}

/// Primary and secondary peers with their addresses, for `AddressableManager.track`. A key in
/// both maps is tracked as primary only.
pub fn AddressableTrackedPeers(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PeerMap = codec.Map(P, types.Address);

        primary: PeerMap,
        secondary: PeerMap,

        pub fn init_primary(primary: PeerMap) Self {
            return .{ .primary = primary, .secondary = .{ .entries = &.{} } };
        }
    };
}

/// Notification sent to subscribers when a peer set changes.
pub fn PeerSetUpdate(comptime P: type) type {
    return struct {
        /// The index of the peer set that changed.
        index: u64,
        /// The primary and secondary peers in the new set.
        latest: TrackedPeers(P),
        /// Union of primary and secondary peers across all tracked peer sets.
        all: TrackedPeers(P),
    };
}

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime trait: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) {
                @compileError(@typeName(T) ++ " lacks " ++ trait ++ "." ++ decl);
            }
        }
    }
}

/// Asserts `S` implements `UnlimitedSender`.
pub fn assert_unlimited_sender(comptime S: type) void {
    assert_decls(S, &.{ "PublicKey", "send" }, "UnlimitedSender");
}

/// Asserts `S` implements `LimitedSender` (and so `Sender`).
pub fn assert_limited_sender(comptime S: type) void {
    assert_decls(S, &.{ "PublicKey", "Checked", "check" }, "LimitedSender");
    assert_decls(S.Checked, &.{ "recipients", "send" }, "CheckedSender");
}

/// Asserts `R` implements `Receiver`.
pub fn assert_receiver(comptime R: type) void {
    assert_decls(R, &.{ "PublicKey", "recv", "capacity" }, "Receiver");
}

/// Asserts `M` implements `Provider` and `Manager`.
pub fn assert_manager(comptime M: type) void {
    assert_decls(M, &.{ "PublicKey", "peer_set", "subscribe", "track" }, "Manager");
}

/// Asserts `B` implements `Blocker`.
pub fn assert_blocker(comptime B: type) void {
    assert_decls(B, &.{ "PublicKey", "block", "blocked" }, "Blocker");
}

const testing = std.testing;

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = sizing;
    _ = rate_limit;
    _ = utils;
    _ = simulated;
    _ = authenticated;
}

test "recipient unions (recipient_unions)" {
    const cryptography = @import("cryptography");
    const PublicKey = cryptography.ed25519.PublicKey;
    const R = Recipients(PublicKey);
    const a = cryptography.ed25519.PrivateKey.from_seed(1).public_key();
    const b = cryptography.ed25519.PrivateKey.from_seed(2).public_key();
    const cases = [_]R{
        .all,              .{ .one = a },              .{ .one = b },
        .{ .some = &.{} }, .{ .some = &.{ a, b, a } },
    };
    for (cases) |left| {
        for (cases) |right| {
            const merged = try R.union_with(testing.allocator, left, right);
            defer merged.deinit(testing.allocator);
            if (left == .all or right == .all) {
                try testing.expect(merged == .all);
                continue;
            }
            const equal_ones = left == .one and right == .one and left.one.eql(right.one);
            try testing.expectEqual(equal_ones, merged == .one);
            // Expected: the sorted, deduplicated union.
            var has_a = false;
            var has_b = false;
            for ([_]R{ left, right }) |side| {
                for (side.peers()) |peer| {
                    has_a = has_a or peer.eql(a);
                    has_b = has_b or peer.eql(b);
                }
            }
            var expected: [2]PublicKey = undefined;
            var count: usize = 0;
            const first, const second = if (PublicKey.order(a, b) == .lt) .{ a, b } else .{ b, a };
            if ((first.eql(a) and has_a) or (first.eql(b) and has_b)) {
                expected[count] = first;
                count += 1;
            }
            if ((second.eql(a) and has_a) or (second.eql(b) and has_b)) {
                expected[count] = second;
                count += 1;
            }
            const actual = merged.peers();
            try testing.expectEqual(count, actual.len);
            for (expected[0..count], actual) |e, x| try testing.expect(e.eql(x));
        }
    }
}

test "tracked peers union keeps sorted unique peers" {
    const Int = struct {
        value: u32,
        pub fn order(x: @This(), y: @This()) std.math.Order {
            return std.math.order(x.value, y.value);
        }
        pub fn write(self: @This(), writer: *codec.Writer) void {
            codec.write(u32, self.value, writer);
        }
        pub const fixed_size = 4;
        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!@This() {
            return .{ .value = try reader.read_int(u32) };
        }
    };
    const T = TrackedPeers(Int);
    const primary = [_]Int{ .{ .value = 1 }, .{ .value = 3 } };
    const secondary = [_]Int{ .{ .value = 2 }, .{ .value = 3 }, .{ .value = 9 } };
    const tracked: T = .{ .primary = .init(&primary), .secondary = .init(&secondary) };
    const all = try tracked.@"union"(testing.allocator);
    defer testing.allocator.free(all);
    try testing.expectEqual(@as(usize, 4), all.len);
    for (all, [_]u32{ 1, 2, 3, 9 }) |peer, value| try testing.expectEqual(value, peer.value);
    const empty = try T.empty.@"union"(testing.allocator);
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
}
