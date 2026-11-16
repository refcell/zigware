//! Mock implementations for testing (commonware `p2p/src/utils/mocks/mod.rs`).
//!
//! Commonware's `Metrics` mock (a supervisor that registers nothing) has no counterpart:
//! zigware components register metrics in a `runtime.telemetry.metrics.Scope`, and a scope
//! over a scratch `Registry` serves the same purpose.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const p2p = @import("../../root.zig");
const mux = @import("../mux.zig");
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// A sender that accepts messages without delivering them. It keeps a static peer set
/// (borrowed: it must outlive the sender) so `Recipients.all` expands consistently with the
/// `Sender` contract.
pub fn InertSender(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Checked = InertCheckedSender(P);

        gpa: Allocator,
        peers: []const P,

        pub fn check(
            self: *Self,
            recipients: p2p.Recipients(P),
        ) Allocator.Error!p2p.Check(Checked) {
            const list: []const P = switch (recipients) {
                .all => self.peers,
                .some => |some| some,
                .one => |*one| one[0..1],
            };
            const owned = try self.gpa.dupe(P, list);
            assert(owned.len == list.len);
            return .{ .checked = .{ .gpa = self.gpa, .list = owned } };
        }

        /// Commonware's blanket `Sender::send`: the recipients attempted (caller-owned).
        pub fn send(
            self: *Self,
            recipients: p2p.Recipients(P),
            parts: []const []const u8,
            priority: bool,
        ) Allocator.Error![]P {
            return mux.send(self.gpa, self, recipients, parts, priority);
        }

        pub fn clone(self: *const Self) Self {
            return self.*;
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }
    };
}

/// Checked sender returned by `InertSender`.
pub fn InertCheckedSender(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        gpa: Allocator,
        list: []const P,

        pub fn recipients(self: *const Self) []const P {
            return self.list;
        }

        pub fn send(self: Self, parts: []const []const u8, priority: bool) Unreliable(Feedback) {
            _ = parts;
            _ = priority;
            self.deinit();
            return .new(.ok);
        }

        pub fn deinit(self: Self) void {
            self.gpa.free(self.list);
        }
    };
}

/// A receiver that never yields a message: `recv` waits until its task is canceled.
pub fn InertReceiver(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,

        pub fn recv(self: *Self) Io.Cancelable!p2p.Message(P) {
            try self.mutex.lock(self.io);
            defer self.mutex.unlock(self.io);
            // Nothing signals the condition, so only cancelation ends the wait.
            while (true) try self.condition.wait(self.io, &self.mutex);
        }

        pub fn capacity(_: *const Self) usize {
            return 1;
        }
    };
}

/// An inert point-to-point channel over a static peer set (borrowed).
pub fn inert_channel(
    comptime P: type,
    gpa: Allocator,
    io: Io,
    peers: []const P,
) struct { sender: InertSender(P), receiver: InertReceiver(P) } {
    return .{
        .sender = .{ .gpa = gpa, .peers = peers },
        .receiver = .{ .io = io },
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const utils_pkg = @import("utils");
const Key = cryptography.ed25519.PublicKey;

/// A sender whose checked sends are always rejected.
const RejectingSender = struct {
    pub const PublicKey = Key;
    pub const Checked = RejectingSender;

    peer: Key,

    pub fn check(self: *RejectingSender, _: p2p.Recipients(Key)) error{}!p2p.Check(Checked) {
        return .{ .checked = self.* };
    }

    pub fn recipients(self: *const RejectingSender) []const Key {
        return (&self.peer)[0..1];
    }

    pub fn send(_: RejectingSender, _: []const []const u8, _: bool) Unreliable(Feedback) {
        return .rejected;
    }

    pub fn deinit(_: RejectingSender) void {}
};

test "inert sender expands all recipients" {
    var rng = utils_pkg.test_rng();
    const peers = [_]Key{
        cryptography.ed25519.PrivateKey.random(&rng).public_key(),
        cryptography.ed25519.PrivateKey.random(&rng).public_key(),
        cryptography.ed25519.PrivateKey.random(&rng).public_key(),
    };
    var channel = inert_channel(Key, testing.allocator, testing.io, &peers);
    const sent = try channel.sender.send(.all, &.{"hello"}, false);
    defer testing.allocator.free(sent);
    try testing.expectEqual(peers.len, sent.len);
    for (peers, sent) |expected, actual| try testing.expect(expected.eql(actual));
}

test "sender returns no recipients when checked send rejects" {
    var rng = utils_pkg.test_rng();
    const peer = cryptography.ed25519.PrivateKey.random(&rng).public_key();
    var sender: RejectingSender = .{ .peer = peer };
    const sent = try mux.send(testing.allocator, &sender, .{ .one = peer }, &.{"hello"}, false);
    defer testing.allocator.free(sent);
    try testing.expectEqual(0, sent.len);
}
