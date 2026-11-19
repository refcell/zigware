//! Network-facing DKG test fixtures (commonware `glue::dkg::tests::mocks`): a manager whose
//! activation always fails, a manager that records each epoch's directory, a receiver that
//! drops messages, and the widest transport directory. `mocks.zig` re-exports them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const network = @import("../network.zig");

const Epoch = consensus.Epoch;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const PublicKey = cryptography.ed25519.PublicKey;
const Addresses = network.Addresses(PublicKey);

fn ReturnType(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}

fn Base(comptime M: type) type {
    return switch (@typeInfo(M)) {
        .pointer => |info| info.child,
        else => M,
    };
}

/// A 253-byte DNS name of four maximal labels: the widest hostname.
fn widest_host() [utils.Hostname.len_max]u8 {
    var host: [utils.Hostname.len_max]u8 = undefined;
    const lengths = [_]usize{ 63, 63, 63, 61 };
    var index: usize = 0;
    for (lengths, "abcd", 0..) |len, char, label| {
        if (label > 0) {
            host[index] = '.';
            index += 1;
        }
        @memset(host[index..][0..len], char);
        index += len;
    }
    assert(index == host.len);
    return host;
}

/// Maps every peer to the widest address: a maximum-length DNS ingress with an IPv6 egress
/// (commonware `widest_addresses`).
pub fn widest_addresses(gpa: Allocator, peers: Set(PublicKey)) !Addresses {
    const host = comptime widest_host();
    const address: p2p.Address = .{ .asymmetric = .{
        .ingress = .{ .dns = .{ .host = try utils.Hostname.init(&host), .port = 65535 } },
        .egress = .{ .ip = .{ .v6 = .localhost }, .port = 65535 },
    } };
    const pairs = try gpa.alloc(Addresses.Inner.Pair, peers.items.len);
    defer gpa.free(pairs);
    for (pairs, peers.items) |*pair, peer| pair.* = .{ peer, address };
    const directory = try Addresses.init(gpa, pairs);
    assert(directory.matches(peers));
    return directory;
}

/// A key-only DKG manager whose `track` always fails (commonware `FailingManager`), so an
/// activation failure can be injected under a real p2p provider.
pub fn FailingManager(comptime M: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = Base(M).PublicKey;
        pub const Directory = Unit;
        pub const Error = error{TrackFailed};

        inner: M,

        pub fn init(inner: M) Self {
            return .{ .inner = inner };
        }

        pub fn track(
            self: *Self,
            epoch: Epoch,
            peers: p2p.TrackedPeers(Self.PublicKey),
            directory: *const Unit,
        ) Error!void {
            _ = .{ self, epoch, peers, directory };
            return error.TrackFailed;
        }

        pub fn peer_set(self: *Self, gpa: Allocator, id: u64) ReturnType(Base(M).peer_set) {
            return self.inner.peer_set(gpa, id);
        }

        pub fn subscribe(self: *Self) ReturnType(Base(M).subscribe) {
            return self.inner.subscribe();
        }
    };
}

/// One `track` call recorded by `DirectoryManager`, owned by the manager.
pub const DirectoryTrack = struct {
    epoch: Epoch,
    primary: []PublicKey,
    secondary: []PublicKey,
    directory: Addresses,
};

/// A DKG manager over addressed directories that records every activation, then forwards the
/// peers to a key-only manager `M` (commonware `DirectoryManager`).
pub fn DirectoryManager(comptime M: type) type {
    network.assert_manager(Base(M));
    return struct {
        const Self = @This();
        pub const PublicKey = Base(M).PublicKey;
        pub const Directory = Addresses;
        pub const Error = Base(M).Error || Allocator.Error;

        gpa: Allocator,
        inner: M,
        tracked: std.ArrayList(DirectoryTrack) = .empty,

        pub fn init(gpa: Allocator, inner: M) Self {
            return .{ .gpa = gpa, .inner = inner };
        }

        pub fn deinit(self: *Self) void {
            for (self.tracked.items) |*entry| {
                self.gpa.free(entry.primary);
                self.gpa.free(entry.secondary);
                entry.directory.deinit(self.gpa);
            }
            self.tracked.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn track(
            self: *Self,
            epoch: Epoch,
            peers: p2p.TrackedPeers(Self.PublicKey),
            directory: *const Addresses,
        ) Error!void {
            const primary = try self.gpa.dupe(Self.PublicKey, peers.primary.items);
            errdefer self.gpa.free(primary);
            const secondary = try self.gpa.dupe(Self.PublicKey, peers.secondary.items);
            errdefer self.gpa.free(secondary);
            var owned = try directory.clone(self.gpa);
            errdefer owned.deinit(self.gpa);
            try self.tracked.append(self.gpa, .{
                .epoch = epoch,
                .primary = primary,
                .secondary = secondary,
                .directory = owned,
            });
            assert(self.tracked.items.len > 0);
            return self.inner.track(epoch, peers, &Unit{});
        }

        pub fn peer_set(self: *Self, gpa: Allocator, id: u64) ReturnType(Base(M).peer_set) {
            return self.inner.peer_set(gpa, id);
        }

        pub fn subscribe(self: *Self) ReturnType(Base(M).subscribe) {
            return self.inner.subscribe();
        }
    };
}

/// Which messages a `FilteredReceiver` drops.
pub const Filter = union(enum) {
    /// Pass every message.
    none,
    /// Drop every message.
    all,
    /// Drop muxed messages whose subchannel (the epoch) is listed.
    epochs: []const u64,
};

/// A receiver that drops the messages its filter selects (commonware `FilteredReceiver`).
pub fn FilteredReceiver(comptime R: type) type {
    p2p.assert_receiver(R);
    return struct {
        const Self = @This();
        pub const PublicKey = R.PublicKey;
        const Recv = @typeInfo(ReturnType(R.recv)).error_union;
        pub const Error = Recv.error_set;

        inner: R,
        filter: Filter,

        pub fn pass(inner: R) Self {
            return .{ .inner = inner, .filter = .none };
        }

        pub fn drop_all(inner: R) Self {
            return .{ .inner = inner, .filter = .all };
        }

        /// Drops messages on the listed epochs' subchannels; `epochs` outlives the receiver.
        pub fn epochs(inner: R, listed: []const u64) Self {
            return .{ .inner = inner, .filter = .{ .epochs = listed } };
        }

        pub fn recv(self: *Self) Error!Recv.payload {
            while (true) {
                var message = try self.inner.recv();
                if (self.keeps(&message)) return message;
                message.deinit();
            }
        }

        fn keeps(self: *const Self, message: *const Recv.payload) bool {
            switch (self.filter) {
                .none => return true,
                .all => return false,
                .epochs => |listed| {
                    const epoch, _ = p2p.utils.mux.parse(message.payload) catch
                        @panic("failed to parse mux message");
                    return std.mem.indexOfScalar(u64, listed, epoch) == null;
                },
            }
        }

        pub fn capacity(self: *const Self) usize {
            const value = self.inner.capacity();
            assert(value > 0);
            return value;
        }
    };
}
