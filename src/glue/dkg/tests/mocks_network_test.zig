//! Checks of the network-facing DKG mocks: the failing and recording managers, the filtered
//! receiver, and the widest directory.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const network = @import("../network.zig");
const mocks = @import("mocks_network.zig");

const Epoch = consensus.Epoch;
const Set = utils.ordered.Set;
const P = cryptography.ed25519.PublicKey;
const Addresses = network.Addresses(P);

fn key(seed: u64) P {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn keys(gpa: Allocator, count: u64) !Set(P) {
    var list: std.ArrayList(P) = .empty;
    defer list.deinit(gpa);
    for (0..count) |seed| try list.append(gpa, key(seed));
    return Set(P).from_dedup(gpa, list.items);
}

/// A key-only manager that counts activations.
const CountingManager = struct {
    pub const PublicKey = P;
    pub const Directory = utils.sequence.Unit;
    pub const Error = error{};

    tracked: u32 = 0,

    pub fn track(
        self: *CountingManager,
        epoch: Epoch,
        peers: p2p.TrackedPeers(P),
        directory: *const Directory,
    ) Error!void {
        _ = .{ epoch, peers, directory };
        self.tracked += 1;
    }

    pub fn peer_set(self: *CountingManager, gpa: Allocator, id: u64) !?u64 {
        _ = .{ self, gpa };
        return id;
    }

    pub fn subscribe(self: *CountingManager) !u32 {
        return self.tracked;
    }
};

test "failing manager rejects activation and forwards reads" {
    var inner: CountingManager = .{};
    var manager = mocks.FailingManager(*CountingManager).init(&inner);
    try testing.expectError(error.TrackFailed, manager.track(.new(0), .empty, &.{}));
    try testing.expectEqual(@as(u32, 0), inner.tracked);
    try testing.expectEqual(@as(?u64, 5), try manager.peer_set(testing.allocator, 5));
}

test "directory manager records each activation before forwarding" {
    const gpa = testing.allocator;
    var peers = try keys(gpa, 3);
    defer peers.deinit(gpa);
    var directory = try mocks.widest_addresses(gpa, peers);
    defer directory.deinit(gpa);
    var inner: CountingManager = .{};
    var manager = mocks.DirectoryManager(*CountingManager).init(gpa, &inner);
    defer manager.deinit();
    const tracked: p2p.TrackedPeers(P) = .init_primary(.{ .items = peers.items });
    try manager.track(.new(2), tracked, &directory);
    try manager.track(.new(3), .empty, &directory);
    try testing.expectEqual(@as(u32, 2), inner.tracked);
    try testing.expectEqual(@as(usize, 2), manager.tracked.items.len);
    const first = manager.tracked.items[0];
    try testing.expectEqual(@as(u64, 2), first.epoch.get());
    try testing.expectEqualSlices(P, peers.items, first.primary);
    try testing.expectEqual(@as(usize, 0), first.secondary.len);
    try testing.expect(first.directory.eql(directory));
    try testing.expectEqual(@as(u64, 3), manager.tracked.items[1].epoch.get());
}

test "widest addresses use the widest address encoding" {
    const gpa = testing.allocator;
    var peers = try keys(gpa, 4);
    defer peers.deinit(gpa);
    var directory = try mocks.widest_addresses(gpa, peers);
    defer directory.deinit(gpa);
    try testing.expect(directory.matches(peers));
    const address = directory.get(peers.items[0]).?;
    try testing.expectEqual(@as(usize, 253), address.asymmetric.ingress.dns.host.len);
    // The bound reserves a 5-byte hostname length varint; 253 takes 2.
    try testing.expectEqual(p2p.Address.max_encode_size - 3, address.encode_size());
    try testing.expect(directory.encode_size() <= Addresses.max_encode_size_for(4));
}

/// A receiver over a fixed list of payloads.
const ListReceiver = struct {
    pub const PublicKey = P;

    payloads: []const []const u8,
    next: usize = 0,

    pub fn recv(self: *ListReceiver) error{Closed}!p2p.Message(P) {
        if (self.next == self.payloads.len) return error.Closed;
        defer self.next += 1;
        return .{ .peer = key(0), .payload = self.payloads[self.next] };
    }

    pub fn capacity(self: *const ListReceiver) usize {
        _ = self;
        return 8;
    }
};

test "filtered receiver passes, drops all, or drops listed epochs" {
    // Subchannels 1, 2, and 300 (varint 0xac 0x02), each with a one-byte body.
    const payloads = [_][]const u8{ "\x01a", "\x02b", "\xac\x02c" };
    var pass = mocks.FilteredReceiver(ListReceiver).pass(.{ .payloads = &payloads });
    try testing.expectEqualStrings(payloads[0], (try pass.recv()).payload);
    try testing.expectEqual(@as(usize, 8), pass.capacity());

    var all = mocks.FilteredReceiver(ListReceiver).drop_all(.{ .payloads = &payloads });
    try testing.expectError(error.Closed, all.recv());

    const dropped = [_]u64{ 1, 300 };
    var epochs = mocks.FilteredReceiver(ListReceiver).epochs(.{ .payloads = &payloads }, &dropped);
    try testing.expectEqualStrings(payloads[1], (try epochs.recv()).payload);
    try testing.expectError(error.Closed, epochs.recv());
}
