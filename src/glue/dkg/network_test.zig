//! Tests of commonware's `glue::dkg::network` (`mod tests`), including the lookup test that
//! a secondary peer activated through `AddressableManager` dials the primary.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const p2p = @import("p2p");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const network = @import("network.zig");

const ed25519 = cryptography.ed25519;
const PublicKey = ed25519.PublicKey;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const Epoch = consensus.Epoch;
const Addresses = network.Addresses(PublicKey);
const PeerMap = p2p.AddressableTrackedPeers(PublicKey).PeerMap;
const Adapter = network.AddressableManager(AddressableTestManager);

/// Records every `track` call, as commonware's `TestManager` does.
const TestManager = struct {
    pub const PublicKey = ed25519.PublicKey;

    gpa: Allocator,
    feedback: p2p.Feedback,
    /// Each tracked id with the union of its primary and secondary peers.
    tracked: std.ArrayList(struct { u64, []ed25519.PublicKey }) = .empty,
    /// Each addressable id with copies of its primary and secondary entries.
    addressable: std.ArrayList(struct { u64, []PeerMap.Entry, []PeerMap.Entry }) = .empty,

    fn deinit(self: *TestManager) void {
        for (self.tracked.items) |entry| self.gpa.free(entry[1]);
        for (self.addressable.items) |entry| {
            self.gpa.free(entry[1]);
            self.gpa.free(entry[2]);
        }
        self.tracked.deinit(self.gpa);
        self.addressable.deinit(self.gpa);
    }

    pub fn track(
        self: *TestManager,
        id: u64,
        peers: p2p.TrackedPeers(ed25519.PublicKey),
    ) p2p.Feedback {
        const all = peers.@"union"(self.gpa) catch @panic("out of memory");
        self.tracked.append(self.gpa, .{ id, all }) catch @panic("out of memory");
        return self.feedback;
    }

    pub fn peer_set(_: *TestManager, _: Allocator, _: u64) !?u8 {
        return null;
    }

    pub fn subscribe(_: *TestManager) !bool {
        return false;
    }
};

const AddressableTestManager = struct {
    pub const PublicKey = ed25519.PublicKey;

    inner: *TestManager,

    pub fn track(
        self: AddressableTestManager,
        id: u64,
        peers: p2p.AddressableTrackedPeers(ed25519.PublicKey),
    ) p2p.Feedback {
        const gpa = self.inner.gpa;
        const primary = gpa.dupe(PeerMap.Entry, peers.primary.entries) catch @panic("oom");
        const secondary = gpa.dupe(PeerMap.Entry, peers.secondary.entries) catch @panic("oom");
        self.inner.addressable.append(gpa, .{ id, primary, secondary }) catch @panic("oom");
        return self.inner.feedback;
    }

    pub fn overwrite(self: AddressableTestManager, _: PeerMap) p2p.Feedback {
        return self.inner.feedback;
    }

    pub fn peer_set(self: AddressableTestManager, gpa: Allocator, id: u64) !?u8 {
        return self.inner.peer_set(gpa, id);
    }

    pub fn subscribe(self: AddressableTestManager) !bool {
        return self.inner.subscribe();
    }
};

fn key(seed: u64) PublicKey {
    return ed25519.PrivateKey.from_seed(seed).public_key();
}

fn address(port: u16) p2p.Address {
    return .{ .symmetric = .{ .ip = .{ .v4 = .localhost }, .port = port } };
}

/// Keys 1..4 sorted, with primary {k0, k1} and secondary {k1, k2} (in sorted-key order).
const Fixture = struct {
    keys: [4]PublicKey,
    primary: Set(PublicKey),
    secondary: Set(PublicKey),

    fn init(gpa: Allocator) !Fixture {
        const keys = [4]PublicKey{ key(1), key(2), key(3), key(4) };
        return .{
            .keys = keys,
            .primary = try Set(PublicKey).from_dedup(gpa, &.{ keys[0], keys[1] }),
            .secondary = try Set(PublicKey).from_dedup(gpa, &.{ keys[1], keys[2] }),
        };
    }

    fn deinit(self: *Fixture, gpa: Allocator) void {
        self.primary.deinit(gpa);
        self.secondary.deinit(gpa);
    }

    fn peers(self: *const Fixture) p2p.TrackedPeers(PublicKey) {
        return .{
            .primary = .{ .items = self.primary.items },
            .secondary = .{ .items = self.secondary.items },
        };
    }

    fn directory(self: *const Fixture, gpa: Allocator, count: usize, offset: u16) !Addresses {
        var pairs: [4]Addresses.Inner.Pair = undefined;
        for (pairs[0..count], 0..) |*pair, index| {
            pair.* = .{ self.keys[index], address(offset + @as(u16, @intCast(index)) + 1) };
        }
        return Addresses.init(gpa, pairs[0..count]);
    }
};

fn expect_address(entries: []const PeerMap.Entry, peer: PublicKey, expected: p2p.Address) !void {
    for (entries) |entry| {
        if (entry.key.eql(peer)) return testing.expect(entry.value.eql(expected));
    }
    return error.TestExpectedEqual;
}

fn expect_keys(entries: []const PeerMap.Entry, keys: Set(PublicKey)) !void {
    try testing.expectEqual(keys.items.len, entries.len);
    for (entries, keys.items) |entry, item| try testing.expect(entry.key.eql(item));
}

test "network: key-only manager tracks peers" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit(gpa);
    var inner: TestManager = .{ .gpa = gpa, .feedback = .closed };
    defer inner.deinit();
    var manager = network.KeyOnlyManager(*TestManager).init(&inner);
    // A closed endpoint still counts as tracked: key-only managers never fail.
    try manager.track(.new(7), fixture.peers(), &Unit{});
    try testing.expectEqual(@as(usize, 1), inner.tracked.items.len);
    try testing.expectEqual(@as(u64, 7), inner.tracked.items[0][0]);
    const all = try fixture.peers().@"union"(gpa);
    defer gpa.free(all);
    try testing.expectEqualSlices(PublicKey, all, inner.tracked.items[0][1]);
}

test "network: addressable provider delegates" {
    const gpa = testing.allocator;
    var inner: TestManager = .{ .gpa = gpa, .feedback = .ok };
    defer inner.deinit();
    var manager = Adapter.init(gpa, .{ .inner = &inner });
    try testing.expectEqual(@as(?u8, null), try manager.peer_set(gpa, 7));
    try testing.expect(!try manager.subscribe());
}

test "network: key-only directory matches any peer set" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit(gpa);
    const Dir = network.DirectoryOps(PublicKey, Unit);
    try testing.expect(Dir.matches(.{}, fixture.primary));
    try testing.expect(Dir.matches(.{}, .empty));
    try testing.expectEqual(@as(usize, 0), Dir.max_encode_size(1000));
}

test "network: addresses require the exact peer set" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit(gpa);
    var directory = try fixture.directory(gpa, 2, 0);
    defer directory.deinit(gpa);
    try testing.expect(directory.matches(fixture.primary));
    const all = try fixture.peers().@"union"(gpa);
    defer gpa.free(all);
    try testing.expect(!directory.matches(.{ .items = all }));
    try testing.expect(!directory.matches(.{ .items = fixture.keys[0..1] }));
}

test "network: addressable mapping preserves roles" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit(gpa);
    var inner: TestManager = .{ .gpa = gpa, .feedback = .ok };
    defer inner.deinit();
    var manager = Adapter.init(gpa, .{ .inner = &inner });
    for ([_]u16{ 0, 10 }, [_]u64{ 9, 10 }) |offset, epoch| {
        var directory = try fixture.directory(gpa, 3, offset);
        defer directory.deinit(gpa);
        try manager.track(.new(epoch), fixture.peers(), &directory);
    }
    const tracked = inner.addressable.items;
    try testing.expectEqual(@as(usize, 2), tracked.len);
    for (tracked, [_]u64{ 9, 10 }, [_]u16{ 0, 10 }) |entry, epoch, offset| {
        try testing.expectEqual(epoch, entry[0]);
        try expect_keys(entry[1], fixture.primary);
        try expect_keys(entry[2], fixture.secondary);
        const k = fixture.keys;
        try expect_address(entry[1], k[0], address(offset + 1));
        try expect_address(entry[1], k[1], address(offset + 2));
        try expect_address(entry[2], k[1], address(offset + 2));
        try expect_address(entry[2], k[2], address(offset + 3));
    }
}

test "network: missing address prevents registration" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit(gpa);
    var inner: TestManager = .{ .gpa = gpa, .feedback = .ok };
    defer inner.deinit();
    var manager = Adapter.init(gpa, .{ .inner = &inner });
    var directory = try fixture.directory(gpa, 1, 0);
    defer directory.deinit(gpa);
    const peers = fixture.peers();
    try testing.expectError(error.MissingAddress, manager.track(.new(1), peers, &directory));
    const missing = network.missing_address(PublicKey, peers, &directory).?;
    try testing.expect(missing.eql(fixture.keys[1]));
    try testing.expectEqual(@as(usize, 0), inner.addressable.items.len);
    _ = Epoch;
}

const runtime = @import("runtime");
const stream = @import("stream");
const lookup = p2p.authenticated.lookup;
const Upgrader = stream.SakeCups(ed25519.PrivateKey, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const LookupNet = lookup.Network(Upgrader, Transport);
const LookupManager = network.AddressableManager(LookupNet.Oracle);
const Io = std.Io;
const Scope = runtime.telemetry.metrics.Scope;

const LookupNode = struct {
    net: *LookupNet,
    registered: LookupNet.Registered,
    task: Io.Future(anyerror!void),

    fn run(net: *LookupNet) anyerror!void {
        return net.run();
    }

    /// Creates the network listening on `port` and activates epoch 3's peers from `directory`
    /// through the DKG addressable manager.
    fn start(
        io: Io,
        transport: *Transport,
        scope: Scope,
        signer: ed25519.PrivateKey,
        port: u16,
        peers: p2p.TrackedPeers(PublicKey),
        directory: *const Addresses,
    ) !LookupNode {
        const gpa = testing.allocator;
        const config = LookupNet.Config.local(.{
            .upgrader = .init(.{
                .signer = signer,
                .synchrony_bound_ms = 5_000,
                .max_handshake_age_ms = 10_000,
                .version = .v1,
            }, .v1),
            .namespace = "_COMMONWARE_GLUE_DKG_LOOKUP_TEST",
            .listen = lookup.network.to_address(address(port).symmetric),
            .max_peers_per_set = 2,
            .max_message_size = 1024,
            .mailbox_size = 1_000,
        });
        const net = try LookupNet.create(gpa, io, transport, scope, config);
        errdefer net.destroy();
        var node: LookupNode = .{
            .net = net,
            .registered = try net.register(0, .per_second(100)),
            .task = undefined,
        };
        var manager = LookupManager.init(gpa, net.oracle());
        try manager.track(.new(3), peers, directory);
        node.task = try io.concurrent(run, .{net});
        return node;
    }

    fn stop(node: *LookupNode, io: Io) void {
        node.task.cancel(io) catch {};
        node.registered.sender.deinit();
        while (node.registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        node.registered.receiver.deinit();
        node.net.destroy();
        node.* = undefined;
    }

    /// Sends `payload` to `to` every 100 ms until `receiver` gets a message, which must be
    /// `payload` from `from` (commonware's spawned send loop, aborted on receipt).
    fn exchange(
        io: Io,
        sender: *LookupNode,
        receiver: *LookupNode,
        to: PublicKey,
        from: PublicKey,
        payload: []const u8,
    ) !void {
        var attempts: u32 = 0;
        while (true) : (attempts += 1) {
            try testing.expect(attempts < 100);
            const sent = try sender.registered.sender.send(.{ .one = to }, &.{payload}, true);
            testing.allocator.free(sent);
            if (receiver.registered.receiver.try_recv()) |message| {
                var owned = message;
                defer owned.deinit();
                try testing.expect(owned.peer.eql(from));
                try testing.expectEqualSlices(u8, payload, owned.payload);
                return;
            } else |err| try testing.expectEqual(error.Empty, err);
            try io.sleep(.fromMilliseconds(100), .real);
        }
    }
};

fn lookup_secondary_dials_primary(io: Io, transport: *Transport, scope: Scope) !void {
    const gpa = testing.allocator;
    const dealer_signer = ed25519.PrivateKey.from_seed(10);
    const participant_signer = ed25519.PrivateKey.from_seed(11);
    const dealer_key = dealer_signer.public_key();
    const participant_key = participant_signer.public_key();
    // The participant's ingress and egress are the same socket, but asymmetric.
    const participant_socket = address(6101).symmetric;
    var directory = try Addresses.init(gpa, &.{
        .{ dealer_key, address(6100) },
        .{ participant_key, .{ .asymmetric = .{
            .ingress = .{ .socket = participant_socket },
            .egress = participant_socket,
        } } },
    });
    defer directory.deinit(gpa);
    var primary = try Set(PublicKey).from_dedup(gpa, &.{dealer_key});
    defer primary.deinit(gpa);
    var secondary = try Set(PublicKey).from_dedup(gpa, &.{participant_key});
    defer secondary.deinit(gpa);
    const peers: p2p.TrackedPeers(PublicKey) = .{
        .primary = .{ .items = primary.items },
        .secondary = .{ .items = secondary.items },
    };
    const dealer_scope = scope.child("dealer");
    var dealer =
        try LookupNode.start(io, transport, dealer_scope, dealer_signer, 6100, peers, &directory);
    defer dealer.stop(io);
    const participant_scope = scope.child("participant");
    var participant = try LookupNode.start(
        io,
        transport,
        participant_scope,
        participant_signer,
        6101,
        peers,
        &directory,
    );
    defer participant.stop(io);
    // The secondary dials the primary; the request and the response cross the connection.
    try LookupNode.exchange(io, &participant, &dealer, dealer_key, participant_key, "request");
    try LookupNode.exchange(io, &dealer, &participant, participant_key, dealer_key, "response");
}

test "network: lookup secondary dials primary and receives response" {
    try runtime.deterministic.soak(testing.allocator, .{
        .seed = 0,
        .timeout_ns = 10 * std.time.ns_per_s,
    }, {}, struct {
        fn run_round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            const args = .{ runner.io(), runner.network(), runner.metrics() };
            try (try runner.start(lookup_secondary_dials_primary, args));
        }
    }.run_round);
}
