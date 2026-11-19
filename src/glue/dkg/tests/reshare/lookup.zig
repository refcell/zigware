//! The reshare harness's transports (commonware `glue::dkg::tests::reshare::harness`'s
//! `Network`, `TestDirectory`, and `TestManager`): discovery dials by key, lookup by the
//! address the epoch's in-band directory names. Participant `i` listens on 127.0.0.1:(10000 + i)
//! (commonware's `addresses`); the simulated network ignores addresses, but the directory a
//! block carries and the manager that resolves it are lookup's.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const dkg_network = @import("../../network.zig");

const Epoch = consensus.Epoch;
const Key = cryptography.ed25519.PublicKey;
const Set = utils.ordered.Set(Key);
const Net = p2p.simulated.Network(Key);
const Addresses = dkg_network.Addresses(Key);

/// commonware `Network`.
pub const Network = enum { discovery, lookup };

/// The first participant's port (commonware's `10_000 + index`).
pub const base_port: u16 = 10_000;

/// commonware `TestDirectory(Option<Addresses>)`: no addresses on discovery.
pub const TestDirectory = struct {
    addresses: ?Addresses = null,

    pub const Cfg = Addresses.Cfg;

    /// commonware `Network::directory`: `peers`' addresses on lookup, none on discovery.
    /// `participants` orders every participant by index, which picks its port.
    pub fn of(
        gpa: Allocator,
        network: Network,
        participants: []const Key,
        peers: Set,
    ) !TestDirectory {
        if (network == .discovery) return .{};
        const pairs = try gpa.alloc(Addresses.Inner.Pair, peers.items.len);
        defer gpa.free(pairs);
        for (pairs, peers.items) |*pair, peer| {
            const index = for (participants, 0..) |key, at| {
                if (key.eql(peer)) break at;
            } else @panic("participant must have an address");
            const port = base_port + @as(u16, @intCast(index));
            const address: p2p.Address = .{
                .symmetric = .{ .ip = .{ .v4 = .localhost }, .port = port },
            };
            pair.* = .{ peer, address };
        }
        const result: TestDirectory = .{ .addresses = try .init(gpa, pairs) };
        assert(result.matches(peers));
        return result;
    }

    pub fn codec_config(peers: Set) Cfg {
        return Addresses.codec_config(peers);
    }

    pub fn max_encode_size_for(peers: usize) usize {
        return 1 + Addresses.max_encode_size_for(peers);
    }

    pub fn matches(self: TestDirectory, peers: Set) bool {
        const addresses = self.addresses orelse return true;
        return addresses.matches(peers);
    }

    pub fn clone(self: TestDirectory, gpa: Allocator) Allocator.Error!TestDirectory {
        const addresses = self.addresses orelse return .{};
        return .{ .addresses = try addresses.clone(gpa) };
    }

    pub fn eql(a: TestDirectory, b: TestDirectory) bool {
        if (a.addresses == null or b.addresses == null) {
            return a.addresses == null and b.addresses == null;
        }
        return a.addresses.?.eql(b.addresses.?);
    }

    pub fn deinit(self: *TestDirectory, gpa: Allocator) void {
        if (self.addresses) |*addresses| addresses.deinit(gpa);
        self.* = undefined;
    }

    pub fn write(self: TestDirectory, writer: *codec.Writer) void {
        writer.write_byte(@intFromBool(self.addresses != null));
        if (self.addresses) |addresses| addresses.write(writer);
    }

    pub fn encode_size(self: TestDirectory) usize {
        const inner = if (self.addresses) |addresses| addresses.encode_size() else 0;
        return 1 + inner;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!TestDirectory {
        if (!try codec.read(bool, gpa, reader)) return .{};
        return .{ .addresses = try Addresses.read(gpa, reader, cfg) };
    }
};

/// commonware `TestManager`: one node's DKG manager over its own peer sets, resolving the
/// directory on lookup.
pub const TestManager = union(Network) {
    pub const PublicKey = Key;
    pub const Directory = TestDirectory;
    pub const Error = error{ MissingAddress, OutOfMemory };
    const Discovery = dkg_network.KeyOnlyManager(Net.Manager);
    const Lookup = dkg_network.AddressableManager(Net.SocketManager);

    discovery: Discovery,
    lookup: Lookup,

    /// commonware `Network::manager`, after the caller reset `control`'s peer sets.
    pub fn init(gpa: Allocator, network: Network, control: Net.Control) TestManager {
        return switch (network) {
            .discovery => .{ .discovery = .init(control.manager()) },
            .lookup => .{ .lookup = .init(gpa, control.socket_manager()) },
        };
    }

    pub fn track(
        self: *TestManager,
        epoch: Epoch,
        peers: p2p.TrackedPeers(Key),
        directory: *const TestDirectory,
    ) Error!void {
        switch (self.*) {
            .discovery => |*manager| {
                if (directory.addresses != null) @panic("network and directory must match");
                return manager.track(epoch, peers, &.{});
            },
            .lookup => |*manager| {
                const addresses = &(directory.addresses orelse
                    @panic("network and directory must match"));
                return manager.track(epoch, peers, addresses);
            },
        }
    }

    /// The node's own peer sets, which both transports track (commonware's `Provider`).
    pub fn provider(self: *const TestManager) Net.Manager {
        return switch (self.*) {
            .discovery => |manager| manager.manager,
            .lookup => |manager| manager.manager.manager,
        };
    }

    pub fn peer_set(self: *TestManager, gpa: Allocator, id: u64) !?Net.OwnedPeers {
        return switch (self.*) {
            .discovery => |*manager| manager.peer_set(gpa, id),
            .lookup => |*manager| manager.peer_set(gpa, id),
        };
    }

    pub fn subscribe(self: *TestManager) !Net.PeerSetSubscription {
        return switch (self.*) {
            .discovery => |*manager| manager.subscribe(),
            .lookup => |*manager| manager.subscribe(),
        };
    }

    comptime {
        dkg_network.assert_manager(TestManager);
    }
};
