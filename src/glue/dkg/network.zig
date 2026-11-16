//! Transport-neutral peer activation for DKG (commonware `glue::dkg::network`).
//!
//! DKG peer identities are key-only in every ceremony artifact and wire message. Transports
//! that need more than a public key to dial a peer (like `p2p.authenticated.lookup`) use an
//! epoch-scoped directory carried in-band by `types.EpochInfo`: the final block of each epoch
//! embeds the next epoch's directory.
//!
//! - A directory type `D` over keys `P` is `utils.sequence.Unit` (key-only transports) or a
//!   type with `codec_config`, `max_encode_size_for`, `matches`, `clone`, `eql`, `deinit`,
//!   and the codec methods, such as `Addresses(P)`. `DirectoryOps(P, D)` dispatches over both.
//! - A DKG manager (`assert_manager`) activates an epoch's peers from its directory:
//!   `KeyOnlyManager` adapts a p2p `Manager` and ignores the directory, `AddressableManager`
//!   adapts a p2p `AddressableManager` and resolves each peer's address.
//!
//! Activation never consults application state: `track` receives only an epoch's peer set
//! and the directory embedded in its `EpochInfo`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const p2p = @import("p2p");
const consensus = @import("consensus");

const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Unit = utils.sequence.Unit;
const Epoch = consensus.Epoch;
const Address = p2p.Address;

/// Static dispatch over a directory type `D` for keys `P` (commonware's `Directory` trait,
/// implemented by `Unit` and `Addresses`).
pub fn DirectoryOps(comptime P: type, comptime D: type) type {
    const key_only = D == Unit;
    if (!key_only) {
        for ([_][]const u8{
            "Cfg",    "codec_config", "max_encode_size_for", "matches", "clone", "eql",
            "deinit", "write",        "encode_size",         "read",
        }) |decl| {
            if (!@hasDecl(D, decl)) @compileError(@typeName(D) ++ " lacks Directory." ++ decl);
        }
    }
    return struct {
        /// The codec configuration `read` takes.
        pub const Cfg = codec.Cfg(D);

        /// The configuration for decoding a directory of exactly `peers`.
        pub fn codec_config(peers: Set(P)) Cfg {
            if (comptime key_only) return {};
            return D.codec_config(peers);
        }

        /// An upper bound on the encoded size of a directory of at most `peers` peers.
        pub fn max_encode_size(peers: usize) usize {
            if (comptime key_only) return 0;
            return D.max_encode_size_for(peers);
        }

        /// Whether `directory` names exactly `peers` (always true for a key-only directory).
        pub fn matches(directory: D, peers: Set(P)) bool {
            if (comptime key_only) return true;
            return directory.matches(peers);
        }

        pub fn clone(directory: D, gpa: Allocator) Allocator.Error!D {
            if (comptime key_only) return directory;
            return directory.clone(gpa);
        }

        pub fn eql(a: D, b: D) bool {
            if (comptime key_only) return true;
            return a.eql(b);
        }

        pub fn deinit(directory: *D, gpa: Allocator) void {
            if (comptime key_only) return;
            directory.deinit(gpa);
        }
    };
}

/// Address directory for transports that dial by `p2p.Address`.
pub fn Addresses(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Inner = Map(P, Address);
        /// The number of address entries the decoder accepts. An `EpochInfo` derives an exact
        /// bound from the union of its dealers, players, and next players.
        pub const Cfg = codec.RangeCfg(usize);

        map: Inner = .empty,

        /// Sorts `pairs` by key into a directory, keeping the first of each duplicate key
        /// (commonware's `FromIterator`).
        pub fn init(gpa: Allocator, pairs: []const Inner.Pair) Allocator.Error!Self {
            const map = try Inner.from_dedup(gpa, pairs);
            assert(map.keys.items.len <= pairs.len);
            return .{ .map = map };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.map.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var keys = try self.map.keys.clone(gpa);
            errdefer keys.deinit(gpa);
            const values = try gpa.dupe(Address, self.map.values);
            assert(values.len == keys.items.len);
            return .{ .map = .{ .keys = keys, .values = values } };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.map.eql(b.map);
        }

        /// The address recorded for `peer`, if any.
        pub fn get(self: *const Self, peer: P) ?*const Address {
            return self.map.get_value(peer);
        }

        pub fn codec_config(peers: Set(P)) Cfg {
            return .exact(peers.items.len);
        }

        pub fn max_encode_size_for(peers: usize) usize {
            return Inner.encode_size_max(peers, Address.max_encode_size);
        }

        /// Whether the directory names exactly `peers`.
        pub fn matches(self: Self, peers: Set(P)) bool {
            return self.map.keys.eql(peers);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.map.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.map.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return .{ .map = try Inner.read(gpa, reader, .{ .range = cfg }) };
        }
    };
}

/// Primary and secondary peers of an epoch, owned (commonware's `TrackedPeers`).
/// `view` borrows them as the `p2p.TrackedPeers` managers take.
pub fn Tracked(comptime P: type) type {
    return struct {
        const Self = @This();

        primary: Set(P),
        secondary: Set(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.primary.deinit(gpa);
            self.secondary.deinit(gpa);
            self.* = undefined;
        }

        pub fn view(self: *const Self) p2p.TrackedPeers(P) {
            return .{
                .primary = .{ .items = self.primary.items },
                .secondary = .{ .items = self.secondary.items },
            };
        }
    };
}

/// Asserts `M` is a DKG manager: a p2p `Provider` that activates an epoch's peers with
/// `track(manager, epoch, peers, *const M.Directory) M.Error!void`.
pub fn assert_manager(comptime M: type) void {
    for ([_][]const u8{ "PublicKey", "Directory", "Error", "track", "peer_set", "subscribe" }) |
        decl,
    | {
        if (!@hasDecl(M, decl)) @compileError(@typeName(M) ++ " lacks dkg Manager." ++ decl);
    }
}

fn ReturnType(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}

/// The manager type behind `M`, which may be the manager or a pointer to it.
fn Base(comptime M: type) type {
    return switch (@typeInfo(M)) {
        .pointer => |info| info.child,
        else => M,
    };
}

/// Adapts a key-only p2p `Manager` (commonware's blanket `impl Manager for M`): it ignores the
/// directory and never fails.
pub fn KeyOnlyManager(comptime M: type) type {
    p2p.assert_manager(Base(M));
    return struct {
        const Self = @This();
        pub const PublicKey = Base(M).PublicKey;
        pub const Directory = Unit;
        pub const Error = error{};

        manager: M,

        pub fn init(manager: M) Self {
            return .{ .manager = manager };
        }

        /// Activates `peers` for `epoch`; the epoch is the peer-set ID.
        pub fn track(
            self: *Self,
            epoch: Epoch,
            peers: p2p.TrackedPeers(PublicKey),
            directory: *const Unit,
        ) Error!void {
            _ = directory;
            _ = self.manager.track(epoch.get(), peers);
        }

        pub fn peer_set(self: *Self, gpa: Allocator, id: u64) ReturnType(Base(M).peer_set) {
            return self.manager.peer_set(gpa, id);
        }

        pub fn subscribe(self: *Self) ReturnType(Base(M).subscribe) {
            return self.manager.subscribe();
        }
    };
}

/// Adapts an addressable p2p manager to DKG's key-only peer sets. `track` resolves each tracked
/// peer through the epoch's `Addresses`, preserving primary and secondary roles, and fails with
/// `MissingAddress` without activating any peer if the directory omits a tracked peer
/// (`missing_address` names it).
pub fn AddressableManager(comptime M: type) type {
    for ([_][]const u8{ "PublicKey", "track", "overwrite", "peer_set", "subscribe" }) |decl| {
        if (!@hasDecl(Base(M), decl)) {
            @compileError(@typeName(M) ++ " lacks AddressableManager." ++ decl);
        }
    }
    return struct {
        const Self = @This();
        pub const PublicKey = Base(M).PublicKey;
        pub const Directory = Addresses(PublicKey);
        pub const Error = error{ MissingAddress, OutOfMemory };
        const PeerMap = p2p.AddressableTrackedPeers(PublicKey).PeerMap;

        gpa: Allocator,
        manager: M,

        pub fn init(gpa: Allocator, manager: M) Self {
            return .{ .gpa = gpa, .manager = manager };
        }

        pub fn track(
            self: *Self,
            epoch: Epoch,
            peers: p2p.TrackedPeers(PublicKey),
            directory: *const Directory,
        ) Error!void {
            const primary = try resolve(PublicKey, self.gpa, peers.primary.items, directory);
            defer self.gpa.free(primary);
            const secondary = try resolve(PublicKey, self.gpa, peers.secondary.items, directory);
            defer self.gpa.free(secondary);
            assert(primary.len == peers.primary.items.len);
            _ = self.manager.track(epoch.get(), .{
                .primary = PeerMap.init(primary),
                .secondary = PeerMap.init(secondary),
            });
        }

        pub fn peer_set(self: *Self, gpa: Allocator, id: u64) ReturnType(Base(M).peer_set) {
            return self.manager.peer_set(gpa, id);
        }

        pub fn subscribe(self: *Self) ReturnType(Base(M).subscribe) {
            return self.manager.subscribe();
        }
    };
}

/// The first of `peers` (primary, then secondary) that `directory` omits, if any: the key
/// commonware's `MissingAddress` error carries.
pub fn missing_address(
    comptime P: type,
    peers: p2p.TrackedPeers(P),
    directory: *const Addresses(P),
) ?P {
    for ([_][]const P{ peers.primary.items, peers.secondary.items }) |list| {
        for (list) |peer| if (directory.get(peer) == null) return peer;
    }
    return null;
}

fn resolve(
    comptime P: type,
    gpa: Allocator,
    peers: []const P,
    directory: *const Addresses(P),
) error{ MissingAddress, OutOfMemory }![]p2p.AddressableTrackedPeers(P).PeerMap.Entry {
    const Entry = p2p.AddressableTrackedPeers(P).PeerMap.Entry;
    const entries = try gpa.alloc(Entry, peers.len);
    errdefer gpa.free(entries);
    for (peers, entries) |peer, *entry| {
        const address = directory.get(peer) orelse return error.MissingAddress;
        entry.* = .{ .key = peer, .value = address.* };
    }
    assert(entries.len == peers.len);
    return entries;
}

test {
    _ = @import("network_test.zig");
}
