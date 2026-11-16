//! Shared setup for the shard engine tests (commonware `marshal/coding/shards/engine.rs`
//! tests): the test scheme and provider, a `Fixture` of running engines on the simulated
//! network, an `Unstarted` engine driven through its handlers, and helpers.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const codec = @import("codec");
const coding = @import("coding");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");

const engine_module = @import("engine.zig");
const test_block = @import("../test_block.zig");
const types = @import("../types.zig");
const consensus_types = @import("../../../types.zig");

pub const metrics = runtime.telemetry.metrics;
pub const oneshot = utils.channel.oneshot;
pub const ed25519 = cryptography.ed25519;
pub const Sha256 = cryptography.Sha256;
pub const Key = ed25519.PublicKey;
pub const PrivateKey = ed25519.PrivateKey;
pub const Net = p2p.simulated.Network(Key);
pub const Epoch = consensus_types.Epoch;
pub const View = consensus_types.View;
pub const Round = consensus_types.Round;
pub const B = test_block.EmptyBlock;
pub const C = test_block.RS;
pub const H = Sha256;
pub const Coded = test_block.Coded;
pub const ShardType = types.Shard(B, C, H);
pub const Commitment = Coded.Commitment;
pub const gpa = testing.allocator;

/// commonware's `TestSubject`: a message signed under the base namespace.
pub const TestSubject = struct {
    pub const Namespace = cryptography.certificate.BytesNamespace;

    bytes: []const u8,

    pub fn namespace(_: TestSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(self: TestSubject, allocator: Allocator) Allocator.Error![]u8 {
        return allocator.dupe(u8, self.bytes);
    }
};

pub const Scheme = ed25519.certificate.Scheme(TestSubject, utils.N3f1);
pub const scheme_namespace = "_COMMONWARE_SHARD_ENGINE_TEST";

/// Maps each epoch to a scheme (commonware `MultiEpochProvider`).
pub const MultiEpochProvider = struct {
    const Entry = struct { epoch: u64, scheme: Scheme };

    entries: std.ArrayList(Entry) = .empty,

    pub fn scheme(provider: *const MultiEpochProvider, epoch: Epoch) ?*const Scheme {
        for (provider.entries.items) |*entry| {
            if (entry.epoch == epoch.get()) return &entry.scheme;
        }
        return null;
    }

    pub fn add(provider: *MultiEpochProvider, epoch: u64, value: Scheme) !void {
        assert(provider.scheme(.new(epoch)) == null);
        var owned = value;
        errdefer owned.deinit(gpa);
        try provider.entries.append(gpa, .{ .epoch = epoch, .scheme = owned });
    }

    pub fn deinit(provider: *MultiEpochProvider) void {
        for (provider.entries.items) |*entry| entry.scheme.deinit(gpa);
        provider.entries.deinit(gpa);
    }
};

/// The provider handle an engine holds (borrowed).
pub const ProviderRef = struct {
    provider: *const MultiEpochProvider,

    pub fn scheme(ref: ProviderRef, epoch: Epoch) ?*const Scheme {
        return ref.provider.scheme(epoch);
    }
};

pub const Types = struct {
    pub const Block = B;
    pub const Coding = C;
    pub const Hasher = H;
    pub const Provider = ProviderRef;
    pub const Blocker = Net.Control;
    pub const PeerProvider = Net.Manager;
    pub const Network = Net;
    pub const Strategy = parallel.Sequential;
};

pub const ShardEngine = engine_module.Engine(Types);
pub const Mailbox = ShardEngine.Mailbox;

/// Per-peer rate, high enough not to interfere.
pub const test_quota = p2p.Quota.per_second(1_024);
/// Latency of every default link.
pub const link_latency_ms = 50;
pub const peers_max = 16;
pub const default_link: p2p.simulated.Link = .{
    .latency = utils.Duration.from_millis(link_latency_ms),
    .jitter = utils.Duration.from_millis(0),
    .success_rate = 1.0,
};

pub fn sleep_ms(io: Io, ms: u64) !void {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

pub fn run_deterministic(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

/// commonware's `network_config`: frames sized by the coding buffer's bound.
pub fn network_config(participants: usize, max_peers_per_set: usize) p2p.simulated.Config {
    const payload = types.max_buffer_payload_size(
        B,
        C,
        H,
        @intCast(participants),
        B.max_encode_size,
    );
    assert(max_peers_per_set >= participants);
    return .{
        .max_size = p2p.max_message_size(&.{payload}),
        .max_peers_per_set = max_peers_per_set,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    };
}

pub fn at(view: u64) Round {
    return .new(.zero(), .new(view));
}

pub fn round(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

/// The block at `height` with `timestamp`, coded for `config`.
pub fn encode(config: coding.Config, height: u64, timestamp: u64) !Coded {
    return test_block.encode_block(gpa, B.init(.empty, .new(height), timestamp), config);
}

/// commonware's `make_block(id)`: height and timestamp `id`.
pub fn make_block(config: coding.Config, id: u64) !Coded {
    return encode(config, id, id);
}

pub fn commitment_of(config: coding.Config, id: u64) !Commitment {
    var block = try make_block(config, id);
    defer block.deinit(gpa);
    return block.commitment();
}

/// A copy of `block`'s shard at `index`.
pub fn shard_of(block: *const Coded, index: usize) !ShardType {
    return (try block.shard(gpa, @intCast(index))) orelse error.MissingShard;
}

/// `block`'s shard at `index`, retargeted at `commitment`.
pub fn shard_for(block: *const Coded, index: usize, commitment: Commitment) !ShardType {
    var shard = try shard_of(block, index);
    shard.commitment_value = commitment;
    return shard;
}

pub fn encode_shard(shard: *const ShardType) ![]u8 {
    return codec.encode(ShardType, gpa, shard.*);
}

/// Sends `shard` (borrowed) from `sender` to `to`.
pub fn send_shard(sender: *Net.Sender, to: Key, shard: *const ShardType) !void {
    const bytes = try encode_shard(shard);
    defer gpa.free(bytes);
    const attempted = try sender.send(.{ .one = to }, &.{bytes}, true);
    gpa.free(attempted);
}

pub fn sorted(peers: []const Key) ![]Key {
    const copy = try gpa.dupe(Key, peers);
    std.sort.pdq(Key, copy, {}, Key.less_than);
    return copy;
}

/// Tracks `primary` and `secondary` at peer-set id `id`.
pub fn track(network: *Net, id: u64, primary: []const Key, secondary: []const Key) !void {
    const tracked: p2p.TrackedPeers(Key) = .{
        .primary = .init(try sorted(primary)),
        .secondary = .init(try sorted(secondary)),
    };
    defer gpa.free(tracked.primary.items);
    defer gpa.free(tracked.secondary.items);
    const feedback = network.oracle().manager().track(id, tracked);
    try testing.expectEqual(p2p.Feedback.ok, feedback);
}

pub fn is_blocked(network: *Net, blocker: Key, blocked: Key) !bool {
    const pairs = try network.oracle().blocked(gpa);
    defer gpa.free(pairs);
    for (pairs) |pair| {
        if (pair.origin.eql(blocker) and pair.recipient.eql(blocked)) return true;
    }
    return false;
}

/// commonware `assert_blocked`.
pub fn expect_blocked(network: *Net, blocker: Key, blocked: Key) !void {
    try testing.expect(try is_blocked(network, blocker, blocked));
}

pub fn blocked_count(network: *Net) !usize {
    const pairs = try network.oracle().blocked(gpa);
    defer gpa.free(pairs);
    return pairs.len;
}

/// Keys from seeds `first..first + count`, sorted by public key.
pub fn sorted_keys(keys: []PrivateKey, peers: []Key, first: usize) void {
    assert(keys.len == peers.len);
    for (keys, 0..) |*key, index| key.* = .from_seed(first + index);
    const by_key = struct {
        fn less(_: void, a: PrivateKey, b: PrivateKey) bool {
            return Key.less_than({}, a.public_key(), b.public_key());
        }
    }.less;
    std.sort.pdq(PrivateKey, keys, {}, by_key);
    for (keys, peers) |key, *peer| peer.* = key.public_key();
}

fn RecvResult(comptime R: type) type {
    return @typeInfo(@TypeOf(R.recv)).@"fn".return_type.?;
}

fn RecvValue(comptime R: type) type {
    return @typeInfo(RecvResult(R)).error_union.payload;
}

/// Frees a received value: a coded block, a network message, or nothing.
pub fn free_value(value: anytype) void {
    const T = @TypeOf(value);
    if (T == void) return;
    if (comptime @hasDecl(T, "discard")) return value.discard();
    var owned = value;
    owned.deinit();
}

/// The next value of `receiver` within `timeout_ms`, or null on timeout (commonware's
/// `select!` against `context.sleep`). A closed receiver returns its error.
pub fn recv_within(io: Io, receiver: anytype, timeout_ms: u64) !?RecvValue(@TypeOf(receiver.*)) {
    const R = @TypeOf(receiver.*);
    const Outcome = union(enum) {
        received: RecvResult(R),
        timeout: Io.Cancelable!void,
    };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    try select.concurrent(.received, R.recv, .{receiver});
    const duration: Io.Duration = .fromMilliseconds(@intCast(timeout_ms));
    select.concurrent(.timeout, Io.sleep, .{ io, duration, .awake }) catch |err| {
        select.cancelDiscard();
        return err;
    };
    const first = try select.await();
    while (select.cancel()) |rest| {
        if (rest == .received) if (rest.received) |value| free_value(value) else |_| {};
    }
    return switch (first) {
        .received => |result| try result,
        .timeout => null,
    };
}

/// Waits up to five seconds for a subscription to resolve.
pub fn expect_resolves(io: Io, receiver: anytype) !RecvValue(@TypeOf(receiver.*)) {
    return (try recv_within(io, receiver, 5_000)) orelse error.Timeout;
}

/// commonware's test `Fixture`: primary peers (participants) and secondary peers
/// (non-participants), all linked, each running a shard engine on channel 0.
pub const Fixture = struct {
    pub const Options = struct {
        primary: usize = 4,
        /// A primary peer whose scheme reports membership but cannot sign.
        shareless_member: ?usize = null,
        secondary: usize = 0,
        /// Peers introduced after setup (sizes the network's peer sets).
        future: usize = 0,
        /// Additional epochs that use the fixture's participant set.
        epochs: []const u64 = &.{},
        link: p2p.simulated.Link = default_link,
        peer_buffer_size: usize = 64,
        records: usize = 16,
    };

    io: Io,
    options: Options,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: *metrics.Registry,
    keys: [peers_max]PrivateKey = undefined,
    peers: [peers_max]Key = undefined,
    providers: [peers_max]MultiEpochProvider = @splat(.{}),
    mailboxes: [peers_max]?Mailbox = @splat(null),
    senders: [peers_max]?Net.Sender = @splat(null),
    engines: [peers_max]?*ShardEngine = @splat(null),
    tasks: [peers_max]?Io.Future(ShardEngine.Error!void) = @splat(null),
    coding_config: coding.Config,

    pub fn count(fixture: *const Fixture) usize {
        return fixture.options.primary + fixture.options.secondary;
    }

    pub fn init(io: Io, options: Options) !*Fixture {
        const total = options.primary + options.secondary;
        assert(total + options.future <= peers_max and options.primary >= 4);
        const fixture = try gpa.create(Fixture);
        errdefer gpa.destroy(fixture);
        const registry = try gpa.create(metrics.Registry);
        registry.* = .init(gpa);
        const max_peers_per_set = options.primary + @max(options.secondary, options.future);
        const config = network_config(options.primary, max_peers_per_set);
        const network = try Net.init(gpa, io, config);
        fixture.* = .{
            .io = io,
            .options = options,
            .network = network,
            .network_task = try io.concurrent(Net.run, .{network}),
            .registry = registry,
            .coding_config = types.coding_config_for_participants(@intCast(options.primary)),
        };
        const primary = options.primary;
        sorted_keys(fixture.keys[0..primary], fixture.peers[0..primary], 0);
        sorted_keys(fixture.keys[primary..total], fixture.peers[primary..total], primary);
        try fixture.link_all();
        try track(network, 0, fixture.peers[0..primary], fixture.peers[primary..total]);
        for (0..total) |index| try fixture.spawn(index);
        // Let every engine apply the initial peer set.
        try sleep_ms(io, 1);
        return fixture;
    }

    fn link_all(fixture: *Fixture) !void {
        const oracle = fixture.network.oracle();
        for (fixture.peers[0..fixture.count()]) |from| {
            for (fixture.peers[0..fixture.count()]) |to| {
                if (!from.eql(to)) try oracle.add_link(from, to, fixture.options.link);
            }
        }
    }

    pub fn participants(fixture: *const Fixture) !Scheme.Participants {
        return Scheme.Participants.init(gpa, fixture.peers[0..fixture.options.primary]);
    }

    /// The scheme peer `index` runs in every epoch.
    fn scheme_for(fixture: *const Fixture, index: usize, initial: bool) !Scheme {
        const set = try fixture.participants();
        if (index >= fixture.options.primary) {
            return Scheme.verifier(gpa, scheme_namespace, set);
        }
        if (initial and fixture.options.shareless_member == index) {
            return (try Scheme.member(gpa, scheme_namespace, set, fixture.peers[index])).?;
        }
        return (try Scheme.signer(gpa, scheme_namespace, set, fixture.keys[index])).?;
    }

    fn spawn(fixture: *Fixture, index: usize) !void {
        try fixture.providers[index].add(0, try fixture.scheme_for(index, true));
        for (fixture.options.epochs) |epoch| {
            try fixture.providers[index].add(epoch, try fixture.scheme_for(index, false));
        }
        const oracle = fixture.network.oracle();
        const peer = fixture.peers[index];
        const registered = try oracle.control(peer).register(0, test_quota);
        const scope = metrics.Scope.init(fixture.registry).child("peer")
            .with_attribute("index", index);
        const created = try ShardEngine.init(gpa, fixture.io, &scope, .{
            .scheme_provider = .{ .provider = &fixture.providers[index] },
            .blocker = oracle.control(peer),
            .block_codec_config = {},
            .strategy = parallel.sequential,
            .mailbox_size = 1024,
            .peer_buffer_size = fixture.options.peer_buffer_size,
            .records = fixture.options.records,
            .peer_provider = oracle.manager(),
        });
        fixture.mailboxes[index] = created.mailbox;
        fixture.senders[index] = registered.sender.clone();
        fixture.engines[index] = created.engine;
        fixture.tasks[index] = try created.engine.start(registered.sender, registered.receiver);
    }

    pub fn mailbox(fixture: *const Fixture, index: usize) Mailbox {
        return fixture.mailboxes[index].?;
    }

    pub fn sender(fixture: *Fixture, index: usize) *Net.Sender {
        return &fixture.senders[index].?;
    }

    /// Sends `shard` from peer `from` to peer `to` over the network.
    pub fn send(fixture: *Fixture, from: usize, to: usize, shard: *const ShardType) !void {
        try send_shard(fixture.sender(from), fixture.peers[to], shard);
    }

    pub fn latency(fixture: *const Fixture, multiple: u64) !void {
        try sleep_ms(fixture.io, multiple * fixture.options.link.latency.as_millis_u64());
    }

    /// Each engine's value of the gauge `name` (commonware `gauges`).
    pub fn gauges(fixture: *Fixture, name: []const u8, out: []i64) !usize {
        const text = try fixture.registry.encode(gpa);
        defer gpa.free(text);
        var samples = metrics.metric_samples(text, name);
        var found: usize = 0;
        while (samples.next()) |sample| : (found += 1) {
            out[found] = try std.fmt.parseInt(i64, sample.value, 10);
        }
        return found;
    }

    pub fn deinit(fixture: *Fixture) void {
        for (0..fixture.count()) |index| {
            if (fixture.tasks[index]) |*future| {
                future.cancel(fixture.io) catch |err| std.debug.panic("engine: {t}", .{err});
            }
            if (fixture.mailboxes[index]) |*value| value.deinit();
            if (fixture.senders[index]) |*value| value.deinit();
            fixture.providers[index].deinit();
        }
        fixture.network.close();
        fixture.network_task.await(fixture.io) catch |err| std.debug.panic("run: {t}", .{err});
        fixture.network.deinit();
        fixture.registry.deinit();
        gpa.destroy(fixture.registry);
        gpa.destroy(fixture);
    }
};

/// commonware's `unstarted`: an engine for the participant at `index` of `count` peers that
/// tests drive through its handlers. Every participant is a tracked primary.
pub const Unstarted = struct {
    pub const Options = struct {
        count: usize = 4,
        index: usize = 0,
        records: usize = 16,
        /// Run a member scheme (knows its index, cannot sign) instead of a signer.
        member: bool = false,
    };

    io: Io,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: *metrics.Registry,
    count: usize,
    index: usize,
    keys: [peers_max]PrivateKey = undefined,
    peers: [peers_max]Key = undefined,
    provider: MultiEpochProvider = .{},
    engine: *ShardEngine = undefined,
    mailbox: Mailbox = undefined,
    receiver: ?Net.Receiver = null,
    observers: [peers_max]?Net.Registered = @splat(null),
    coding_config: coding.Config,

    pub fn init(io: Io, options: Options) !*Unstarted {
        assert(options.count <= peers_max and options.index < options.count);
        const self = try gpa.create(Unstarted);
        errdefer gpa.destroy(self);
        const registry = try gpa.create(metrics.Registry);
        registry.* = .init(gpa);
        const network = try Net.init(gpa, io, network_config(options.count, options.count));
        self.* = .{
            .io = io,
            .network = network,
            .network_task = try io.concurrent(Net.run, .{network}),
            .registry = registry,
            .count = options.count,
            .index = options.index,
            .coding_config = types.coding_config_for_participants(@intCast(options.count)),
        };
        sorted_keys(self.keys[0..self.count], self.peers[0..self.count], 0);
        const set = try Scheme.Participants.init(gpa, self.peers[0..self.count]);
        const scheme = if (options.member)
            (try Scheme.member(gpa, scheme_namespace, set, self.me())).?
        else
            (try Scheme.signer(gpa, scheme_namespace, set, self.keys[options.index])).?;
        try self.provider.add(0, scheme);
        try self.create(options.records);
        return self;
    }

    fn create(self: *Unstarted, records: usize) !void {
        const control = self.network.oracle().control(self.me());
        const registered = try control.register(0, test_quota);
        self.receiver = registered.receiver;
        const scope = metrics.Scope.init(self.registry).child("engine");
        const created = try ShardEngine.init(gpa, self.io, &scope, .{
            .scheme_provider = .{ .provider = &self.provider },
            .blocker = control,
            .block_codec_config = {},
            .strategy = parallel.sequential,
            .mailbox_size = 16,
            .peer_buffer_size = 4,
            .records = records,
            .peer_provider = self.network.oracle().manager(),
        });
        self.engine = created.engine;
        self.mailbox = created.mailbox;
        self.engine.attach_sender(registered.sender);
        try self.engine.update_primary_peers(self.peers[0..self.count]);
    }

    pub fn me(self: *const Unstarted) Key {
        return self.peers[self.index];
    }

    /// Registers peer `index` to observe the engine's gossip, links the engine to it, and
    /// tracks every participant (commonware's observer setup).
    pub fn observe(self: *Unstarted, index: usize) !*Net.Receiver {
        assert(index != self.index and self.observers[index] == null);
        const oracle = self.network.oracle();
        self.observers[index] = try oracle.control(self.peers[index]).register(0, test_quota);
        try oracle.add_link(self.me(), self.peers[index], default_link);
        try self.track_all();
        return &self.observers[index].?.receiver;
    }

    pub fn track_all(self: *Unstarted) !void {
        try track(self.network, 0, self.peers[0..self.count], &.{});
        try sleep_ms(self.io, 10);
    }

    pub fn shard(self: *Unstarted, from: usize, value: ShardType) !void {
        try self.engine.handle_network_shard(self.peers[from], value);
    }

    pub fn gather(self: *Unstarted, commitment: Commitment, at_round: Round) !void {
        try self.engine.handle_gather(commitment, at_round);
    }

    pub fn has_record(self: *const Unstarted, commitment: Commitment) bool {
        return self.engine.records.contains(commitment);
    }

    pub fn buffered(self: *const Unstarted, from: usize, commitment: Commitment) usize {
        return self.engine.buffered(self.peers[from], commitment);
    }

    pub fn subscribe_assigned(self: *Unstarted, commitment: Commitment) !oneshot.Receiver(void) {
        const pair = try oneshot.channel(void, gpa, self.io);
        try self.engine.subscribe_assigned(commitment, pair.sender);
        return pair.receiver;
    }

    pub fn subscribe(self: *Unstarted, commitment: Commitment) !oneshot.Receiver(Coded) {
        const pair = try oneshot.channel(Coded, gpa, self.io);
        try self.engine.subscribe_commitment(commitment, pair.sender);
        return pair.receiver;
    }

    pub fn deinit(self: *Unstarted) void {
        self.engine.destroy();
        self.mailbox.deinit();
        if (self.receiver) |*value| value.deinit();
        for (&self.observers) |*observer| if (observer.*) |*value| value.deinit();
        self.provider.deinit();
        self.network.close();
        self.network_task.await(self.io) catch |err| std.debug.panic("run: {t}", .{err});
        self.network.deinit();
        self.registry.deinit();
        gpa.destroy(self.registry);
        gpa.destroy(self);
    }
};

/// Expects `receiver` to hold nothing yet.
pub fn expect_pending(receiver: anytype) !void {
    const value = receiver.try_recv() catch |err| return testing.expectEqual(error.Empty, err);
    free_value(value);
    return error.TestUnexpectedResult;
}

/// Expects `receiver` to be closed without a value.
pub fn expect_closed(receiver: anytype) !void {
    const value = receiver.try_recv() catch |err| return testing.expectEqual(error.Closed, err);
    free_value(value);
    return error.TestUnexpectedResult;
}

/// Expects the network message `message` (owned) from `from` to carry `shard`.
pub fn expect_gossip(message: anytype, from: Key, shard: *const ShardType) !void {
    var owned = message;
    defer owned.deinit();
    try testing.expect(owned.peer.eql(from));
    const bytes = try encode_shard(shard);
    defer gpa.free(bytes);
    try testing.expectEqualSlices(u8, bytes, owned.payload);
}
