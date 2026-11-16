//! Shard engine tests, ported from commonware `marshal/coding/shards/engine.rs`, on the
//! simulated network and the deterministic runtime.

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

const metrics = runtime.telemetry.metrics;
const ed25519 = cryptography.ed25519;
const Sha256 = cryptography.Sha256;
const Key = ed25519.PublicKey;
const PrivateKey = ed25519.PrivateKey;
const Net = p2p.simulated.Network(Key);
const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const Round = consensus_types.Round;
const B = test_block.EmptyBlock;
const C = test_block.RS;
const H = Sha256;
const Coded = test_block.Coded;
const gpa = testing.allocator;

/// commonware's `TestSubject`: a message signed under the base namespace.
const TestSubject = struct {
    pub const Namespace = cryptography.certificate.BytesNamespace;

    bytes: []const u8,

    pub fn namespace(_: TestSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(self: TestSubject, allocator: Allocator) Allocator.Error![]u8 {
        return allocator.dupe(u8, self.bytes);
    }
};

const Scheme = ed25519.certificate.Scheme(TestSubject, utils.N3f1);
const scheme_namespace = "_COMMONWARE_SHARD_ENGINE_TEST";

/// Maps each epoch to a scheme (commonware `MultiEpochProvider`). Borrowed by the engines.
const MultiEpochProvider = struct {
    const Entry = struct { epoch: u64, scheme: Scheme };

    entries: std.ArrayList(Entry) = .empty,

    pub fn scheme(provider: *const MultiEpochProvider, epoch: Epoch) ?*const Scheme {
        for (provider.entries.items) |*entry| {
            if (entry.epoch == epoch.get()) return &entry.scheme;
        }
        return null;
    }

    fn add(provider: *MultiEpochProvider, epoch: u64, value: Scheme) !void {
        assert(provider.scheme(.new(epoch)) == null);
        try provider.entries.append(gpa, .{ .epoch = epoch, .scheme = value });
    }

    fn deinit(provider: *MultiEpochProvider) void {
        for (provider.entries.items) |*entry| entry.scheme.deinit(gpa);
        provider.entries.deinit(gpa);
    }
};

/// The provider handle an engine holds.
const ProviderRef = struct {
    provider: *const MultiEpochProvider,

    pub fn scheme(ref: ProviderRef, epoch: Epoch) ?*const Scheme {
        return ref.provider.scheme(epoch);
    }
};

const Types = struct {
    pub const Block = B;
    pub const Coding = C;
    pub const Hasher = H;
    pub const Provider = ProviderRef;
    pub const Blocker = Net.Control;
    pub const PeerProvider = Net.Manager;
    pub const Network = Net;
    pub const Strategy = parallel.Sequential;
};

const ShardEngine = engine_module.Engine(Types);
const Mailbox = ShardEngine.Mailbox;

/// Per-peer rate, high enough not to interfere.
const test_quota = p2p.Quota.per_second(1_024);
/// Latency of every default link.
const link_latency_ms = 50;
const peers_max = 16;

fn sleep_ms(io: Io, ms: u64) !void {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

fn run_deterministic(comptime function: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()}));
}

/// commonware's `network_config`: frames sized by the coding buffer's bound.
fn network_config(participants: usize, max_peers_per_set: usize) p2p.simulated.Config {
    const payload = types.max_buffer_payload_size(
        B,
        C,
        H,
        @intCast(participants),
        B.max_encode_size,
    );
    return .{
        .max_size = p2p.max_message_size(&.{payload}),
        .max_peers_per_set = max_peers_per_set,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    };
}

/// commonware's test `Fixture`: primary peers (participants) and secondary peers
/// (non-participants), all linked, each running a shard engine on channel 0.
const Fixture = struct {
    const Options = struct {
        primary: usize = 4,
        secondary: usize = 0,
        peer_buffer_size: usize = 64,
        records: usize = 16,
        link: p2p.simulated.Link = .{
            .latency = utils.Duration.from_millis(link_latency_ms),
            .jitter = utils.Duration.from_millis(0),
            .success_rate = 1.0,
        },
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
    engines: [peers_max]?Io.Future(ShardEngine.Error!void) = @splat(null),
    coding_config: coding.Config,

    fn count(fixture: *const Fixture) usize {
        return fixture.options.primary + fixture.options.secondary;
    }

    fn init(io: Io, options: Options) !*Fixture {
        const total = options.primary + options.secondary;
        assert(total <= peers_max and options.primary >= 4);
        const fixture = try gpa.create(Fixture);
        errdefer gpa.destroy(fixture);
        const registry = try gpa.create(metrics.Registry);
        registry.* = .init(gpa);
        const network = try Net.init(gpa, io, network_config(options.primary, total));
        fixture.* = .{
            .io = io,
            .options = options,
            .network = network,
            .network_task = try io.concurrent(Net.run, .{network}),
            .registry = registry,
            .coding_config = types.coding_config_for_participants(@intCast(options.primary)),
        };
        fixture.make_keys();
        try fixture.link_all();
        try fixture.track();
        for (0..total) |index| try fixture.spawn(index);
        // Let every engine apply the initial peer set.
        try sleep_ms(io, 1);
        return fixture;
    }

    /// Primary keys from seeds `0..primary` sorted, then secondary keys sorted.
    fn make_keys(fixture: *Fixture) void {
        const primary = fixture.options.primary;
        for (0..fixture.count()) |index| fixture.keys[index] = .from_seed(index);
        const by_key = struct {
            fn less(_: void, a: PrivateKey, b: PrivateKey) bool {
                return Key.less_than({}, a.public_key(), b.public_key());
            }
        }.less;
        std.sort.pdq(PrivateKey, fixture.keys[0..primary], {}, by_key);
        std.sort.pdq(PrivateKey, fixture.keys[primary..fixture.count()], {}, by_key);
        for (0..fixture.count()) |index| fixture.peers[index] = fixture.keys[index].public_key();
    }

    fn link_all(fixture: *Fixture) !void {
        const oracle = fixture.network.oracle();
        for (fixture.peers[0..fixture.count()]) |from| {
            for (fixture.peers[0..fixture.count()]) |to| {
                if (!from.eql(to)) try oracle.add_link(from, to, fixture.options.link);
            }
        }
    }

    fn track(fixture: *Fixture) !void {
        const primary = fixture.peers[0..fixture.options.primary];
        const secondary = fixture.peers[fixture.options.primary..fixture.count()];
        const tracked: p2p.TrackedPeers(Key) = .{
            .primary = .init(try sorted(primary)),
            .secondary = .init(try sorted(secondary)),
        };
        defer gpa.free(tracked.primary.items);
        defer gpa.free(tracked.secondary.items);
        const feedback = fixture.network.oracle().manager().track(0, tracked);
        try testing.expectEqual(p2p.Feedback.ok, feedback);
    }

    fn sorted(peers: []const Key) ![]Key {
        const copy = try gpa.dupe(Key, peers);
        std.sort.pdq(Key, copy, {}, Key.less_than);
        return copy;
    }

    fn participants(fixture: *const Fixture) !Scheme.Participants {
        return Scheme.Participants.init(gpa, fixture.peers[0..fixture.options.primary]);
    }

    fn spawn(fixture: *Fixture, index: usize) !void {
        const set = try fixture.participants();
        const scheme = if (index < fixture.options.primary)
            (try Scheme.signer(gpa, scheme_namespace, set, fixture.keys[index])).?
        else
            try Scheme.verifier(gpa, scheme_namespace, set);
        try fixture.providers[index].add(0, scheme);
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
        fixture.engines[index] = try created.engine.start(registered.sender, registered.receiver);
    }

    fn mailbox(fixture: *const Fixture, index: usize) Mailbox {
        return fixture.mailboxes[index].?;
    }

    fn deinit(fixture: *Fixture) void {
        for (0..fixture.count()) |index| {
            if (fixture.engines[index]) |*future| {
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

fn round(epoch: u64, view: u64) Round {
    return .new(.new(epoch), .new(view));
}

fn encode(fixture: *const Fixture, height: u64, timestamp: u64) !Coded {
    const inner = B.init(.empty, .new(height), timestamp);
    return test_block.encode_block(gpa, inner, fixture.coding_config);
}

/// Waits for the local assigned shard of `commitment` to verify.
fn expect_assigned(mailbox: Mailbox, commitment: Coded.Commitment) !void {
    var receiver = try mailbox.subscribe_assigned_shard_verified(commitment);
    defer receiver.deinit();
    try receiver.recv();
}

fn expect_reconstructed(mailbox: Mailbox, expected: *const Coded) !void {
    var got = (try mailbox.get(expected.commitment())) orelse return error.NotReconstructed;
    defer got.deinit(gpa);
    try testing.expect(got.commitment().eql(expected.commitment()));
    try testing.expectEqual(expected.height().get(), got.height().get());
}

test "e2e dispersal and reconstruction" {
    try run_deterministic(struct {
        fn run(io: Io) !void {
            const fixture = try Fixture.init(io, .{ .primary = 10 });
            defer fixture.deinit();
            var block = try encode(fixture, 1, 100);
            defer block.deinit(gpa);
            const commitment = block.commitment();
            const at = round(0, 1);
            try fixture.mailbox(0).disperse(at, block.clone());
            // Inform every other peer of the commitment so it processes the shards.
            for (1..10) |index| try fixture.mailbox(index).gather(commitment, at);
            try sleep_ms(io, link_latency_ms);
            for (0..10) |index| try expect_assigned(fixture.mailbox(index), commitment);
            try sleep_ms(io, link_latency_ms);
            for (0..10) |index| try expect_reconstructed(fixture.mailbox(index), &block);
        }
    }.run);
}
