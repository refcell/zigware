//! Tests of the DKG probe (commonware `glue/src/dkg/probe/mod.rs` `mod tests`), on the
//! deterministic runtime and the simulated network.
//!
//! commonware's harness serves the source probe from a marshal actor holding the source
//! boundaries; here a `MemorySource` holds the same boundary blocks and finalizations, keyed by
//! height, and answers as marshal's `get_finalization`, `get_block`, and latest finalization do.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const utils = @import("utils");
const probe = @import("mod.zig");
const wire = @import("wire.zig");
const mocks = @import("../tests/mocks.zig");
const network = @import("../network.zig");
const types = @import("../types.zig");

const gpa = testing.allocator;
const P = mocks.TestPublicKey;
const Digest = mocks.TestDigest;
const Sha256 = cryptography.sha256.Sha256;
const MinPk = mocks.TestBlsVariant;
const Set = utils.ordered.Set;
const Epoch = consensus.Epoch;
const Height = consensus.Height;
const simplex = consensus.simplex.types;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const certificate_mocks = cryptography.certificate.mocks;
const Net = p2p.simulated.Network(P);
const Quota = p2p.Quota;
const oneshot = utils.channel.oneshot;

/// commonware's `simplex::mocks::scheme`, the `TestScheme` of glue's DKG tests.
const Scheme = @import("../state_sync_test.zig").Scheme;
const Fixture = certificate_mocks.Fixture(Scheme);
const V = consensus.marshal.standard.Standard(mocks.TestBlock);
const Block = V.Block;
const Finalization = simplex.Finalization(Scheme, Digest);
const Proposal = simplex.Proposal(Digest);
const Info = types.EpochInfo(MinPk, P, utils.sequence.Unit);
const Message = wire.Message(Scheme, V);
const DkgManager = network.KeyOnlyManager(Net.Manager);

const boundary_channel: u64 = 1;
const blocks_per_epoch: u64 = 2;
const quota = Quota.per_second(1024);
const namespace = "_COMMONWARE_GLUE_DKG_TEST";
const link: p2p.simulated.Link = .{
    .latency = utils.Duration.from_millis(1),
    .jitter = .zero,
    .success_rate = 1.0,
};

/// The peer manager the probe activates the snapshot through; `fail` stands in for an
/// addressable manager whose directory lacks a tracked peer.
const Manager = struct {
    pub const PublicKey = P;
    pub const Directory = utils.sequence.Unit;
    pub const Error = error{MissingAddress};

    inner: DkgManager,
    fail: bool = false,

    pub fn track(
        self: *Manager,
        epoch: Epoch,
        peers: p2p.TrackedPeers(P),
        directory: *const Directory,
    ) Error!void {
        if (self.fail) return error.MissingAddress;
        self.inner.track(epoch, peers, directory) catch unreachable; // Proof: error{}.
    }
};

/// Boundary blocks and their finalizations, served by height as marshal serves them.
const MemorySource = struct {
    const Entry = struct { height: Height, block: Block, finalization: Finalization };

    entries: *std.ArrayList(Entry),

    pub fn latest_finalization(self: MemorySource, allocator: Allocator) !?Finalization {
        var latest: ?*const Entry = null;
        for (self.entries.items) |*entry| {
            if (latest == null or entry.height.get() > latest.?.height.get()) latest = entry;
        }
        const entry = latest orelse return null;
        return try entry.finalization.clone(allocator);
    }

    pub fn get_finalization(
        self: MemorySource,
        allocator: Allocator,
        height: Height,
    ) !?Finalization {
        const entry = self.find(height) orelse return null;
        return try entry.finalization.clone(allocator);
    }

    pub fn get_block(self: MemorySource, allocator: Allocator, height: Height) !?Block {
        _ = allocator;
        const entry = self.find(height) orelse return null;
        return entry.block.clone();
    }

    fn find(self: MemorySource, height: Height) ?*const Entry {
        for (self.entries.items) |*entry| {
            if (entry.height.get() == height.get()) return entry;
        }
        return null;
    }
};

const Probe = probe.Probe(struct {
    pub const Scheme = Scheme_;
    pub const Variant = V;
    pub const Manager = Manager_;
    pub const Source = MemorySource;
    pub const Blocker = Net.Control;
    pub const NetSender = Net.Sender;
    pub const NetReceiver = Net.Receiver;
});
const Scheme_ = Scheme;
const Manager_ = Manager;
const Artifact = Probe.Artifact;

fn sorted_participants(fixture: *const Fixture) !Set(P) {
    return Set(P).from_dedup(gpa, fixture.participants);
}

fn deal(seed: u64, participants: Set(P)) !fd.Output(MinPk, P) {
    var rng = utils.rng.TestRng.init(seed);
    const owned = try participants.clone(gpa);
    var dealt = try fd.deal(MinPk, P, utils.N3f1, gpa, &rng, .non_zero_counter, owned);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return dealt.output;
}

/// The info `seed`'s deal produces for `epoch` over `participants`.
fn epoch_info(epoch: u64, participants: Set(P)) !Info {
    var output = try deal(epoch, participants);
    errdefer output.deinit(gpa);
    var players = try participants.clone(gpa);
    errdefer players.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .new(epoch),
        .output = output,
        .players = players,
        .next_players = try participants.clone(gpa),
        .directory = .{},
    };
}

fn boundary_height(epoch: u64) Height {
    assert(epoch > 0);
    return .new(epoch * blocks_per_epoch - 1);
}

/// commonware `boundary_block`: the last block of `epoch - 1`, carrying `epoch`'s info.
fn boundary_block(epoch: u64, leader: P, info: Info) !Block {
    const height = boundary_height(epoch);
    const parent: Digest = if (height.is_zero()) .fill(0) else blk: {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, height.get() - 1, .big);
        break :blk Sha256.hash(&.{&bytes});
    };
    const context: mocks.TestContext = .{
        .round = .new(.new(epoch - 1), .new(1)),
        .leader = leader,
        .parent = .{ .zero(), parent },
    };
    const raw = mocks.TestBlock.init(context, parent, height, epoch);
    const block = try raw.with_payload(gpa, 16, .{ .epoch_info = info });
    return Block.compute(gpa, block);
}

fn finalize(fixture: *const Fixture, proposal: Proposal) !Finalization {
    const Finalize = simplex.Finalize(Scheme, Digest);
    var finalizes: [4]Finalize = undefined;
    for (fixture.schemes, &finalizes) |*scheme, *vote| {
        vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
    }
    const first = &fixture.schemes[0];
    return Finalization.from_votes(gpa, first, &finalizes, parallel.sequential);
}

/// commonware `boundary_finalization`: the finalization of `epoch`'s boundary block.
fn boundary_finalization(fixture: *const Fixture, epoch: u64, digest: Digest) !Finalization {
    return finalize(fixture, .init(.new(.new(epoch - 1), .new(1)), .zero(), digest));
}

/// commonware `latest_finalization`: a finalization within `epoch` committing to `digest`.
fn latest_finalization(fixture: *const Fixture, epoch: u64, digest: Digest) !Finalization {
    return finalize(fixture, .init(.new(.new(epoch), .new(2)), .new(1), digest));
}

fn latest_response(finalization: Finalization) ![]u8 {
    const message: Message = .{ .latest_response = finalization };
    return message.encode(gpa);
}

const Options = struct {
    /// Epochs whose boundaries the source serves.
    source_boundaries: []const u64 = &.{1},
    bootstrap_epoch: u64 = 0,
    /// The joiner's persisted floor epoch.
    floor_epoch: ?u64 = null,
    /// Whether the joiner's manager fails to activate the snapshot.
    fail_activation: bool = false,
};

const ProbeTask = Io.Future(anyerror!void);

const Harness = struct {
    io: Io,
    fixture: Fixture,
    participants: Set(P),
    net: *Net,
    net_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    entries: std.ArrayList(MemorySource.Entry) = .empty,
    source: Probe.Created = undefined,
    joiner_probe: *Probe = undefined,
    joiner: Probe.ProbeMailbox = undefined,
    tasks: [2]?ProbeTask = .{ null, null },
    rngs: [2]utils.rng.TestRng = .{ .init(1), .init(2) },
    /// A clone of the source probe's boundary sender.
    source_sender: Net.Sender = undefined,
    client: Net.Registered = undefined,
    backup: Net.Registered = undefined,
    /// The epoch-1 boundary block and its finalization and info.
    boundary: Block = undefined,
    boundary_finalization: Finalization = undefined,
    boundary_info: Info = undefined,

    fn init(h: *Harness, io: Io, options: Options) !void {
        var rng = utils.rng.TestRng.init(0);
        var fixture = try certificate_mocks.fixture(Scheme, gpa, &rng, namespace, 4);
        errdefer fixture.deinit(gpa);
        var participants = try sorted_participants(&fixture);
        errdefer participants.deinit(gpa);
        const peers: p2p.TrackedPeers(P) = .init_primary(.init(participants.items));
        const net = try Net.init_with_peers(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = 4,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        }, peers);
        errdefer net.deinit();
        h.* = .{
            .io = io,
            .fixture = fixture,
            .participants = participants,
            .net = net,
            .net_task = try io.concurrent(Net.run, .{net}),
        };
        const oracle = net.oracle();
        for (fixture.participants) |from| for (fixture.participants) |to| {
            if (!from.eql(to)) try oracle.add_link(from, to, link);
        };
        try h.init_boundaries(options);
        try h.start_probes(options);
        h.client = try oracle.control(fixture.participants[2]).register(boundary_channel, quota);
        h.backup = try oracle.control(fixture.participants[3]).register(boundary_channel, quota);
    }

    fn init_boundaries(h: *Harness, options: Options) !void {
        const leader = h.fixture.participants[0];
        h.boundary_info = try epoch_info(1, h.participants);
        h.boundary = try boundary_block(1, leader, h.boundary_info);
        h.boundary_finalization = try boundary_finalization(&h.fixture, 1, h.boundary.digest());
        for (options.source_boundaries) |epoch| {
            var info = try epoch_info(epoch, h.participants);
            defer info.deinit(gpa);
            var block = try boundary_block(epoch, leader, info);
            errdefer block.deinit();
            var finalization = try boundary_finalization(&h.fixture, epoch, block.digest());
            errdefer finalization.deinit(gpa);
            try h.entries.append(gpa, .{
                .height = boundary_height(epoch),
                .block = block,
                .finalization = finalization,
            });
        }
    }

    fn probe_config(h: *Harness, index: usize, options: Options) !Probe.Config {
        const oracle = h.net.oracle();
        const genesis = try epoch_info(0, h.participants);
        return .{
            .discovery = .{
                .manager = .{
                    .inner = .init(oracle.manager()),
                    .fail = options.fail_activation and index == 1,
                },
                .bootstrap = .{
                    .epoch = .new(options.bootstrap_epoch),
                    .participants = .{
                        .dealers = try genesis.players.clone(gpa),
                        .players = try genesis.players.clone(gpa),
                        .next_players = try genesis.next_players.clone(gpa),
                    },
                    .directory = .{},
                },
                .floor_epoch = if (index == 1 and options.floor_epoch != null)
                    .new(options.floor_epoch.?)
                else
                    null,
                .verifier = &h.fixture.schemes[index],
                .genesis = genesis,
                .blocker = oracle.control(h.fixture.participants[index]),
                .blocks_per_epoch = blocks_per_epoch,
                .block_cfg = {},
            },
            .retry_timeout_ns = 500 * std.time.ns_per_ms,
            .mailbox_size = 16,
        };
    }

    fn start_probes(h: *Harness, options: Options) !void {
        const oracle = h.net.oracle();
        for (0..2) |index| {
            const key = h.fixture.participants[index];
            const channel = try oracle.control(key).register(boundary_channel, quota);
            const config = try h.probe_config(index, options);
            const created = try Probe.init(gpa, h.io, config, channel.sender, channel.receiver);
            if (index == 0) {
                h.source_sender = channel.sender.clone();
                h.source = created;
                try created.mailbox.attach(.{ .entries = &h.entries });
            } else {
                h.joiner_probe = created.probe;
                h.joiner = created.mailbox;
            }
            h.tasks[index] = try h.io.concurrent(run_probe, .{ created.probe, &h.rngs[index] });
        }
    }

    fn run_probe(target: *Probe, rng: *utils.rng.TestRng) anyerror!void {
        return target.run(rng, parallel.sequential);
    }

    fn deinit(h: *Harness) void {
        for (&h.tasks) |*task| if (task.*) |*running| {
            running.cancel(h.io) catch {};
        };
        h.source.probe.deinit();
        h.source.mailbox.deinit();
        h.joiner_probe.deinit();
        h.joiner.deinit();
        h.source_sender.deinit();
        h.client.deinit();
        h.backup.deinit();
        h.net.close();
        h.net_task.await(h.io) catch {};
        h.net.deinit();
        for (h.entries.items) |*entry| {
            entry.block.deinit();
            entry.finalization.deinit(gpa);
        }
        h.entries.deinit(gpa);
        h.boundary.deinit();
        h.boundary_finalization.deinit(gpa);
        h.boundary_info.deinit(gpa);
        h.participants.deinit(gpa);
        h.fixture.deinit(gpa);
    }

    /// The default latest reply: a finalization within epoch 1 committing to the epoch-1
    /// boundary digest.
    fn target_finalization(h: *Harness) !Finalization {
        return latest_finalization(&h.fixture, 1, h.boundary.digest());
    }

    fn reply_latest(h: *Harness, from: *Net.Registered, finalization: *const Finalization) !void {
        const bytes = try latest_response(finalization.*);
        defer gpa.free(bytes);
        const joiner = h.fixture.participants[1];
        const sent = try from.sender.send(.{ .one = joiner }, &.{bytes}, false);
        gpa.free(sent);
    }

    /// Completes a sample for the target finalization from the client and backup peers.
    fn complete_target_sample(h: *Harness) !Finalization {
        var target = try h.target_finalization();
        errdefer target.deinit(gpa);
        try h.reply_latest(&h.client, &target);
        try h.reply_latest(&h.backup, &target);
        return target;
    }

    fn sleep_ms(h: *Harness, ms: u64) !void {
        try h.io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
    }

    /// Expects participant `by` to have blocked participant `peer`.
    fn expect_blocked(h: *Harness, by: usize, peer: usize) !void {
        const blocked = try h.net.oracle().blocked(gpa);
        defer gpa.free(blocked);
        for (blocked) |pair| {
            if (pair.origin.eql(h.fixture.participants[by]) and
                pair.recipient.eql(h.fixture.participants[peer])) return;
        }
        return error.ExpectedBlocked;
    }

    fn blocked_count(h: *Harness) !usize {
        const blocked = try h.net.oracle().blocked(gpa);
        defer gpa.free(blocked);
        return blocked.len;
    }
};

/// Sends `message` from `sender` to the joiner.
fn send_to(sender: *Net.Sender, to: P, message: Message) !void {
    const bytes = try message.encode(gpa);
    defer gpa.free(bytes);
    const sent = try sender.send(.{ .one = to }, &.{bytes}, false);
    gpa.free(sent);
}

fn expect_latest_request(receiver: *Net.Receiver) !void {
    try testing.expectEqual(.latest, try next_request(receiver));
}

fn next_boundary_request(receiver: *Net.Receiver) !u64 {
    return switch (try next_request(receiver)) {
        .boundary => |epoch| epoch.get(),
        .block, .latest => error.ExpectedBoundaryRequest,
    };
}

fn next_block_request(receiver: *Net.Receiver) !u64 {
    return switch (try next_request(receiver)) {
        .block => |epoch| epoch.get(),
        .boundary, .latest => error.ExpectedBlockRequest,
    };
}

fn expect_silent(receiver: *Net.Receiver) !void {
    try testing.expectError(error.Empty, receiver.try_recv());
}

fn next_response(receiver: *Net.Receiver, fixture: *const Fixture) !Response {
    var message = try receiver.recv();
    errdefer message.deinit();
    const cfg = fixture.schemes[2].certificate_codec_config();
    const response = (try wire.read_response(Scheme, V, gpa, message.payload, cfg)).?;
    return .{ .message = message, .response = response };
}

/// A decoded response and the message whose bytes a block body borrows.
const Response = struct {
    message: p2p.Message(P),
    response: wire.Response(Scheme, V),

    fn deinit(self: *Response) void {
        self.response.deinit(gpa);
        self.message.deinit();
    }
};

fn next_request(receiver: *Net.Receiver) !wire.Request {
    var message = try receiver.recv();
    defer message.deinit();
    return (try wire.read_request(gpa, message.payload)) orelse error.ExpectedRequest;
}

/// Compares finalizations by encoding (the mock certificate has no pointer `eql`).
fn expect_finalization(expected: *const Finalization, actual: *const Finalization) !void {
    const left = try codec.encode(Finalization, gpa, expected.*);
    defer gpa.free(left);
    const right = try codec.encode(Finalization, gpa, actual.*);
    defer gpa.free(right);
    try testing.expectEqualSlices(u8, left, right);
}

fn expect_artifact(
    artifact: *const Artifact,
    finalization: *const Finalization,
    info: *const Info,
) !void {
    try expect_finalization(finalization, &artifact.finalization.?);
    try testing.expect(artifact.info.eql(info.*));
    try testing.expectEqual(info.epoch.get(), artifact.floor.epoch().get());
}

fn run(comptime body: fn (Io) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, .{
        .timeout_ns = 30 * std.time.ns_per_s,
    }, {}, struct {
        fn run_round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start(body, .{runner.io()}));
        }
    }.run_round);
}

test "dkg probe: discovers the artifact from a sample" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            var target = try h.complete_target_sample();
            defer target.deinit(gpa);

            try h.sleep_ms(100);
            var artifact = try subscription.try_recv();
            defer artifact.deinit();
            try expect_finalization(&target, &artifact.floor);
            try expect_artifact(&artifact, &h.boundary_finalization, &h.boundary_info);
        }
    }.body);
}

/// Subscribes, then expects one latest request at the client and one at the backup.
fn subscribe_solicited(h: *Harness) !oneshot.Receiver(Artifact) {
    var subscription = try h.joiner.subscribe();
    errdefer subscription.deinit();
    try expect_latest_request(&h.client.receiver);
    try expect_latest_request(&h.backup.receiver);
    return subscription;
}

test "dkg probe: waits for a full sample" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            // One reply is below the sample threshold (f + 1 = 2 of 4).
            var target = try h.target_finalization();
            defer target.deinit(gpa);
            try h.reply_latest(&h.client, &target);
            try h.sleep_ms(100);
            try testing.expectError(error.Empty, subscription.try_recv());
        }
    }.body);
}

test "dkg probe: a duplicate latest reply is ignored" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            // Two different valid replies from the same peer count once.
            var first = try latest_finalization(&h.fixture, 1, Sha256.hash(&.{"first"}));
            defer first.deinit(gpa);
            var second = try latest_finalization(&h.fixture, 2, Sha256.hash(&.{"second"}));
            defer second.deinit(gpa);
            try h.reply_latest(&h.client, &first);
            try h.reply_latest(&h.client, &second);
            try h.sleep_ms(100);
            try testing.expectError(error.Empty, subscription.try_recv());
            try testing.expectEqual(0, try h.blocked_count());
        }
    }.body);
}

test "dkg probe: the sample selects the highest reply" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{2} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            var info = try epoch_info(2, h.participants);
            defer info.deinit(gpa);
            var newer = try boundary_block(2, h.fixture.participants[0], info);
            defer newer.deinit();
            var stale = try latest_finalization(&h.fixture, 1, Sha256.hash(&.{"stale"}));
            defer stale.deinit(gpa);
            var newest = try latest_finalization(&h.fixture, 2, newer.digest());
            defer newest.deinit(gpa);
            try h.reply_latest(&h.client, &stale);
            try h.reply_latest(&h.backup, &newest);
            try h.sleep_ms(100);
            var artifact = try subscription.try_recv();
            defer artifact.deinit();
            try expect_finalization(&newest, &artifact.floor);
            var expected = try boundary_finalization(&h.fixture, 2, newer.digest());
            defer expected.deinit(gpa);
            try expect_artifact(&artifact, &expected, &info);
        }
    }.body);
}

test "dkg probe: a genesis floor resolves locally" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            // An epoch-zero sample resolves from genesis without a boundary fetch.
            var floor = try latest_finalization(&h.fixture, 0, Sha256.hash(&.{"genesis floor"}));
            defer floor.deinit(gpa);
            try h.reply_latest(&h.client, &floor);
            try h.reply_latest(&h.backup, &floor);
            try h.sleep_ms(100);
            var artifact = try subscription.try_recv();
            defer artifact.deinit();
            try testing.expectEqual(0, artifact.info.epoch.get());
            try testing.expect(artifact.finalization == null);
            var genesis = try epoch_info(0, h.participants);
            defer genesis.deinit(gpa);
            try testing.expect(artifact.info.eql(genesis));
            try expect_finalization(&floor, &artifact.floor);
        }
    }.body);
}

test "dkg probe: re-solicits when the sample is incomplete" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            // The first solicitation goes unanswered and is re-issued after the timeout.
            try expect_latest_request(&h.client.receiver);
            try expect_latest_request(&h.client.receiver);
        }
    }.body);
}

fn below_bootstrap(io: Io, floor_epoch: ?u64) !void {
    var h: Harness = undefined;
    try h.init(io, .{ .bootstrap_epoch = 1, .floor_epoch = floor_epoch });
    defer h.deinit();
    var subscription = try h.joiner.subscribe();
    defer subscription.deinit();
    // Valid replies below the bootstrap epoch are stale: ignored without blocking.
    var stale = try latest_finalization(&h.fixture, 0, Sha256.hash(&.{"stale"}));
    defer stale.deinit(gpa);
    try h.reply_latest(&h.client, &stale);
    try h.reply_latest(&h.backup, &stale);
    try h.sleep_ms(100);
    try testing.expectError(error.Empty, subscription.try_recv());
    try testing.expectEqual(0, try h.blocked_count());
    // The same peers may still contribute accepted replies.
    var target = try h.complete_target_sample();
    defer target.deinit(gpa);
    try h.sleep_ms(100);
    var artifact = try subscription.try_recv();
    defer artifact.deinit();
    try expect_finalization(&target, &artifact.floor);
}

test "dkg probe: ignores latest replies below the bootstrap epoch" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            try below_bootstrap(io, null);
            // A persisted epoch-zero floor does not lower the minimum below bootstrap.
            try below_bootstrap(io, 0);
        }
    }.body);
}

test "dkg probe: ignores latest replies below the persisted floor's epoch" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{
                .source_boundaries = &.{ 1, 2 },
                .bootstrap_epoch = 1,
                .floor_epoch = 2,
            });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            var stale = try h.target_finalization();
            defer stale.deinit(gpa);
            try h.reply_latest(&h.client, &stale);
            try h.reply_latest(&h.backup, &stale);
            try h.sleep_ms(100);
            try testing.expectError(error.Empty, subscription.try_recv());
            try testing.expectEqual(0, try h.blocked_count());

            // Replies in the floor's epoch resolve its info; the committee is tracked at the
            // bootstrap epoch's peer-set ID, not the floor's.
            var sampled = try latest_finalization(&h.fixture, 2, Sha256.hash(&.{"sampled"}));
            defer sampled.deinit(gpa);
            try h.reply_latest(&h.client, &sampled);
            try h.reply_latest(&h.backup, &sampled);
            try h.sleep_ms(100);
            var artifact = try subscription.try_recv();
            defer artifact.deinit();
            try expect_finalization(&sampled, &artifact.floor);
            try testing.expectEqual(2, artifact.info.epoch.get());
            const manager = h.net.oracle().manager();
            const one = (try manager.peer_set(gpa, 1)) orelse return error.ExpectedPeerSet;
            one.free(gpa);
            try testing.expect(try manager.peer_set(gpa, 2) == null);
        }
    }.body);
}

test "dkg probe: an invalid latest reply blocks its peer" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            // A finalization from a foreign key set decodes but fails verification.
            var rng = utils.rng.TestRng.init(99);
            var foreign = try certificate_mocks.fixture(Scheme, gpa, &rng, namespace, 4);
            defer foreign.deinit(gpa);
            var invalid = try latest_finalization(&foreign, 1, Sha256.hash(&.{"foreign"}));
            defer invalid.deinit(gpa);
            try h.reply_latest(&h.client, &invalid);
            try h.sleep_ms(100);
            try h.expect_blocked(1, 2);
        }
    }.body);
}

/// Completes the target sample and expects the epoch-1 boundary request at both peers.
fn start_boundary_fetch(h: *Harness) !oneshot.Receiver(Artifact) {
    var subscription = try subscribe_solicited(h);
    errdefer subscription.deinit();
    var target = try h.complete_target_sample();
    defer target.deinit(gpa);
    try testing.expectEqual(1, try next_boundary_request(&h.client.receiver));
    try testing.expectEqual(1, try next_boundary_request(&h.backup.receiver));
    return subscription;
}

fn send_boundary(h: *Harness, from: *Net.Registered) !void {
    const joiner = h.fixture.participants[1];
    try send_to(&from.sender, joiner, .{ .boundary_response = h.boundary_finalization });
}

fn send_block(h: *Harness, from: *Net.Registered, block: Block) !void {
    const joiner = h.fixture.participants[1];
    const response: Message.BlockResponse = .{ .epoch = .new(1), .block = block };
    try send_to(&from.sender, joiner, .{ .block_response = response });
}

fn expect_boundary_artifact(h: *Harness, subscription: *oneshot.Receiver(Artifact)) !void {
    var artifact = try subscription.try_recv();
    defer artifact.deinit();
    try expect_artifact(&artifact, &h.boundary_finalization, &h.boundary_info);
}

test "dkg probe: fetches the boundary block from one responder" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try start_boundary_fetch(&h);
            defer subscription.deinit();
            try send_boundary(&h, &h.client);
            try testing.expectEqual(1, try next_block_request(&h.client.receiver));
            try h.sleep_ms(100);
            try expect_silent(&h.backup.receiver); // No request to an unselected responder.
            try send_block(&h, &h.client, h.boundary);
            try h.sleep_ms(100);
            try expect_boundary_artifact(&h, &subscription);
        }
    }.body);
}

test "dkg probe: retries the boundary block with another responder" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try start_boundary_fetch(&h);
            defer subscription.deinit();
            try send_boundary(&h, &h.client);
            try testing.expectEqual(1, try next_block_request(&h.client.receiver));
            // The client stays silent; after the retry timeout the backup is asked.
            try send_boundary(&h, &h.backup);
            try testing.expectEqual(1, try next_block_request(&h.backup.receiver));
            try send_block(&h, &h.backup, h.boundary);
            try h.sleep_ms(100);
            try expect_boundary_artifact(&h, &subscription);
            try testing.expectEqual(0, try h.blocked_count());
        }
    }.body);
}

test "dkg probe: an invalid boundary block tries another responder at once" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try start_boundary_fetch(&h);
            defer subscription.deinit();
            try send_boundary(&h, &h.client);
            try testing.expectEqual(1, try next_block_request(&h.client.receiver));
            try send_boundary(&h, &h.backup);
            try h.sleep_ms(100);
            var info = try epoch_info(2, h.participants);
            defer info.deinit(gpa);
            var wrong = try boundary_block(2, h.fixture.participants[0], info);
            defer wrong.deinit();
            try send_block(&h, &h.client, wrong);
            // Failover comes well before the 500 ms retry timeout.
            try h.sleep_ms(100);
            var request = try h.backup.receiver.try_recv();
            defer request.deinit();
            const decoded = (try wire.read_request(gpa, request.payload)).?;
            try testing.expectEqual(1, decoded.block.get());
            try send_block(&h, &h.backup, h.boundary);
            try h.sleep_ms(100);
            try expect_boundary_artifact(&h, &subscription);
            try h.expect_blocked(1, 2);
        }
    }.body);
}

test "dkg probe: re-broadcasts an unanswered boundary request" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            try expect_latest_request(&h.client.receiver);
            var target = try h.complete_target_sample();
            defer target.deinit(gpa);
            try testing.expectEqual(1, try next_boundary_request(&h.client.receiver));
            try testing.expectError(error.Empty, subscription.try_recv());
            try testing.expectEqual(1, try next_boundary_request(&h.client.receiver));
            try testing.expectError(error.Empty, subscription.try_recv());
        }
    }.body);
}

test "dkg probe: a terminal-epoch boundary response blocks its sender" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .source_boundaries = &.{} });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            try expect_latest_request(&h.client.receiver);
            var target = try h.complete_target_sample();
            defer target.deinit(gpa);
            try testing.expectEqual(1, try next_boundary_request(&h.client.receiver));
            const max = std.math.maxInt(u64);
            const round: consensus.Round = .new(.new(max), .new(1));
            const proposal: Proposal = .init(round, .zero(), h.boundary.digest());
            var terminal = try finalize(&h.fixture, proposal);
            defer terminal.deinit(gpa);
            try send_to(&h.source_sender, h.fixture.participants[1], .{
                .boundary_response = terminal,
            });
            try h.sleep_ms(100);
            try h.expect_blocked(1, 0);
            try testing.expectError(error.Empty, subscription.try_recv());
        }
    }.body);
}

test "dkg probe: does not solicit without a subscriber" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            try h.sleep_ms(700);
            try expect_silent(&h.client.receiver);
        }
    }.body);
}

test "dkg probe: a late subscriber receives the cached artifact" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            var first = try h.joiner.subscribe();
            defer first.deinit();
            var target = try h.complete_target_sample();
            defer target.deinit(gpa);
            try h.sleep_ms(100);
            try expect_boundary_artifact(&h, &first);
            var second = try h.joiner.subscribe();
            defer second.deinit();
            try h.sleep_ms(10);
            try expect_boundary_artifact(&h, &second);
        }
    }.body);
}

test "dkg probe: service answers a latest request from the source" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            try send_to(&h.client.sender, h.fixture.participants[0], .latest_request);
            var response = try next_response(&h.client.receiver, &h.fixture);
            defer response.deinit();
            try testing.expect(response.response == .latest);
            try expect_finalization(&h.boundary_finalization, &response.response.latest);
        }
    }.body);
}

test "dkg probe: service answers boundary finalization and block requests" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            const source = h.fixture.participants[0];
            try send_to(&h.client.sender, source, .{ .boundary_request = .new(1) });
            var boundary = try next_response(&h.client.receiver, &h.fixture);
            defer boundary.deinit();
            try testing.expect(boundary.response == .boundary);
            const finalization = &boundary.response.boundary;
            try expect_finalization(&h.boundary_finalization, finalization);

            try send_to(&h.client.sender, source, .{ .block_request = .new(1) });
            var response = try next_response(&h.client.receiver, &h.fixture);
            defer response.deinit();
            try testing.expect(response.response == .block);
            const block_response = response.response.block;
            try testing.expectEqual(1, block_response.epoch.get());
            const commitment = finalization.proposal.payload;
            const body_bytes = block_response.body;
            const seq = parallel.sequential;
            var block = try wire.read_block(V, gpa, body_bytes, commitment, {}, seq);
            defer block.deinit();
            try testing.expect(block.digest().eql(h.boundary.digest()));
            try testing.expectEqual(1, block.inner().height().get());
        }
    }.body);
}

test "dkg probe: service ignores an epoch without a boundary" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            const source = h.fixture.participants[0];
            try send_to(&h.client.sender, source, .{ .boundary_request = .zero() });
            try h.sleep_ms(100);
            try expect_silent(&h.client.receiver);
        }
    }.body);
}

test "dkg probe: a failed activation stops the probe and drops the subscriber" {
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{ .fail_activation = true });
            defer h.deinit();
            var subscription = try h.joiner.subscribe();
            defer subscription.deinit();
            try testing.expectError(error.Closed, subscription.recv());
            try h.tasks[1].?.await(io);
            h.tasks[1] = null;
        }
    }.body);
}

test "dkg probe: a canceled probe returns error.Canceled" {
    // Swallowing the cancel would leave the caller's next wait unwakeable (AGENTS.md).
    try run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, .{});
            defer h.deinit();
            // The source probe serves; the joiner waits in discovery for a subscriber.
            try h.sleep_ms(50);
            for (&h.tasks) |*task| {
                try testing.expectError(error.Canceled, task.*.?.cancel(io));
                task.* = null;
            }
        }
    }.body);
}
