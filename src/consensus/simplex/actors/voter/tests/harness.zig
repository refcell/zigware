//! The voter-actor test harness (commonware `simplex/actors/voter/mod.rs` test helpers):
//! one voter actor over the mock application, relay, and reporter, with its batcher and
//! resolver mailboxes held by the test (`setup_voter`, `start_voter_with_floor`), plus the
//! certificate builders and journal seeding the tests share.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor_pkg = @import("actor");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const consensus_types = @import("../../../../types.zig");
const types = @import("../../../types.zig");
const config_mod = @import("../../../config.zig");
const elector_mod = @import("../../../elector.zig");
const ed25519 = @import("../../../scheme/ed25519.zig");
const application_mod = @import("../../../mocks/application.zig");
const relay_mod = @import("../../../mocks/relay.zig");
const reporter_mod = @import("../../../mocks/reporter.zig");
const voter = @import("../actor.zig");
const batcher_ingress = @import("../../batcher/ingress.zig");
const resolver_ingress = @import("../../resolver/ingress.zig");

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const Key = cryptography.ed25519.PublicKey;
pub const Scheme = ed25519.Scheme(Digest);
pub const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
pub const Net = p2p.simulated.Network(Key);
pub const Ctx = runtime.deterministic.Context;
pub const Application = application_mod.Application(Sha256, Key);
pub const Relay = relay_mod.Relay(Digest, Key);
pub const Reporter = reporter_mod.Reporter(Scheme, Digest);
pub const Elector = elector_mod.RoundRobinElector;
pub const View = consensus_types.View;
pub const Epoch = consensus_types.Epoch;
pub const Round = consensus_types.Round;
pub const Duration = utils.Duration;
pub const Proposal = types.Proposal(Digest);
pub const Notarize = types.Notarize(Scheme, Digest);
pub const Finalize = types.Finalize(Scheme, Digest);
pub const Nullify = types.Nullify(Scheme);
pub const Notarization = types.Notarization(Scheme, Digest);
pub const Finalization = types.Finalization(Scheme, Digest);
pub const Nullification = types.Nullification(Scheme);
pub const Certificate = types.Certificate(Scheme, Digest);
pub const Artifact = types.Artifact(Scheme, Digest);
pub const Floor = config_mod.Floor(Scheme, Digest);
pub const BatcherMessage = batcher_ingress.Message(Scheme, Digest);
pub const ResolverMessage = resolver_ingress.Message(Scheme, Digest);

pub const Params = struct {
    pub const Scheme = harness_scheme;
    pub const Elector = elector_mod.RoundRobinElector;
    pub const Digest = harness_digest;
    pub const Blocker = Net.Control;
    pub const Automaton = Application;
    pub const Relay = *Application;
    pub const Reporter = *reporter_mod.Reporter(harness_scheme, harness_digest);
    pub const Sender = Net.Sender;
};
const harness_scheme = Scheme;
const harness_digest = Digest;
pub const Voter = voter.Actor(Params);

/// commonware `TEST_QUOTA`.
pub const test_quota = p2p.Quota.per_second(std.math.maxInt(u32));
pub const page_size = 1024;
pub const page_cache_size = 10;
/// commonware's voter tests run in epoch 333.
pub const default_epoch: Epoch = .new(333);

/// The voter knobs of `setup_voter` (commonware `VoterOptions`): a short leader timeout,
/// with certification and retry timeouts far beyond any test.
pub const Options = struct {
    leader_timeout_ms: u64 = 500,
    certification_timeout_ms: u64 = 1_000_000,
    timeout_retry_ms: u64 = 1_000_000,
    local_index: usize = 0,
    propose_latency_ms: f64 = 1.0,
    verify_latency_ms: f64 = 1.0,
    certify_latency_ms: f64 = 1.0,
    stall_proposals: bool = false,
    drop_proposals: bool = false,
    fail_verification: bool = false,
    handoff: std.meta.Tag(@import("../../../../traits.zig").Handoff(Digest)) = .wait,
    certifier: application_mod.Certifier(Digest) = .always,
    epoch: Epoch = default_epoch,
    /// Null starts at genesis (owned by the voter otherwise).
    floor: ?Finalization = null,
    skip_budget: u64 = std.math.maxInt(u64),
    /// Null names the journal `voter_test_<index>`.
    partition: ?[]const u8 = null,
    batcher_capacity: u32 = 16,
    resolver_capacity: u32 = 8,
};

/// `n` ed25519 validators on one simulated network (commonware
/// `start_test_network_with_peers`). Must not move.
pub const Network = struct {
    gpa: Allocator,
    io: Io,
    fixture: Fixture,
    network: *Net,
    task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    relay: Relay,

    pub fn start(self: *Network, ctx: Ctx, n: u32, namespace: []const u8) !void {
        const gpa = ctx.gpa();
        const io = ctx.io();
        var rng = utils.rng.test_rng();
        self.gpa = gpa;
        self.io = io;
        self.fixture = try ed25519.fixture(Digest, gpa, &rng, namespace, n);
        errdefer self.fixture.deinit(gpa);
        self.network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = n,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        self.task = try io.concurrent(Net.run, .{self.network});
        _ = self.oracle().manager().track(0, .init_primary(.init(self.keys())));
        self.relay = .init(gpa, io);
    }

    pub fn deinit(self: *Network) void {
        self.relay.deinit();
        self.network.close();
        self.task.await(self.io) catch {};
        self.network.deinit();
        self.fixture.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn keys(self: *const Network) []const Key {
        return self.fixture.participants;
    }

    pub fn schemes(self: *const Network) []const Scheme {
        return self.fixture.schemes;
    }

    pub fn oracle(self: *const Network) Net.Oracle {
        return self.network.oracle();
    }

    pub fn quorum(self: *const Network) u32 {
        return utils.N3f1.quorum(@as(u32, @intCast(self.keys().len)));
    }
};

/// One running voter with the mailboxes the test holds (commonware `setup_voter`'s
/// returned tuple). Must not move.
pub const VoterStack = struct {
    gpa: Allocator,
    io: Io,
    application: Application,
    reporter: Reporter,
    page_cache: runtime.buffer.paged.CacheRef,
    voter: Voter,
    mailbox: Voter.Mailbox,
    batcher: actor_pkg.mailbox.Receiver(BatcherMessage),
    resolver: actor_pkg.mailbox.Receiver(ResolverMessage),
    batcher_sender: actor_pkg.mailbox.Sender(BatcherMessage),
    resolver_sender: actor_pkg.mailbox.Sender(ResolverMessage),
    elector: Elector,
    vote_sender: Net.Sender,
    vote_receiver: Net.Receiver,
    certificate_sender: Net.Sender,
    certificate_receiver: Net.Receiver,
    partition: [32]u8,
    task: ?Io.Future(anyerror!void),

    pub fn start(self: *VoterStack, ctx: Ctx, net: *Network, options: Options) !void {
        const gpa = ctx.gpa();
        const io = ctx.io();
        self.gpa = gpa;
        self.io = io;
        self.task = null;
        const index = options.local_index;
        const me = net.keys()[index];
        const scheme = &net.schemes()[index];
        try self.start_application(net, me, options);
        errdefer self.application.deinit();
        self.reporter = .init(gpa, io, &net.fixture.verifier);
        errdefer self.reporter.deinit();
        self.page_cache = try .init(gpa, page_size, page_cache_size);
        errdefer self.page_cache.deinit();
        const n: u32 = @intCast(net.keys().len);
        self.elector = try elector_mod.RoundRobin(Sha256).default().build(gpa, n);
        errdefer self.elector.deinit(gpa);
        self.partition = @splat(0);
        const partition = options.partition orelse
            try std.fmt.bufPrint(&self.partition, "voter_test_{d}", .{index});
        const floor: Floor = if (options.floor) |finalization|
            .{ .finalized = finalization }
        else
            .{ .genesis = application_mod.genesis(Sha256, options.epoch) };
        self.voter, self.mailbox = try Voter.init(gpa, io, .{
            .scheme = scheme,
            .elector = self.elector,
            .blocker = net.oracle().control(me),
            .automaton = &self.application,
            .relay = &self.application,
            .reporter = &self.reporter,
            .floor = floor,
            .partition = partition,
            .epoch = options.epoch,
            .mailbox_size = 128,
            .leader_timeout = .from_millis(options.leader_timeout_ms),
            .certification_timeout = .from_millis(options.certification_timeout_ms),
            .timeout_retry = .from_millis(options.timeout_retry_ms),
            .skip_budget = options.skip_budget,
            .view_retention = .new(10),
            .replay_buffer = 10240,
            .write_buffer = 10240,
            .cache_ref = &self.page_cache,
            .storage = ctx.storage,
            .scope = ctx.scope.child("voter"),
        });
        const batcher =
            try actor_pkg.mailbox.new(BatcherMessage, gpa, io, options.batcher_capacity);
        self.batcher = batcher.receiver;
        self.batcher_sender = batcher.sender;
        const resolver =
            try actor_pkg.mailbox.new(ResolverMessage, gpa, io, options.resolver_capacity);
        self.resolver = resolver.receiver;
        self.resolver_sender = resolver.sender;
        const votes = try net.oracle().control(me).register(0, test_quota);
        self.vote_sender, self.vote_receiver = .{ votes.sender, votes.receiver };
        const certificates = try net.oracle().control(me).register(1, test_quota);
        self.certificate_sender = certificates.sender;
        self.certificate_receiver = certificates.receiver;
        self.task = try io.concurrent(run_voter, .{
            self,
            batcher_ingress.Mailbox(Scheme, Digest){ .sender = self.batcher_sender },
            resolver_ingress.Mailbox(Scheme, Digest){ .sender = self.resolver_sender },
        });
    }

    fn start_application(self: *VoterStack, net: *Network, me: Key, options: Options) !void {
        self.application = try .init(self.gpa, self.io, .{
            .relay = &net.relay,
            .me = me,
            .propose_latency = .{ .mean = options.propose_latency_ms, .std_dev = 0 },
            .verify_latency = .{ .mean = options.verify_latency_ms, .std_dev = 0 },
            .certify_latency = .{ .mean = options.certify_latency_ms, .std_dev = 0 },
            .should_certify = options.certifier,
        });
        errdefer self.application.deinit();
        self.application.stall_proposals = options.stall_proposals;
        self.application.drop_proposals = options.drop_proposals;
        self.application.fail_verification = options.fail_verification;
        self.application.handoff = options.handoff;
        try self.application.register();
    }

    fn run_voter(
        self: *VoterStack,
        batcher: batcher_ingress.Mailbox(Scheme, Digest),
        resolver: resolver_ingress.Mailbox(Scheme, Digest),
    ) anyerror!void {
        return self.voter.run(batcher, resolver, &self.vote_sender, &self.certificate_sender);
    }

    /// Aborts the voter (commonware `handle.abort()`); its journal stays in storage.
    pub fn stop(self: *VoterStack) void {
        if (self.task) |*task| {
            task.cancel(self.io) catch {};
            self.task = null;
        }
        self.mailbox.deinit();
        self.voter.deinit();
        self.elector.deinit(self.gpa);
        self.vote_sender.deinit();
        self.vote_receiver.deinit();
        self.certificate_sender.deinit();
        self.certificate_receiver.deinit();
        self.batcher.deinit();
        self.resolver.deinit();
        self.page_cache.deinit();
        self.reporter.deinit();
        self.application.deinit();
        self.* = undefined;
    }

    /// The next batcher message within `limit_ms` of simulated time, or null.
    pub fn next_batcher(self: *VoterStack, ctx: Ctx, limit_ms: u64) !?BatcherMessage {
        return next_within(BatcherMessage, ctx, &self.batcher, limit_ms);
    }

    /// The next batcher `update` (skipping `constructed`) within `limit_ms`, or an error.
    pub fn next_update(self: *VoterStack, ctx: Ctx, limit_ms: u64) !BatcherMessage.Update {
        var waited: u64 = 0;
        // Bounded by `limit_ms` of simulated time.
        while (waited <= limit_ms) : (waited += 1) {
            const message = self.batcher.try_recv() catch |err| switch (err) {
                error.Empty => {
                    try ctx.sleep(.fromMilliseconds(1));
                    continue;
                },
                else => return error.MailboxClosed,
            };
            if (message == .update) return message.update;
        }
        return error.TimedOut;
    }

    /// Waits for the batcher `update` announcing `current` with `finalized` as its floor,
    /// skipping updates below `current` (commonware's update loops).
    pub fn expect_update(self: *VoterStack, ctx: Ctx, current: u64, finalized: u64) !void {
        // Bounded: views only advance, and each wait is limited.
        while (true) {
            const update = try self.next_update(ctx, 5_000);
            if (update.current.get() < current) continue;
            try std.testing.expectEqual(current, update.current.get());
            try std.testing.expectEqual(finalized, update.finalized.get());
            return;
        }
    }

    /// commonware `expect_replayed`: the next resolver message is `replayed`.
    pub fn expect_replayed(self: *VoterStack, ctx: Ctx) !void {
        const message = (try self.next_resolver(ctx, 5_000)) orelse return error.TimedOut;
        defer message.discard();
        try std.testing.expect(message == .replayed);
    }

    /// Expects the next resolver message to be an `updated` certificate of `kind` at `view`.
    pub fn expect_updated(
        self: *VoterStack,
        ctx: Ctx,
        kind: std.meta.Tag(Certificate),
        view: u64,
    ) !void {
        const message = (try self.next_resolver(ctx, 5_000)) orelse return error.TimedOut;
        defer message.discard();
        try std.testing.expect(message == .updated);
        try std.testing.expectEqual(kind, std.meta.activeTag(message.updated.certificate));
        try std.testing.expectEqual(view, message.updated.certificate.view().get());
    }

    /// The next resolver message within `limit_ms` of simulated time, or null.
    pub fn next_resolver(self: *VoterStack, ctx: Ctx, limit_ms: u64) !?ResolverMessage {
        return next_within(ResolverMessage, ctx, &self.resolver, limit_ms);
    }
};

fn next_within(
    comptime T: type,
    ctx: Ctx,
    receiver: *actor_pkg.mailbox.Receiver(T),
    limit_ms: u64,
) !?T {
    var waited: u64 = 0;
    while (waited <= limit_ms) : (waited += 1) {
        if (receiver.try_recv()) |message| return message else |err| switch (err) {
            error.Empty => try ctx.sleep(.fromMilliseconds(1)),
            else => return error.MailboxClosed,
        }
    }
    return null;
}

/// Appends `artifacts` (borrowed, all at `view`) to the voter journal `partition` and syncs
/// it (commonware `seed_voter_journal_artifacts`).
pub fn seed_journal(
    ctx: Ctx,
    partition: []const u8,
    scheme: *const Scheme,
    view: View,
    artifacts: []const Artifact,
) !void {
    const gpa = ctx.gpa();
    var page_cache: runtime.buffer.paged.CacheRef = try .init(gpa, page_size, page_cache_size);
    defer page_cache.deinit();
    const Journal = storage.journal.segmented.variable.Journal(Artifact);
    var recovery = try Journal.init(gpa, ctx.storage, .{
        .partition = partition,
        .codec_config = scheme.certificate_codec_config(),
        .cache_ref = &page_cache,
        .write_buffer = 1024 * 1024,
        .replay_buffer = 1024 * 1024,
    });
    errdefer recovery.deinit();
    // Bounded by the journal's contents.
    while (try recovery.next()) |entry| {
        var artifact = entry.item;
        artifact.deinit(gpa);
    }
    var journal = try recovery.finish();
    defer journal.deinit();
    for (artifacts) |artifact| {
        assert(artifact.view().get() == view.get());
        _ = try journal.append(view.get(), artifact);
    }
    try journal.sync(&.{view.get()});
}

/// Waits for the restarted voter to announce `finalized.next()` with `finalized` as its
/// floor, and to report the finalization at `finalized` (none above it) to the resolver
/// (commonware `expect_restarted_voter_at_floor`).
pub fn expect_at_floor(stack: *VoterStack, ctx: Ctx, finalized: View) !void {
    var saw_update = false;
    var saw_finalization = false;
    var waited: u64 = 0;
    while (!(saw_update and saw_finalization)) : (waited += 1) {
        if (waited > 5_000) return error.TimedOut;
        if (stack.batcher.try_recv()) |message| {
            if (message == .update) {
                const update = message.update;
                try std.testing.expectEqual(finalized.get() + 1, update.current.get());
                try std.testing.expectEqual(finalized.get(), update.finalized.get());
                saw_update = true;
            }
            continue;
        } else |_| {}
        if (stack.resolver.try_recv()) |message| {
            defer message.discard();
            if (message == .updated and message.updated.certificate == .finalization) {
                const view = message.updated.certificate.view();
                try std.testing.expect(view.get() <= finalized.get());
                saw_finalization = saw_finalization or view.get() == finalized.get();
            }
            continue;
        } else |_| {}
        try ctx.sleep(.fromMilliseconds(1));
    }
}

/// A proposal at `view` of `epoch` over `view - 1`, with payload `hash(label)`.
pub fn proposal_at(epoch: Epoch, view: u64, label: []const u8) Proposal {
    assert(view > 0);
    return .init(.new(epoch, .new(view)), .new(view - 1), Sha256.hash(&.{label}));
}

/// A certificate of `kind` over `subject` signed by the first `count` of `schemes`
/// (commonware `build_notarization`, `build_finalization`, `build_nullification`). Free it.
pub fn build(
    gpa: Allocator,
    comptime kind: std.meta.Tag(Certificate),
    schemes: []const Scheme,
    subject: if (kind == .nullification) Round else Proposal,
    count: u32,
) !@FieldType(Certificate, @tagName(kind)) {
    const Vote = switch (kind) {
        .notarization => Notarize,
        .finalization => Finalize,
        .nullification => Nullify,
    };
    var votes: [16]Vote = undefined;
    assert(count <= votes.len and count <= schemes.len);
    for (votes[0..count], schemes[0..count]) |*vote, *scheme| {
        vote.* = (try Vote.sign(gpa, scheme, subject)).?;
    }
    const Signed = @FieldType(Certificate, @tagName(kind));
    return Signed.from_votes(gpa, &schemes[0], votes[0..count], parallel.sequential);
}

test "voter harness starts at genesis and announces view 1" {
    var runner = try runtime.deterministic.Runner.init(std.testing.allocator, .{
        .timeout_ns = 20 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(struct {
        fn body(ctx: Ctx) anyerror!void {
            var net: Network = undefined;
            try net.start(ctx, 5, "voter_harness");
            defer net.deinit();
            var stack: VoterStack = undefined;
            try stack.start(ctx, &net, .{});
            defer stack.stop();
            const message = (try stack.next_batcher(ctx, 1_000)) orelse return error.NoUpdate;
            try std.testing.expect(message == .update);
            try std.testing.expectEqual(@as(u64, 1), message.update.current.get());
        }
    }.body, .{});
}
