//! Tests of commonware's `glue::dkg::reshare::store` (`mod tests`), with the in-memory secret
//! store of glue's DKG test mocks (`tests/mocks.zig`).

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const types = @import("../types.zig");
const store_mod = @import("store.zig");
const mocks = @import("../tests/mocks.zig");

const ed25519 = cryptography.ed25519;
const PrivateKey = ed25519.PrivateKey;
const P = ed25519.PublicKey;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const N3f1 = utils.N3f1;
const Epoch = consensus.Epoch;
const MinPk = cryptography.bls12381.primitives.MinPk;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const Summary = cryptography.transcript.Summary;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_STORE_TEST";

const MemorySecretStore = mocks.MemorySecretStore;

const TestStore = mocks.TestStore;
const Dealer = store_mod.Dealer(MinPk, PrivateKey);
const Player = store_mod.Player(MinPk, PrivateKey);
const Info = fd.Info(MinPk, P);

/// Opens stores over one in-memory storage, as a restarted node would.
const Harness = struct {
    inner: mocks.StoreHarness,

    fn init() !Harness {
        return .{ .inner = try .init(gpa) };
    }

    fn deinit(self: *Harness) void {
        self.inner.deinit();
    }

    fn open(self: *Harness, partition: []const u8, secrets: *MemorySecretStore) !TestStore {
        return self.inner.open(gpa, partition, secrets);
    }
};

fn summary(seed: u8) Summary {
    return .{ .bytes = @splat(seed) };
}

fn signers() [4]PrivateKey {
    var keys: [4]PrivateKey = undefined;
    for (&keys, 0..) |*item, seed| item.* = .from_seed(seed);
    return keys;
}

fn players(keys: []const PrivateKey) !Set(P) {
    var public_keys: [4]P = undefined;
    for (keys, public_keys[0..keys.len]) |item, *public| public.* = item.public_key();
    return Set(P).from_dedup(gpa, public_keys[0..keys.len]);
}

fn dealt(seed: u64) !fd.Dealt(MinPk, P) {
    var rng = utils.rng.TestRng.init(seed);
    return fd.deal(MinPk, P, N3f1, gpa, &rng, .non_zero_counter, try players(&signers()));
}

fn output(seed: u64) !fd.Output(MinPk, P) {
    var result = try dealt(seed);
    for (result.shares.values) |*share| share.private.zeroize();
    result.shares.deinit(gpa);
    return result.output;
}

fn epoch_info(epoch: u64, out: fd.Output(MinPk, P)) TestStore.Info {
    return .{
        .outcome = .success,
        .epoch = .new(epoch),
        .output = out,
        .players = .empty,
        .next_players = .empty,
        .directory = .{},
    };
}

fn round_info() !Info {
    const keys = signers();
    const dealers = try players(&keys);
    const mode = .non_zero_counter;
    return Info.init(N3f1, gpa, namespace, 0, null, mode, .v1, dealers, try players(&keys));
}

/// The dealer of `signers()[0]` for epoch zero, seeded with `summary(2)`.
fn first_dealer(store: *TestStore, info: *const Info) !?Dealer {
    return store.create_dealer(N3f1, PrivateKey, .zero(), signers()[0], info, null, summary(2));
}

fn dealing_for(dealer: *const Dealer, player: P) fd.DealerPrivMsg {
    for (dealer.shares_to_distribute()) |item| if (item.player.eql(player)) return item.msg;
    @panic("dealing for player");
}

test "store: commit_epoch seeds the configured epoch (commit_epoch_seeds_configured_epoch)" {
    var harness = try Harness.init();
    defer harness.deinit();
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("configured-start", &secrets);
    defer store.deinit();
    try store.commit_epoch(epoch_info(7, try output(1)), summary(1), null);
    try testing.expectEqual(@as(u64, 7), store.current_info().?.epoch.get());
}

/// Records a valid dealer log from `dealer`'s finalization in `store`.
fn record_log(store: *TestStore, dealer: *Dealer, info: *const Info) !void {
    try testing.expect(try dealer.finalize(N3f1));
    const signed = &dealer.finalized.?;
    try testing.expect(try fd.check_log(MinPk, P, gpa, info, signed));
    try testing.expect(try store.append_log(.zero(), signed.dealer, signed.log));
}

test "store: replay restores dealings, acks, and logs (replay_restores_dealings_acks_and_logs)" {
    var harness = try Harness.init();
    defer harness.deinit();
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("replay", &secrets);
    var info = try round_info();
    defer info.deinit(gpa);
    try store.commit_epoch(epoch_info(0, try output(1)), summary(1), null);
    const keys = signers();
    const dealer_pk = keys[0].public_key();
    const player_pk = keys[1].public_key();
    var dealer = (try first_dealer(&store, &info)).?;
    defer dealer.deinit();
    var player = (try store.create_player(N3f1, PrivateKey, .zero(), keys[1], &info)).?;
    defer player.deinit();
    const private = dealing_for(&dealer, player_pk);
    const ack = try player.handle(&store, .zero(), dealer_pk, dealer.public, private);
    const duplicate = try player.handle(&store, .zero(), dealer_pk, dealer.public, private);
    try testing.expect(duplicate.eql(ack));
    // Sender membership and signature failures stay visible without consuming pending state.
    const stranger = PrivateKey.from_seed(std.math.maxInt(u64)).public_key();
    try testing.expectError(error.UnexpectedPlayer, dealer.handle(&store, .zero(), stranger, ack));
    const other = keys[2].public_key();
    try testing.expectError(error.InvalidAck, dealer.handle(&store, .zero(), other, ack));
    // Acknowledgements distinguish new and duplicate outcomes.
    try testing.expectEqual(.recorded, try dealer.handle(&store, .zero(), player_pk, ack));
    try testing.expectEqual(.duplicate, try dealer.handle(&store, .zero(), player_pk, ack));
    try record_log(&store, &dealer, &info);
    store.deinit();

    var restarted = try harness.open("replay", &secrets);
    defer restarted.deinit();
    // The current epoch is not persisted: setup re-derives it from finalized blocks.
    try testing.expect(restarted.current_info() == null);
    try testing.expectEqual(@as(usize, 1), restarted.dealings(.zero()).len);
    try testing.expectEqual(@as(usize, 1), restarted.acks(.zero()).len);
    try testing.expectEqual(@as(usize, 1), restarted.logs(.zero()).len);
    var replayed = (try restarted.create_player(N3f1, PrivateKey, .zero(), keys[1], &info)).?;
    defer replayed.deinit();
    try testing.expectEqual(@as(usize, 1), replayed.acks.len());
    const public = dealer.public;
    const replayed_ack = try replayed.handle(&restarted, .zero(), dealer_pk, public, private);
    try testing.expect(replayed_ack.eql(ack));
}

// commonware `resume_with_missing_dealing_degrades_to_observer`.
test "store: a missing private dealing degrades to observer" {
    var harness = try Harness.init();
    defer harness.deinit();
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("missing-dealing", &secrets);
    var info = try round_info();
    defer info.deinit(gpa);
    try store.commit_epoch(epoch_info(0, try output(1)), summary(1), null);
    const keys = signers();
    const dealer_pk = keys[0].public_key();
    var dealer = (try first_dealer(&store, &info)).?;
    defer dealer.deinit();
    // With n = 4 and f = 1 the log tolerates one reveal, so three players acknowledge and
    // the log records an ack for each of them.
    for ([_]usize{ 1, 2, 3 }) |index| {
        const player_pk = keys[index].public_key();
        var player: Player = .{
            .gpa = gpa,
            .player = try fd.Player(MinPk, PrivateKey).init(&info, keys[index]),
            .acks = .empty,
        };
        defer player.deinit();
        const private = dealing_for(&dealer, player_pk);
        const ack = try player.handle(&store, .zero(), dealer_pk, dealer.public, private);
        try testing.expectEqual(.recorded, try dealer.handle(&store, .zero(), player_pk, ack));
    }
    try record_log(&store, &dealer, &info);
    store.deinit();

    // The finalized log, which records this player's ack, replays from public storage, but
    // the matching private dealing is gone: resuming must degrade to an observer.
    var empty: MemorySecretStore = .init(gpa);
    defer empty.deinit();
    var restarted = try harness.open("missing-dealing", &empty);
    defer restarted.deinit();
    try testing.expectEqual(@as(usize, 0), restarted.dealings(.zero()).len);
    try testing.expectEqual(@as(usize, 1), restarted.logs(.zero()).len);
    const player = try restarted.create_player(N3f1, PrivateKey, .zero(), keys[1], &info);
    try testing.expect(player == null);
}

// commonware `protocol_storage_does_not_restore_private_dealings`.
test "store: protocol storage does not restore private dealings" {
    var harness = try Harness.init();
    defer harness.deinit();
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("private-dealing-boundary", &secrets);
    var info = try round_info();
    defer info.deinit(gpa);
    try store.commit_epoch(epoch_info(0, try output(1)), summary(1), null);
    const keys = signers();
    var dealer = (try first_dealer(&store, &info)).?;
    defer dealer.deinit();
    var player = (try store.create_player(N3f1, PrivateKey, .zero(), keys[1], &info)).?;
    defer player.deinit();
    const private = dealing_for(&dealer, keys[1].public_key());
    _ = try player.handle(&store, .zero(), keys[0].public_key(), dealer.public, private);
    try testing.expectEqual(@as(usize, 1), store.dealings(.zero()).len);
    store.deinit();

    var empty: MemorySecretStore = .init(gpa);
    defer empty.deinit();
    var restarted = try harness.open("private-dealing-boundary", &empty);
    defer restarted.deinit();
    try testing.expectEqual(@as(usize, 0), restarted.dealings(.zero()).len);
    var replayed = (try restarted.create_player(N3f1, PrivateKey, .zero(), keys[1], &info)).?;
    defer replayed.deinit();
    try testing.expectEqual(@as(usize, 0), replayed.acks.len());
}

// commonware `protocol_storage_does_not_restore_secret_shares`.
test "store: protocol storage does not restore secret shares" {
    var harness = try Harness.init();
    defer harness.deinit();
    var result = try dealt(9);
    defer result.deinit(gpa);
    const share = result.shares.get_value(signers()[0].public_key()).?.*;
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("secret-boundary", &secrets);
    try store.commit_epoch(epoch_info(0, try output(1)), summary(1), share);
    try testing.expect(try store.share(.zero()) != null);
    store.deinit();

    var empty: MemorySecretStore = .init(gpa);
    defer empty.deinit();
    var restarted = try harness.open("secret-boundary", &empty);
    defer restarted.deinit();
    // Neither the current epoch nor the share (held only in the secret store) survives.
    try testing.expect(restarted.current_info() == null);
    try testing.expect(try restarted.share(.zero()) == null);
}

// commonware `prune_removes_old_protocol_state_and_secret_shares`.
test "store: prune removes old protocol state and secret shares" {
    var harness = try Harness.init();
    defer harness.deinit();
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("prune", &secrets);
    var next = try dealt(10);
    for (next.shares.values) |*share| share.private.zeroize();
    const share = next.shares.get_value(signers()[0].public_key()).?.*;
    next.shares.deinit(gpa);
    try store.commit_epoch(epoch_info(0, try output(1)), summary(1), null);
    // Something to prune: a log in epoch zero.
    var info = try round_info();
    defer info.deinit(gpa);
    var dealer = (try first_dealer(&store, &info)).?;
    defer dealer.deinit();
    try record_log(&store, &dealer, &info);
    try store.commit_epoch(epoch_info(1, next.output), summary(2), share);
    try store.prune(.new(1));
    store.deinit();

    var restarted = try harness.open("prune", &secrets);
    defer restarted.deinit();
    try testing.expect(restarted.current_info() == null);
    try testing.expectEqual(@as(usize, 0), restarted.logs(.zero()).len);
    try testing.expectEqualSlices(u64, &.{1}, secrets.prunes.items);
    try testing.expect(!secrets.has_share(.zero()));
    try testing.expect(secrets.has_share(.new(1)));
    _ = types;
}

const runtime = @import("runtime");
const Ctx = runtime.deterministic.Context;
const MutationFaults = runtime.storage.mocks.MutationFaults;
const MutationFault = runtime.storage.mocks.MutationFault;

/// Where a player stops while it records a dealing (commonware `Interruption`).
const Interruption = union(enum) {
    /// The journal completes this many mutations and parks every later one.
    journal: u64,
    /// `put_dealing` stores nothing and never returns.
    secret_store,
};

/// A dealing's public message and private half, owned.
const TestDealing = struct {
    public: fd.DealerPubMsg(MinPk),
    private: fd.DealerPrivMsg,

    fn eql(a: *const TestDealing, b: *const TestDealing) bool {
        return a.public.eql(b.public) and a.private.eql(b.private);
    }

    fn deinit(self: *TestDealing) void {
        self.public.deinit(gpa);
        self.private.zeroize();
    }
};

/// The dealing the first signer sends the second when it deals from `summary(seed)`
/// (commonware `dealing`). Different seeds give different dealings.
fn dealing(seed: u8) !TestDealing {
    var harness = try Harness.init();
    defer harness.deinit();
    var secrets: MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try harness.open("dealing", &secrets);
    defer store.deinit();
    var info = try round_info();
    defer info.deinit(gpa);
    const signer = signers()[0];
    const seeded = summary(seed);
    const created = try store.create_dealer(N3f1, PrivateKey, .zero(), signer, &info, null, seeded);
    var dealer = created.?;
    defer dealer.deinit();
    const player = signers()[1].public_key();
    for (dealer.shares_to_distribute()) |item| if (item.player.eql(player)) {
        return .{ .public = try dealer.public.clone(gpa), .private = item.msg };
    };
    return error.MissingDealing;
}

/// What one run of `handle_dealing` saw.
const Handled = struct {
    /// The dealings replay restored at startup.
    restored: std.ArrayList(TestDealing) = .empty,
    ack: ?fd.PlayerAck(P) = null,

    fn deinit(self: *Handled) void {
        for (self.restored.items) |*item| item.deinit();
        self.restored.deinit(gpa);
    }

    fn expect_restored(self: *const Handled, expected: ?*const TestDealing) !void {
        const count: usize = if (expected == null) 0 else 1;
        try testing.expectEqual(count, self.restored.items.len);
        if (expected) |value| try testing.expect(self.restored.items[0].eql(value));
    }
};

/// The player's `handle` running in its own task; `done` is set once it returns.
const Handle = struct {
    player: *Player,
    store: *TestStore,
    sent: *const TestDealing,
    done: bool = false,
    result: anyerror!fd.PlayerAck(P) = error.Unfinished,

    fn run(task_ctx: Ctx, self: *Handle) anyerror!void {
        _ = task_ctx;
        const dealer = signers()[0].public_key();
        const sent = self.sent;
        self.result = self.player.handle(self.store, .zero(), dealer, sent.public, sent.private);
        self.done = true;
    }
};

/// Runs the second signer's player from startup on `runner`'s storage and `secrets` until it
/// has handled `sent` from the first signer or stops at `interruption` (commonware
/// `handle_dealing`). The runner keeps only synced storage for its next run.
fn handle_dealing(
    runner: *runtime.deterministic.Runner,
    secrets: *MemorySecretStore,
    sent: *const TestDealing,
    interruption: ?Interruption,
) !Handled {
    var handled: Handled = .{};
    errdefer handled.deinit();
    try try runner.start_context(handle_body, .{ secrets, sent, interruption, &handled });
    return handled;
}

fn handle_body(
    ctx: Ctx,
    secrets: *MemorySecretStore,
    sent: *const TestDealing,
    interruption: ?Interruption,
    handled: *Handled,
) anyerror!void {
    // Start from the journal and secrets as earlier runs left them. The journal's faults are
    // armed only after startup, so replay is never interrupted.
    var faults: MutationFaults = .init(ctx.io());
    var wrapper: MutationFault = .init(gpa, ctx.storage, &faults);
    var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
    defer cache_ref.deinit();
    var store = try TestStore.init(gpa, wrapper.storage(), .{
        .partition_prefix = "interrupted",
        .max_participants = 16,
        .cache_ref = &cache_ref,
        .write_buffer = 1024,
        .replay_buffer = 1024,
    }, secrets);
    defer store.deinit();
    for (store.dealings(.zero())) |entry| {
        const public = try entry.public.clone(gpa);
        const copy: TestDealing = .{ .public = public, .private = entry.private };
        try handled.restored.append(gpa, copy);
    }
    var info = try round_info();
    defer info.deinit(gpa);
    const joined = try store.create_player(N3f1, PrivateKey, .zero(), signers()[1], &info);
    var player = joined orelse return error.PlayerMustResume;
    defer player.deinit();

    // A storage failure is fatal to the store, so a dealing is stopped by parking one of its
    // writes and abandoning it.
    const parks = interruption != null and interruption.? == .secret_store;
    secrets.park_dealings(if (parks) ctx.io() else null);
    defer secrets.park_dealings(null);
    if (interruption) |stop| if (stop == .journal) faults.park_after(stop.journal);
    var task: Handle = .{ .player = &player, .store = &store, .sent = sent };
    const running = try ctx.child("handle").spawn(Handle.run, .{&task});
    var polls: u32 = 0;
    while (!task.done and polls < 16) : (polls += 1) try ctx.sleep(.fromMilliseconds(1));
    if (task.done) {
        try try running.join();
        handled.ack = try task.result;
    } else {
        if (running.abort()) |_| {} else |_| {}
    }
    faults.disarm();

    // A dealing is acknowledged exactly when none of its writes parked; a journal interruption
    // past the dealing's last mutation parks nothing.
    if (interruption) |stop| switch (stop) {
        .journal => try testing.expectEqual(handled.ack != null, !faults.parked()),
        .secret_store => try testing.expect(handled.ack == null),
    };
}

fn new_runner() !runtime.deterministic.Runner {
    return runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = 60 * std.time.ns_per_s });
}

/// Every place a dealing can stop: in the secret store, or before each journal mutation of an
/// uninterrupted dealing.
fn interruptions(buffer: []Interruption, sent: *const TestDealing) ![]const Interruption {
    buffer[0] = .secret_store;
    var count: usize = 1;
    var allowed: u64 = 0;
    while (count < buffer.len) : (allowed += 1) {
        var runner = try new_runner();
        defer runner.deinit();
        var secrets: MemorySecretStore = .init(gpa);
        defer secrets.deinit();
        var handled = try handle_dealing(&runner, &secrets, sent, .{ .journal = allowed });
        defer handled.deinit();
        if (handled.ack != null) break;
        buffer[count] = .{ .journal = allowed };
        count += 1;
    }
    try testing.expect(count > 1 and count < buffer.len);
    return buffer[0..count];
}

// commonware `issue_5721_regression` (https://github.com/commonwarexyz/monorepo/issues/5721):
// a dealing interrupted while it is recorded is restored whole or not at all, also when the
// dealer follows it with a different dealing that is interrupted too.
test "store: an interrupted dealing is restored whole or not at all (issue 5721)" {
    var dealings: [3]TestDealing = .{ try dealing(2), try dealing(3), try dealing(4) };
    defer for (&dealings) |*item| item.deinit();
    const first, const second, const third = .{ &dealings[0], &dealings[1], &dealings[2] };
    var buffer: [16]Interruption = undefined;
    const stops = try interruptions(&buffer, first);
    for (stops) |first_stop| for (stops) |second_stop| {
        // The dealer sends one dealing and, after the player restarts, a different one.
        var runner = try new_runner();
        defer runner.deinit();
        var secrets: MemorySecretStore = .init(gpa);
        defer secrets.deinit();
        var initial = try handle_dealing(&runner, &secrets, first, first_stop);
        initial.deinit();
        var later = try handle_dealing(&runner, &secrets, second, second_stop);
        defer later.deinit();

        // The restarted player has the second dealing exactly when it acknowledged it.
        // Otherwise it has none and acknowledges the next one it is sent.
        var next = try handle_dealing(&runner, &secrets, third, null);
        defer next.deinit();
        const ack = next.ack orelse return error.UninterruptedDealingUnhandled;
        const acknowledged = if (later.ack != null) second else third;
        if (later.ack) |second_ack| {
            try next.expect_restored(second);
            try testing.expect(ack.eql(second_ack));
        } else {
            try next.expect_restored(null);
        }

        // After another restart, the acknowledged dealing is restored whole and handling a
        // dealing again returns the same acknowledgement.
        var replayed = try handle_dealing(&runner, &secrets, third, null);
        defer replayed.deinit();
        try replayed.expect_restored(acknowledged);
        try testing.expect(replayed.ack.?.eql(ack));
    };
}

// commonware `interrupted_dealing_is_recorded_when_resent`.
test "store: an interrupted dealing is recorded when it is sent again" {
    var sent = try dealing(2);
    defer sent.deinit();
    // The first attempt leaves only the private half (or, in commonware, only the public one).
    for ([_]Interruption{ .secret_store, .{ .journal = 0 } }) |stop| {
        var runner = try new_runner();
        defer runner.deinit();
        var secrets: MemorySecretStore = .init(gpa);
        defer secrets.deinit();
        var interrupted = try handle_dealing(&runner, &secrets, &sent, stop);
        defer interrupted.deinit();
        try testing.expect(interrupted.ack == null);

        // The restarted player has no dealing and acknowledges the one sent again.
        var resent = try handle_dealing(&runner, &secrets, &sent, null);
        defer resent.deinit();
        try resent.expect_restored(null);
        const ack = resent.ack orelse return error.UninterruptedDealingUnhandled;

        // After another restart, the dealing is restored whole and handling it again returns
        // the same acknowledgement.
        var replayed = try handle_dealing(&runner, &secrets, &sent, null);
        defer replayed.deinit();
        try replayed.expect_restored(&sent);
        try testing.expect(replayed.ack.?.eql(ack));
    }
}
