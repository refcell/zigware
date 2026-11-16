//! Tests of commonware's `glue::dkg::reshare::store` (`mod tests`), with the in-memory secret
//! store of glue's DKG test mocks (`MemorySecretStore`).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const runtime = @import("runtime");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const types = @import("../types.zig");
const store_mod = @import("store.zig");

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
const MemoryStorage = runtime.buffer.mocks.Storage;
const CacheRef = runtime.buffer.paged.CacheRef;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_STORE_TEST";

/// Secret material kept in memory (commonware's `MemorySecretStore`), recording every prune.
pub const MemorySecretStore = struct {
    gpa: Allocator,
    shares: std.ArrayList(struct { u64, Share }) = .empty,
    seeds: std.ArrayList(struct { u64, Summary }) = .empty,
    dealings: std.ArrayList(struct { u64, P, fd.DealerPrivMsg }) = .empty,
    prunes: std.ArrayList(u64) = .empty,

    pub fn init(allocator: Allocator) MemorySecretStore {
        return .{ .gpa = allocator };
    }

    pub fn deinit(self: *MemorySecretStore) void {
        self.shares.deinit(self.gpa);
        self.seeds.deinit(self.gpa);
        self.dealings.deinit(self.gpa);
        self.prunes.deinit(self.gpa);
    }

    pub fn has_share(self: *const MemorySecretStore, epoch: Epoch) bool {
        for (self.shares.items) |entry| if (entry[0] == epoch.get()) return true;
        return false;
    }

    pub fn put_share(self: *MemorySecretStore, epoch: Epoch, share: Share) !void {
        for (self.shares.items) |*entry| if (entry[0] == epoch.get()) {
            entry[1] = share;
            return;
        };
        try self.shares.append(self.gpa, .{ epoch.get(), share });
    }

    pub fn get_share(self: *MemorySecretStore, epoch: Epoch) !?Share {
        for (self.shares.items) |entry| if (entry[0] == epoch.get()) return entry[1];
        return null;
    }

    pub fn put_seed(self: *MemorySecretStore, epoch: Epoch, seed: Summary) !void {
        for (self.seeds.items) |*entry| if (entry[0] == epoch.get()) {
            entry[1] = seed;
            return;
        };
        try self.seeds.append(self.gpa, .{ epoch.get(), seed });
    }

    pub fn get_seed(self: *MemorySecretStore, epoch: Epoch) !?Summary {
        for (self.seeds.items) |entry| if (entry[0] == epoch.get()) return entry[1];
        return null;
    }

    pub fn put_dealing(
        self: *MemorySecretStore,
        epoch: Epoch,
        dealer: P,
        private: fd.DealerPrivMsg,
    ) !void {
        for (self.dealings.items) |*entry| if (entry[0] == epoch.get() and entry[1].eql(dealer)) {
            entry[2] = private;
            return;
        };
        try self.dealings.append(self.gpa, .{ epoch.get(), dealer, private });
    }

    pub fn get_dealing(self: *MemorySecretStore, epoch: Epoch, dealer: P) !?fd.DealerPrivMsg {
        for (self.dealings.items) |entry| {
            if (entry[0] == epoch.get() and entry[1].eql(dealer)) return entry[2];
        }
        return null;
    }

    pub fn prune(self: *MemorySecretStore, min: Epoch) !void {
        try self.prunes.append(self.gpa, min.get());
        retain(@TypeOf(self.shares.items[0]), &self.shares, min.get());
        retain(@TypeOf(self.seeds.items[0]), &self.seeds, min.get());
        retain(@TypeOf(self.dealings.items[0]), &self.dealings, min.get());
    }

    fn retain(comptime T: type, list: *std.ArrayList(T), min: u64) void {
        var kept: usize = 0;
        for (list.items) |entry| {
            if (entry[0] < min) continue;
            list.items[kept] = entry;
            kept += 1;
        }
        list.shrinkRetainingCapacity(kept);
    }
};

const TestStore = store_mod.Store(MinPk, P, Unit, MemorySecretStore);
const Dealer = store_mod.Dealer(MinPk, PrivateKey);
const Player = store_mod.Player(MinPk, PrivateKey);
const Info = fd.Info(MinPk, P);

/// The storage, page cache, and secret store a store reopens over after a restart.
const Harness = struct {
    storage: MemoryStorage,
    cache_ref: CacheRef,

    fn init() !Harness {
        return .{ .storage = .init(gpa), .cache_ref = try .init(gpa, 1024, 10) };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness, partition: []const u8, secrets: *MemorySecretStore) !TestStore {
        return TestStore.init(gpa, self.storage.interface(), .{
            .partition_prefix = partition,
            .max_participants = 16,
            .cache_ref = &self.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        }, secrets);
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
