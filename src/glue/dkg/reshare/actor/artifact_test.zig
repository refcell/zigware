//! Tests of commonware's `glue::dkg::reshare::actor::inclusion` artifact derivation
//! (`exact_failed_artifact_is_a_cache_hit`, `missing_dealing_recovery_produces_shareless_
//! success_artifact`, and `finalization_failure_produces_failure_artifact`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const actor_test = @import("actor_test.zig");
const inclusion_test = @import("inclusion_test.zig");
const artifact = @import("artifact.zig");

const Epoch = consensus.Epoch;
const PrivateKey = mocks.TestSigner;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const Summary = cryptography.transcript.Summary;
const Harness = actor_test.Harness;
const Artifacts = artifact.Artifacts(mocks.ActorTypes);
const Logs = Artifacts.Logs;
const Info = @import("actor.zig").Actor(mocks.ActorTypes).Info;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST";

fn signers() [4]PrivateKey {
    var keys: [4]PrivateKey = undefined;
    for (&keys, 0..) |*key, seed| key.* = .from_seed(seed);
    return keys;
}

fn players() !Set {
    var keys: [4]P = undefined;
    for (&keys, signers()) |*key, signer| key.* = signer.public_key();
    return Set.from_dedup(gpa, &keys);
}

/// A dealing the target received from one dealer.
const Dealing = struct { dealer: P, public: fd.DealerPubMsg(V), private: fd.DealerPrivMsg };

/// A reshare round over a trusted previous sharing, with a quorum of finalized dealer logs
/// and the target's dealings (commonware `finalization_fixture`).
const Fixture = struct {
    info: fd.Info(V, P),
    previous: fd.Dealt(V, P),
    logs: Logs = .empty,
    dealings: [3]Dealing = undefined,

    fn init(self: *Fixture, seed: u64) !void {
        var rng = utils.rng.TestRng.init(0);
        self.previous = try fd.deal(V, P, N3f1, gpa, &rng, .non_zero_counter, try players());
        self.info = try .init(
            N3f1,
            gpa,
            namespace,
            0,
            try self.previous.output.clone(gpa),
            .non_zero_counter,
            .v1,
            try players(),
            try players(),
        );
        self.logs = .empty;
        for (signers()[0..3], &self.dealings, 0..) |dealer, *dealing, index| {
            try self.deal(dealer, dealing, seed + index);
        }
    }

    fn deinit(self: *Fixture) void {
        for (&self.dealings) |*dealing| dealing.public.deinit(gpa);
        self.logs.deinit(gpa);
        self.info.deinit(gpa);
        self.previous.deinit(gpa);
    }

    fn share(self: *const Fixture, key: P) Share {
        return self.previous.shares.get_value(key).?.*;
    }

    /// Deals from `dealer`, has the first three signers acknowledge, and records its log.
    fn deal(self: *Fixture, dealer: PrivateKey, dealing: *Dealing, seed: u64) !void {
        var rng = utils.rng.TestRng.init(seed);
        const previous_share = self.share(dealer.public_key());
        const Dealer = fd.Dealer(V, PrivateKey);
        var started = try Dealer.start(N3f1, gpa, &rng, &self.info, dealer, previous_share);
        defer {
            started.pub_msg.deinit(gpa);
            gpa.free(started.priv_msgs);
        }
        const target = signers()[0].public_key();
        for (signers()[0..3]) |player_signer| {
            const key = player_signer.public_key();
            const private = for (started.priv_msgs) |item| {
                if (item.player.eql(key)) break item.msg;
            } else return error.MissingDealing;
            if (key.eql(target)) dealing.* = .{
                .dealer = dealer.public_key(),
                .public = try started.pub_msg.clone(gpa),
                .private = private,
            };
            var player = try fd.Player(V, PrivateKey).init(&self.info, player_signer);
            defer player.deinit(gpa);
            const dealer_key = dealer.public_key();
            const public = started.pub_msg;
            const ack = (try player.dealer_message(N3f1, gpa, dealer_key, public, private)).?;
            try started.dealer.receive_player_ack(key, ack);
        }
        var signed = try started.dealer.finalize(N3f1, gpa);
        defer signed.deinit(gpa);
        try testing.expect(try fd.check_log(V, P, gpa, &self.info, &signed));
        try testing.expect(try self.logs.put_first(gpa, signed.dealer, try signed.log.clone(gpa)));
    }

    /// The last successful epoch: the previous output over all four signers.
    fn current(self: *const Fixture) !Info {
        return .{
            .outcome = .success,
            .epoch = .zero(),
            .output = try self.previous.output.clone(gpa),
            .players = try players(),
            .next_players = try players(),
            .directory = .{},
        };
    }
};

const seed_zero: Summary = .{ .bytes = @splat(1) };

// commonware `exact_failed_artifact_is_a_cache_hit`.
test "artifact: an exact failed artifact is a cache hit" {
    var cache: Artifacts.Cache = .{ .cached = .{
        .logs = try inclusion_test.dealer_logs(0),
        .artifact = null,
    } };
    defer cache.deinit(gpa);
    var same = try inclusion_test.dealer_logs(0);
    defer same.deinit(gpa);
    var other = try inclusion_test.dealer_logs(1);
    defer other.deinit(gpa);
    const hit = cache.get(same) orelse return error.ExpectedCacheHit;
    try testing.expect(hit.artifact == null);
    try testing.expect(cache.get(other) == null);
}

// commonware `finalization_failure_produces_failure_artifact`: with no logs, continuous
// reshare carries the previous output and this node's share into a failure artifact.
test "artifact: a finalization failure produces a failure artifact" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "finalization-failure-artifact", 8);
            defer h.deinit();
            var fixture: Fixture = undefined;
            try fixture.init(20);
            defer fixture.deinit();
            const share = fixture.share(h.public_key);
            try h.store.commit_epoch(try fixture.current(), seed_zero, share);
            const empty: Logs = .empty;
            const epoch = Epoch.zero();
            const ceremony = try Artifacts.verify(&h.actor, epoch, &fixture.info, &h.store, empty);
            try testing.expect(ceremony == null);
            var cache: Artifacts.Cache = .empty;
            defer cache.deinit(gpa);
            const derived = try Artifacts.derive(&h.actor, epoch, &h.store, empty, null, &cache);
            const result = derived orelse return error.ExpectedArtifact;
            try testing.expectEqual(.failure, result.info.outcome);
            try testing.expectEqual(@as(u64, 1), result.info.epoch.get());
            try testing.expect(result.info.output.eql(fixture.previous.output));
            try testing.expect(result.share.?.eql(share));
        }
    }.body);
}

// commonware `missing_dealing_recovery_produces_shareless_success_artifact`: recovered
// public logs stay usable when the private dealings are gone; this node observes the
// ceremony and derives a successful artifact without a share.
test "artifact: missing private dealings recover a shareless success artifact" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "missing-dealing-artifact-actor", 8);
            defer h.deinit();
            var fixture: Fixture = undefined;
            try fixture.init(10);
            defer fixture.deinit();
            const partition = "missing-dealing-artifact";
            try persist_round(&h, &fixture, partition);

            // Replay the public journal against an empty secret store.
            var secrets: mocks.MemorySecretStore = .init(gpa);
            defer secrets.deinit();
            var store = try h.store_harness.open(gpa, partition, &secrets);
            defer store.deinit();
            const share = fixture.share(h.public_key);
            try store.commit_epoch(try fixture.current(), seed_zero, share);
            const epoch = Epoch.zero();
            var logs = try Logs.from_sorted(gpa, store.logs(epoch));
            defer logs.deinit(gpa);
            try testing.expectEqual(@as(usize, 3), logs.len());
            const verified = try Artifacts.verify(&h.actor, epoch, &fixture.info, &store, logs);
            var ceremony = verified orelse return error.ExpectedCeremony;
            defer ceremony.deinit(gpa);
            try testing.expect(ceremony.share == null);
            var cache: Artifacts.Cache = .empty;
            defer cache.deinit(gpa);
            const derived = try Artifacts.derive(&h.actor, epoch, &store, logs, &ceremony, &cache);
            const result = derived orelse return error.ExpectedArtifact;
            try testing.expectEqual(.success, result.info.outcome);
            try testing.expect(result.info.output.eql(ceremony.output));
            try testing.expect(result.share == null);
        }
    }.body);
}

/// Persists the target's dealings and the round's finalized logs under `partition`.
fn persist_round(h: *Harness, fixture: *const Fixture, partition: []const u8) !void {
    var secrets: mocks.MemorySecretStore = .init(gpa);
    defer secrets.deinit();
    var store = try h.store_harness.open(gpa, partition, &secrets);
    defer store.deinit();
    const epoch = Epoch.zero();
    const target = PrivateKey.from_seed(0);
    var player = (try store.create_player(N3f1, PrivateKey, epoch, target, &fixture.info)).?;
    defer player.deinit();
    for (fixture.dealings) |dealing| {
        _ = try player.handle(&store, epoch, dealing.dealer, dealing.public, dealing.private);
    }
    for (fixture.logs.entries.items) |entry| {
        try testing.expect(try store.append_log(epoch, entry.key, entry.log));
    }
}

// commonware `finalization_error_panics` (an error here): a persisted dealing that conflicts
// with the finalized logs is invalid local state.
test "artifact: a persisted dealing conflicting with the finalized logs is invalid state" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "finalization-error-artifact-actor", 8);
            defer h.deinit();
            // Two valid ceremonies of one round give conflicting messages from one dealer.
            var persisted: Fixture = undefined;
            try persisted.init(30);
            defer persisted.deinit();
            var finalized: Fixture = undefined;
            try finalized.init(40);
            defer finalized.deinit();
            var secrets: mocks.MemorySecretStore = .init(gpa);
            defer secrets.deinit();
            var store = try h.store_harness.open(gpa, "finalization-error-artifact", &secrets);
            defer store.deinit();
            const share = finalized.share(h.public_key);
            try store.commit_epoch(try finalized.current(), seed_zero, share);
            const epoch = Epoch.zero();
            const target = signers()[0];
            const round = &finalized.info;
            const created = try store.create_player(N3f1, PrivateKey, epoch, target, round);
            var player = created orelse return error.ExpectedPlayer;
            defer player.deinit();

            // Persist the alternate ceremony's dealing from the target's own dealer and the
            // finalized ceremony's other dealings.
            for (finalized.dealings, persisted.dealings) |kept, alternate| {
                const mismatched = kept.dealer.eql(target.public_key());
                const dealing = if (mismatched) alternate else kept;
                const public = dealing.public;
                _ = try player.handle(&store, epoch, dealing.dealer, public, dealing.private);
            }
            // The finalized public logs bind the player to the conflicting dealer message.
            for (finalized.logs.entries.items) |entry| {
                try testing.expect(try store.append_log(epoch, entry.key, entry.log));
            }
            var logs = try Logs.from_sorted(gpa, store.logs(epoch));
            defer logs.deinit(gpa);
            const result = Artifacts.verify(&h.actor, epoch, &finalized.info, &store, logs);
            try testing.expectError(error.InvalidLocalState, result);
        }
    }.body);
}
