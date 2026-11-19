//! The Feldman-Desmedt test plan (commonware `feldman_desmedt::test_plan`): a sequence of
//! rounds over a fixed pool of ed25519 participants, each with optional perturbations
//! (missing acks, bad shares, bad signatures, bad reveals, replaced shares, shifted
//! degrees, and player crash/resume checkpoints). `Plan.run` drives dealers, players, and an
//! observer through every round and checks that the outcome matches the perturbations.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const math = @import("math");
const primitives = @import("../../primitives/root.zig");
const transcript_mod = @import("../../../transcript.zig");
const ed25519 = @import("../../../ed25519.zig");
const fd = @import("../feldman_desmedt.zig");

const Allocator = std.mem.Allocator;
const N3f1 = utils.N3f1;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Participant = utils.Participant;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const Scalar = primitives.group.Scalar;
const Share = primitives.group.Share;
const Private = primitives.group.Private;
const Poly = primitives.sharing.Poly;
const threshold = primitives.ops.threshold;
const ops = primitives.ops;
const PrivateKey = ed25519.PrivateKey;
const PublicKey = ed25519.PublicKey;

const namespace_test = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST";

/// Byte masks XORed into the inputs of a transcript, to check that signatures bind them.
pub const Masks = struct {
    info_summary: []const u8 = &.{},
    dealer: []const u8 = &.{},
    pub_msg: []const u8 = &.{},
    log: []const u8 = &.{},

    fn nonzero(mask: []const u8) bool {
        for (mask) |byte| if (byte != 0) return true;
        return false;
    }

    pub fn modifies_player_ack(self: Masks) bool {
        return nonzero(self.info_summary) or nonzero(self.dealer) or nonzero(self.pub_msg);
    }

    /// XORs `mask` into `bytes` (as far as both reach); whether anything changed.
    fn apply(bytes: []u8, mask: []const u8) bool {
        const count = @min(bytes.len, mask.len);
        for (bytes[0..count], mask[0..count]) |*byte, m| byte.* ^= m;
        return nonzero(mask[0..count]);
    }

    const Masked = struct { modified: bool, transcript: Transcript };

    fn round_transcript(self: Masks, info: anytype) Masked {
        var summary = info.summary;
        const modified = apply(&summary.bytes, self.info_summary);
        return .{
            .modified = modified,
            .transcript = Transcript.resume_from(summary, fd.transcript_version),
        };
    }

    fn commit_masked(
        gpa: Allocator,
        out: *Masked,
        comptime T: type,
        value: T,
        mask: []const u8,
    ) !void {
        const bytes = try codec.encode(T, gpa, value);
        defer gpa.free(bytes);
        out.modified = apply(bytes, mask) or out.modified;
        out.transcript.commit(bytes);
    }

    fn player_ack(
        self: Masks,
        gpa: Allocator,
        comptime V: type,
        info: anytype,
        dealer: PublicKey,
        pub_msg: fd.DealerPubMsg(V),
    ) !Masked {
        var out = self.round_transcript(info);
        out.transcript = out.transcript.fork(fd.sig_ack);
        try commit_masked(gpa, &out, PublicKey, dealer, self.dealer);
        try commit_masked(gpa, &out, fd.DealerPubMsg(V), pub_msg, self.pub_msg);
        return out;
    }

    fn signed_dealer_log(
        self: Masks,
        gpa: Allocator,
        comptime V: type,
        info: anytype,
        log: fd.DealerLog(V, PublicKey),
    ) !Masked {
        var out = self.round_transcript(info);
        out.transcript = out.transcript.fork(fd.sig_log);
        try commit_masked(gpa, &out, fd.DealerLog(V, PublicKey), log, self.log);
        return out;
    }
};

pub const PlayerMasks = struct { dealer: u32, player: u32, masks: Masks };
pub const DealerMasks = struct { dealer: u32, masks: Masks };
pub const Shift = struct { dealer: u32, shift: i32 };

/// One round of a plan. Pairs are `{ dealer, player }`, except checkpoints, which are
/// `{ after_dealer, player }` and `{ after_dealer, missing_dealer }`.
pub const Round = struct {
    dealers: []const u32,
    players: []const u32,
    crash_resume_players: []const [2]u32 = &.{},
    resume_missing_dealer_msg_fails: []const [2]u32 = &.{},
    finalize_missing_dealer_msg_fails: []const u32 = &.{},
    no_acks: []const [2]u32 = &.{},
    bad_shares: []const [2]u32 = &.{},
    bad_player_sigs: []const PlayerMasks = &.{},
    bad_reveals: []const [2]u32 = &.{},
    bad_dealer_sigs: []const DealerMasks = &.{},
    replace_shares: []const u32 = &.{},
    shift_degrees: []const Shift = &.{},

    fn has(items: []const u32, item: u32) bool {
        return std.mem.indexOfScalar(u32, items, item) != null;
    }

    fn has_pair(pairs: []const [2]u32, a: u32, b: u32) bool {
        for (pairs) |pair| if (pair[0] == a and pair[1] == b) return true;
        return false;
    }

    fn player_masks(self: Round, dealer: u32, player: u32) Masks {
        for (self.bad_player_sigs) |entry| {
            if (entry.dealer == dealer and entry.player == player) return entry.masks;
        }
        return .{};
    }

    fn dealer_masks(self: Round, dealer: u32) Masks {
        for (self.bad_dealer_sigs) |entry| if (entry.dealer == dealer) return entry.masks;
        return .{};
    }

    fn shift(self: Round, dealer: u32) ?i32 {
        for (self.shift_degrees) |entry| if (entry.dealer == dealer) return entry.shift;
        return null;
    }

    /// Whether `dealer` misbehaves so that its log must not be selected.
    pub fn bad(self: Round, previous_successful_round: bool, dealer: u32) bool {
        if (has(self.replace_shares, dealer) and previous_successful_round) return true;
        if (self.shift(dealer)) |value| {
            const degree: i64 = @as(i64, N3f1.quorum(self.players.len)) - 1;
            // The shift saturates at degree 0, so it may change nothing.
            if (@max(degree + value, 0) != degree) return true;
        }
        for (self.bad_reveals) |pair| if (pair[0] == dealer) return true;
        // Distinct players this dealer must reveal.
        var revealed: u32 = 0;
        for (self.players) |player| {
            if (has_pair(self.bad_shares, dealer, player) or
                has_pair(self.no_acks, dealer, player)) revealed += 1;
        }
        return revealed > N3f1.max_faults(self.players.len);
    }

    /// Whether this round must fail, given the previous successful round's player count.
    pub fn expect_failure(self: Round, previous_successful_round: ?u32) bool {
        var good: u32 = 0;
        for (self.dealers) |dealer| {
            good += @intFromBool(!self.bad(previous_successful_round != null, dealer));
        }
        const previous_quorum = if (previous_successful_round) |n| N3f1.quorum(n) else 0;
        return good < @max(previous_quorum, N3f1.quorum(self.dealers.len));
    }

    /// Whether the round is well formed for `num_participants` and the previous
    /// successful round's players.
    pub fn validate(self: Round, num_participants: u32, previous: ?[]const u32) bool {
        if (self.dealers.len == 0 or self.players.len == 0) return false;
        for (self.dealers) |d| if (d >= num_participants) return false;
        for (self.players) |p| if (p >= num_participants) return false;
        for (self.crash_resume_players) |pair| {
            if (!has(self.dealers, pair[0]) or !has(self.players, pair[1])) return false;
        }
        for (self.resume_missing_dealer_msg_fails) |pair| {
            if (!self.valid_missing_checkpoint(previous != null, pair[0], pair[1])) return false;
        }
        for (self.finalize_missing_dealer_msg_fails) |p| {
            if (!has(self.players, p)) return false;
        }
        const previous_players = previous orelse return true;
        for (self.dealers) |d| if (!has(previous_players, d)) return false;
        return self.dealers.len >= N3f1.quorum(previous_players.len);
    }

    fn valid_missing_checkpoint(self: Round, previous: bool, after: u32, missing: u32) bool {
        const after_position = std.mem.indexOfScalar(u32, self.dealers, after) orelse
            return false;
        const missing_position = std.mem.indexOfScalar(u32, self.dealers, missing) orelse
            return false;
        if (missing_position > after_position) return false;
        if (self.bad(previous, missing)) return false;
        for (self.players) |player| {
            const corrupted = has_pair(self.no_acks, missing, player) or
                has_pair(self.bad_shares, missing, player) or
                self.player_masks(missing, player).modifies_player_ack();
            if (!corrupted) return true;
        }
        return false;
    }
};

/// A DKG test plan: rounds over participants `0..num_participants`.
pub const Plan = struct {
    num_participants: u32,
    rounds: []const Round,

    /// Whether every round is well formed given the rounds expected to succeed before it.
    pub fn validate(self: Plan) bool {
        var last_successful: ?[]const u32 = null;
        for (self.rounds) |r| {
            if (!r.validate(self.num_participants, last_successful)) return false;
            const previous_count: ?u32 = if (last_successful) |p| @intCast(p.len) else null;
            if (!r.expect_failure(previous_count)) last_successful = r.players;
        }
        return true;
    }

    /// Runs the plan with `seed`; fails when validation fails or any check does.
    pub fn run(self: Plan, comptime V: type, gpa: Allocator, seed: u64) !void {
        if (!self.validate()) return error.InvalidPlan;
        var runner = try Runner(V).init(gpa, self, seed);
        defer runner.deinit();
        for (self.rounds, 0..) |r, index| try runner.run_round(@intCast(index), r);
    }
};

fn Runner(comptime V: type) type {
    return struct {
        const Self = @This();
        const Info = fd.Info(V, PublicKey);
        const Output = fd.Output(V, PublicKey);
        const DealerLog = fd.DealerLog(V, PublicKey);
        const LogPair = Map(PublicKey, DealerLog).Pair;
        const Player = fd.Player(V, PrivateKey);
        const Dealer = fd.Dealer(V, PrivateKey);
        const Logs = fd.Logs(V, PublicKey, N3f1);
        const Persisted = fd.PersistedDealing(V, PublicKey);

        gpa: Allocator,
        rng: utils.rng.TestRng,
        keys: []PrivateKey,
        max_read_size: u32,
        previous_output: ?Output = null,
        shares: std.ArrayList(struct { PublicKey, Share }) = .empty,
        threshold_public_key: ?V.Public = null,

        fn init(gpa: Allocator, plan: Plan, seed: u64) !Self {
            var rng = utils.rng.TestRng.init(seed);
            const keys = try gpa.alloc(PrivateKey, plan.num_participants);
            for (keys) |*key| key.* = PrivateKey.random(&rng);
            // Reads must allow the largest shifted polynomial degree.
            var max_shift: u32 = 0;
            for (plan.rounds) |r| for (r.shift_degrees) |s| {
                max_shift = @max(max_shift, @as(u32, @intCast(@max(s.shift, 0))));
            };
            return .{
                .gpa = gpa,
                .rng = rng,
                .keys = keys,
                .max_read_size = plan.num_participants + max_shift,
            };
        }

        fn deinit(self: *Self) void {
            if (self.previous_output) |*output| output.deinit(self.gpa);
            for (self.shares.items) |*entry| entry[1].private.zeroize();
            self.shares.deinit(self.gpa);
            self.gpa.free(self.keys);
            self.* = undefined;
        }

        fn key_index(self: *const Self, pk: PublicKey) u32 {
            for (self.keys, 0..) |key, i| if (key.public_key().eql(pk)) return @intCast(i);
            unreachable; // Every key in a plan comes from `keys`.
        }

        fn key_of(self: *const Self, index: u32) PublicKey {
            return self.keys[index].public_key();
        }

        fn share_of(self: *const Self, key: PublicKey) ?Share {
            for (self.shares.items) |entry| if (entry[0].eql(key)) return entry[1];
            return null;
        }

        fn key_set(self: *const Self, indices: []const u32) !Set(PublicKey) {
            const items = try self.gpa.alloc(PublicKey, indices.len);
            defer self.gpa.free(items);
            for (items, indices) |*item, i| item.* = self.key_of(i);
            return Set(PublicKey).init(self.gpa, items);
        }

        fn run_round(self: *Self, round_index: u32, r: Round) !void {
            const gpa = self.gpa;
            const previous: ?u32 = if (self.previous_output) |o| @intCast(
                o.players.len(),
            ) else null;
            var info = try self.round_info(round_index, r);
            defer info.deinit(gpa);
            var state = try RoundState.init(gpa, &info, self.keys, r.players);
            defer state.deinit(gpa);
            for (r.dealers) |i_dealer| {
                try self.run_dealer(&state, r, previous != null, i_dealer);
                try self.check_resume_missing(&state, r, i_dealer);
                try self.crash_resume(&state, r, i_dealer);
            }
            var logs: Logs = .init(&info);
            defer logs.deinit(gpa);
            for (state.dealer_logs.items) |pair| {
                _ = try logs.record(gpa, pair[0], try pair[1].clone(gpa));
            }
            var selection_logs = try logs.clone(gpa);
            defer selection_logs.deinit(gpa);
            var selection = selection_logs.select(gpa, &self.rng, null) catch |err| switch (err) {
                error.InsufficientLogs => null,
                else => return err,
            };
            defer if (selection) |*s| s.deinit(gpa);
            if (selection) |s| for (r.dealers) |i_dealer| {
                if (r.bad(previous != null, i_dealer)) {
                    try testing.expect(s.dealers.position(self.key_of(i_dealer)) == null);
                }
            };
            var observe_logs = try logs.clone(gpa);
            defer observe_logs.deinit(gpa);
            const observed = fd.observe(V, PublicKey, N3f1, gpa, &self.rng, &observe_logs, null);
            if (r.expect_failure(previous)) {
                try testing.expectError(error.InsufficientLogs, observed);
                return;
            }
            var output = try observed;
            errdefer output.deinit(gpa);
            try self.check_round(&info, &state, &logs, r, previous != null, output, selection.?);
            try self.finalize_players(&state, &logs, output);
            try self.check_signing(round_index, r, output);
            if (self.previous_output) |*old| old.deinit(gpa);
            self.previous_output = output;
        }

        fn round_info(self: *Self, round_index: u32, r: Round) !Info {
            var dealers = try self.key_set(r.dealers);
            errdefer dealers.deinit(self.gpa);
            var players = try self.key_set(r.players);
            errdefer players.deinit(self.gpa);
            var previous: ?Output = null;
            if (self.previous_output) |o| previous = try o.clone(self.gpa);
            return Info.init(
                N3f1,
                self.gpa,
                namespace_test,
                round_index,
                previous,
                .non_zero_counter,
                .v1,
                dealers,
                players,
            );
        }

        /// Per-round state: the players (in `info.players` order), each player's acked
        /// dealings, and the verified dealer logs so far.
        const RoundState = struct {
            info: *const Info,
            players: []Player,
            acked: []std.ArrayList(Persisted),
            dealer_logs: std.ArrayList(LogPair) = .empty,

            fn init(
                gpa: Allocator,
                info: *const Info,
                keys: []const PrivateKey,
                indices: []const u32,
            ) !RoundState {
                const players = try gpa.alloc(Player, indices.len);
                errdefer gpa.free(players);
                for (players, info.players.items) |*player, key| {
                    const sk = for (keys) |candidate| {
                        if (candidate.public_key().eql(key)) break candidate;
                    } else unreachable; // Every player key comes from `keys`.
                    player.* = try Player.init(info, sk);
                }
                const acked = try gpa.alloc(std.ArrayList(Persisted), indices.len);
                @memset(acked, .empty);
                return .{ .info = info, .players = players, .acked = acked };
            }

            fn deinit(self: *RoundState, gpa: Allocator) void {
                for (self.players) |*player| player.deinit(gpa);
                gpa.free(self.players);
                for (self.acked) |*list| {
                    for (list.items) |*entry| entry.pub_msg.deinit(gpa);
                    list.deinit(gpa);
                }
                gpa.free(self.acked);
                for (self.dealer_logs.items) |*pair| pair[1].deinit(gpa);
                self.dealer_logs.deinit(gpa);
                self.* = undefined;
            }

            fn log_of(self: *const RoundState, dealer: PublicKey) ?*const DealerLog {
                for (self.dealer_logs.items) |*pair| if (pair[0].eql(dealer)) return &pair[1];
                return null;
            }
        };

        fn dealer_share(self: *Self, r: Round, i_dealer: u32) ?Share {
            const existing = self.share_of(self.key_of(i_dealer)) orelse return null;
            if (!Round.has(r.replace_shares, i_dealer)) return existing;
            return Share.init(Participant.init(i_dealer), Private.random(&self.rng));
        }

        /// Starts a dealer whose polynomial degree is shifted by `shift` (saturating at 0).
        fn start_shifted(
            self: *Self,
            info: *const Info,
            sk: PrivateKey,
            share: ?Share,
            shift: i32,
        ) !Dealer.Started {
            const gpa = self.gpa;
            const degree: u32 = @intCast(@max(@as(i64, info.degree(N3f1)) + shift, 0));
            const secret = if (share) |s| s.private.scalar.value else null;
            const constant = try info.unwrap_or_random_share(&self.rng, secret);
            var poly = try Poly(Scalar).random_with_constant(gpa, &self.rng, degree, constant);
            defer poly.deinit(gpa);
            const n = info.players.len();
            const priv_msgs = try gpa.alloc(fd.PrivMsgFor(PublicKey), n);
            errdefer gpa.free(priv_msgs);
            const values = try gpa.alloc(fd.AckOrReveal(PublicKey), n);
            errdefer gpa.free(values);
            for (priv_msgs, values, info.players.items) |*msg, *value, player| {
                const eval = poly.eval(Scalar, info.player_scalar(player).?);
                msg.* = .{ .player = player, .msg = .init(eval) };
                value.* = .{ .reveal = msg.msg };
            }
            var keys = try info.players.clone(gpa);
            errdefer keys.deinit(gpa);
            const results = Map(PublicKey, fd.AckOrReveal(PublicKey)).from_parts(keys, values).?;
            var pub_msg: fd.DealerPubMsg(V) = .{
                .commitment = try math.poly.commit(gpa, V.Public, poly),
            };
            errdefer pub_msg.deinit(gpa);
            const round = info.round_transcript();
            const transcript = try fd.transcript_for_ack(
                gpa,
                &round,
                V,
                PublicKey,
                sk.public_key(),
                pub_msg,
            );
            return .{
                .dealer = .{
                    .me = sk,
                    .info = info,
                    .pub_msg = pub_msg,
                    .results = results,
                    .transcript = transcript,
                },
                .pub_msg = try pub_msg.clone(gpa),
                .priv_msgs = priv_msgs,
            };
        }

        fn run_dealer(
            self: *Self,
            state: *RoundState,
            r: Round,
            previous: bool,
            i_dealer: u32,
        ) !void {
            const gpa = self.gpa;
            const info = state.info;
            const sk = self.keys[i_dealer];
            const dealer_pk = sk.public_key();
            const share = self.dealer_share(r, i_dealer);
            var started = if (r.shift(i_dealer)) |value|
                try self.start_shifted(info, sk, share, value)
            else
                try Dealer.start(N3f1, gpa, &self.rng, info, sk, share);
            defer {
                started.pub_msg.deinit(gpa);
                gpa.free(started.priv_msgs);
            }
            var dealer_live = true;
            errdefer if (dealer_live) started.dealer.deinit(gpa);
            for (started.priv_msgs) |*msg| {
                if (Round.has_pair(r.bad_shares, i_dealer, self.key_index(msg.player))) {
                    msg.msg = .init(Scalar.random(&self.rng));
                }
            }
            assert(started.priv_msgs.len == state.players.len);
            var num_reveals: u32 = @intCast(state.players.len);
            for (started.priv_msgs) |msg| {
                const acked = try self.deliver(state, r, previous, i_dealer, &started, msg);
                num_reveals -= @intFromBool(acked);
            }
            dealer_live = false;
            var signed = try started.dealer.finalize(N3f1, gpa);
            defer signed.deinit(gpa);
            try expect_roundtrip(gpa, fd.SignedDealerLog(V, PublicKey), signed, self.max_read_size);
            const masked = try r.dealer_masks(i_dealer).signed_dealer_log(gpa, V, info, signed.log);
            try testing.expectEqual(
                !masked.modified,
                masked.transcript.verify(&dealer_pk, &signed.sig),
            );
            try testing.expect(try fd.check_log(V, PublicKey, gpa, info, &signed));
            try testing.expect(signed.dealer.eql(dealer_pk));
            var log = try signed.log.clone(gpa);
            errdefer log.deinit(gpa);
            try self.apply_bad_reveals(info, r, i_dealer, &log, num_reveals);
            try state.dealer_logs.append(gpa, .{ dealer_pk, log });
        }

        /// Delivers one dealing to its player; whether the dealer received an ack.
        fn deliver(
            self: *Self,
            state: *RoundState,
            r: Round,
            previous: bool,
            i_dealer: u32,
            started: *Dealer.Started,
            msg: fd.PrivMsgFor(PublicKey),
        ) !bool {
            const gpa = self.gpa;
            const dealer_pk = self.key_of(i_dealer);
            try expect_roundtrip(gpa, fd.DealerPrivMsg, msg.msg, {});
            const index = state.info.players.position(msg.player).?;
            const player_key = self.key_index(msg.player);
            const result = state.players[index].dealer_message(
                N3f1,
                gpa,
                dealer_pk,
                started.pub_msg,
                msg.msg,
            );
            const ack = result catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => null,
            };
            try expect_roundtrip(gpa, ?fd.PlayerAck(PublicKey), ack, {});
            const value = ack orelse {
                try testing.expect(Round.has_pair(r.bad_shares, i_dealer, player_key) or
                    r.bad(previous, i_dealer));
                return false;
            };
            try state.acked[index].append(gpa, .{
                .dealer = dealer_pk,
                .pub_msg = try started.pub_msg.clone(gpa),
                .priv_msg = msg.msg,
            });
            const masks = r.player_masks(i_dealer, player_key);
            const masked = try masks.player_ack(gpa, V, state.info, dealer_pk, started.pub_msg);
            try testing.expectEqual(
                !masked.modified,
                masked.transcript.verify(&msg.player, &value.sig),
            );
            if (Round.has_pair(r.no_acks, i_dealer, player_key)) return false;
            try started.dealer.receive_player_ack(msg.player, value);
            return true;
        }

        fn apply_bad_reveals(
            self: *Self,
            info: *const Info,
            r: Round,
            i_dealer: u32,
            log: *DealerLog,
            num_reveals: u32,
        ) !void {
            switch (log.results) {
                .too_many_reveals => try testing.expect(num_reveals > info.max_reveals(N3f1)),
                .ok => |*results| {
                    try testing.expectEqual(info.players.len(), results.len());
                    for (r.players) |i_player| {
                        if (!Round.has_pair(r.bad_reveals, i_dealer, i_player)) continue;
                        const slot = results.get_value_mut(self.key_of(i_player)).?;
                        slot.* = .{ .reveal = .init(Scalar.random(&self.rng)) };
                    }
                },
            }
        }

        /// The acked dealings of `player` (an `info.players` position) without `skip`.
        fn replay_without(
            self: *const Self,
            state: *const RoundState,
            player: usize,
            skip: ?PublicKey,
        ) ![]Persisted {
            var out: std.ArrayList(Persisted) = .empty;
            errdefer out.deinit(self.gpa);
            for (state.acked[player].items) |entry| {
                if (skip) |s| if (entry.dealer.eql(s)) continue;
                try out.append(self.gpa, entry);
            }
            return out.toOwnedSlice(self.gpa);
        }

        /// After `i_dealer`, resuming without a good dealer's message must fail exactly for
        /// players that acked it.
        fn check_resume_missing(self: *Self, state: *RoundState, r: Round, i_dealer: u32) !void {
            const gpa = self.gpa;
            for (r.resume_missing_dealer_msg_fails) |pair| {
                if (pair[0] != i_dealer) continue;
                const missing_pk = self.key_of(pair[1]);
                const missing_log = state.log_of(missing_pk).?;
                for (r.players) |i_player| {
                    const player_pk = self.key_of(i_player);
                    const was_acked = missing_log.get_ack(player_pk) != null;
                    const position = state.info.players.position(player_pk).?;
                    const replay = try self.replay_without(state, position, missing_pk);
                    defer gpa.free(replay);
                    const resumed = Player.resume_from(
                        N3f1,
                        gpa,
                        state.info,
                        self.keys[i_player],
                        state.dealer_logs.items,
                        replay,
                    );
                    if (was_acked) {
                        try testing.expectError(error.MissingPlayerDealing, resumed);
                    } else {
                        var value = try resumed;
                        value.player.deinit(gpa);
                        value.acks.deinit(gpa);
                    }
                }
            }
        }

        fn crash_resume(self: *Self, state: *RoundState, r: Round, i_dealer: u32) !void {
            const gpa = self.gpa;
            for (r.crash_resume_players) |pair| {
                if (pair[0] != i_dealer) continue;
                const position = state.info.players.position(self.key_of(pair[1])).?;
                const replay = state.acked[position].items;
                var resumed = try Player.resume_from(
                    N3f1,
                    gpa,
                    state.info,
                    self.keys[pair[1]],
                    state.dealer_logs.items,
                    replay,
                );
                resumed.acks.deinit(gpa);
                state.players[position].deinit(gpa);
                state.players[position] = resumed.player;
            }
        }

        fn check_round(
            self: *Self,
            info: *const Info,
            state: *const RoundState,
            logs: *Logs,
            r: Round,
            previous: bool,
            output: Output,
            selection: fd.Selection(V, PublicKey),
        ) !void {
            // The expected dealers: good dealers in key order, up to the required count.
            const required = info.required_commitments(N3f1);
            var expected: std.ArrayList(PublicKey) = .empty;
            defer expected.deinit(self.gpa);
            for (info.dealers.items) |dealer| {
                if (expected.items.len == required) break;
                if (!r.bad(previous, self.key_index(dealer))) try expected.append(self.gpa, dealer);
            }
            try testing.expectEqualSlices(PublicKey, expected.items, output.dealers.items);
            try testing.expectEqualSlices(PublicKey, expected.items, selection.dealers.items);
            try self.check_finalize_missing(state, logs, r, previous, selection);
            try self.check_reveals(info, r, output, selection);
        }

        fn check_finalize_missing(
            self: *Self,
            state: *const RoundState,
            logs: *Logs,
            r: Round,
            previous: bool,
            selection: fd.Selection(V, PublicKey),
        ) !void {
            const gpa = self.gpa;
            for (r.finalize_missing_dealer_msg_fails) |i_player| {
                const player_pk = self.key_of(i_player);
                const position = state.info.players.position(player_pk).?;
                var tested: u32 = 0;
                for (selection.dealers.items, selection.logs) |dealer_pk, log| {
                    if (r.bad(previous, self.key_index(dealer_pk))) continue;
                    if (log.get_ack(player_pk) == null) continue;
                    const replay = try self.replay_without(state, position, dealer_pk);
                    defer gpa.free(replay);
                    var stale: std.ArrayList(LogPair) = .empty;
                    defer stale.deinit(gpa);
                    for (state.dealer_logs.items) |pair| {
                        if (!pair[0].eql(dealer_pk)) try stale.append(gpa, pair);
                    }
                    var resumed = try Player.resume_from(
                        N3f1,
                        gpa,
                        state.info,
                        self.keys[i_player],
                        stale.items,
                        replay,
                    );
                    defer resumed.player.deinit(gpa);
                    resumed.acks.deinit(gpa);
                    var copy = try logs.clone(gpa);
                    defer copy.deinit(gpa);
                    const finalized = resumed.player.finalize(N3f1, gpa, &self.rng, &copy, null);
                    try testing.expectError(error.MissingPlayerDealing, finalized);
                    tested += 1;
                }
                try testing.expect(tested > 0);
            }
        }

        fn check_reveals(
            self: *Self,
            info: *const Info,
            r: Round,
            output: Output,
            selection: fd.Selection(V, PublicKey),
        ) !void {
            const reveal_threshold = info.reveal_threshold(N3f1);
            for (info.players.items) |player| {
                const player_key = self.key_index(player);
                var count: u32 = 0;
                for (selection.dealers.items) |dealer| {
                    const dealer_key = self.key_index(dealer);
                    count += @intFromBool(Round.has_pair(r.no_acks, dealer_key, player_key) or
                        Round.has_pair(r.bad_shares, dealer_key, player_key));
                }
                const expected = count >= reveal_threshold;
                try testing.expectEqual(expected, output.revealed.position(player) != null);
            }
        }

        fn finalize_players(self: *Self, state: *RoundState, logs: *Logs, output: Output) !void {
            const gpa = self.gpa;
            for (self.shares.items) |*entry| entry[1].private.zeroize();
            self.shares.clearRetainingCapacity();
            for (state.players, state.info.players.items) |*player, player_pk| {
                var copy = try logs.clone(gpa);
                defer copy.deinit(gpa);
                var finalized = try player.finalize(N3f1, gpa, &self.rng, &copy, null);
                defer finalized.output.deinit(gpa);
                try testing.expect(finalized.output.eql(output));
                const expected = try output.public.partial_public(finalized.share.index);
                try testing.expect(expected.eql(finalized.share.public(V)));
                try self.shares.append(gpa, .{ player_pk, finalized.share });
            }
        }

        fn check_signing(self: *Self, round_index: u32, r: Round, output: Output) !void {
            const gpa = self.gpa;
            const current = output.public.public();
            if (self.threshold_public_key) |key| {
                try testing.expect(key.eql(current));
            } else self.threshold_public_key = current;
            var buffer: [64]u8 = undefined;
            const message = try std.fmt.bufPrint(&buffer, "test message round {d}", .{round_index});
            const namespace = "test";
            const partials = try gpa.alloc(primitives.variant.PartialSignature(V), r.players.len);
            defer gpa.free(partials);
            for (partials, r.players) |*partial, i_player| {
                const share = self.share_of(self.key_of(i_player)).?;
                partial.* = threshold.sign_message(V, share, namespace, message);
                try threshold.verify_message(V, output.public, namespace, message, partial.*);
            }
            const quorum = output.quorum(N3f1);
            const signature = try threshold.recover(
                V,
                gpa,
                output.public,
                partials[0..quorum],
                parallel.sequential,
            );
            try ops.verify_message(V, self.threshold_public_key.?, namespace, message, signature);
        }
    };
}

/// Encodes `value`, decodes it with `cfg`, and expects the same value back.
fn expect_roundtrip(gpa: Allocator, comptime T: type, value: T, cfg: anytype) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    const decoded = try codec.decode_cfg(T, gpa, bytes, cfg);
    defer codec.free(T, gpa, decoded);
    const equal = if (@typeInfo(T) == .optional)
        (value == null and decoded == null) or
            (value != null and decoded != null and value.?.eql(decoded.?))
    else
        value.eql(decoded);
    try testing.expect(equal);
}

/// Most participants and rounds in an arbitrary plan.
pub const max_num_participants: u32 = 20;
pub const max_rounds: u32 = 10;

const Unstructured = @import("invariants").minifuzz.Unstructured;
const UError = @import("invariants").minifuzz.Error;

/// `Vec<u8>::arbitrary`: a continuation bit before each byte.
fn arbitrary_bytes(arena: Allocator, u: *Unstructured) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    while (u.arbitrary(bool) catch false) try out.append(arena, try u.arbitrary(u8));
    return out.items;
}

fn arbitrary_masks(arena: Allocator, u: *Unstructured) !Masks {
    return .{
        .info_summary = try arbitrary_bytes(arena, u),
        .dealer = try arbitrary_bytes(arena, u),
        .pub_msg = try arbitrary_bytes(arena, u),
        .log = try arbitrary_bytes(arena, u),
    };
}

/// At most `num` elements of `data` in random order (a partial Fisher-Yates shuffle).
fn pick(comptime T: type, u: *Unstructured, num: usize, data: []T) []T {
    const count = @min(num, data.len);
    for (0..count) |start| {
        std.mem.swap(T, &data[start], &data[u.int_in_range(usize, start, data.len - 1)]);
    }
    return data[0..count];
}

/// A random subset of `items`, as a sorted set (Rust's `BTreeSet`).
fn pick_set(comptime T: type, arena: Allocator, u: *Unstructured, items: []const T) ![]T {
    const num = u.int_in_range(usize, 0, items.len);
    if (num == 0) return &.{};
    const picked = pick(T, u, num, try arena.dupe(T, items));
    std.mem.sort(T, picked, {}, struct {
        fn less(_: void, a: T, b: T) bool {
            if (T == u32) return a < b;
            return a[0] < b[0] or (a[0] == b[0] and a[1] < b[1]);
        }
    }.less);
    return picked;
}

fn range(arena: Allocator, n: u32) ![]u32 {
    const out = try arena.alloc(u32, n);
    for (out, 0..) |*value, i| value.* = @intCast(i);
    return out;
}

/// commonware `arbitrary_round`: dealers (a quorum or more of the last successful players
/// when there is one), players, then each perturbation set in field order.
fn arbitrary_round(arena: Allocator, u: *Unstructured, n: u32, last: ?[]const u32) !Round {
    const dealers = if (last) |players| pick(
        u32,
        u,
        u.int_in_range(usize, N3f1.quorum(players.len), players.len),
        try arena.dupe(u32, players),
    ) else pick(u32, u, u.int_in_range(usize, 1, n), try range(arena, n));
    const players = pick(u32, u, u.int_in_range(usize, 1, n), try range(arena, n));
    const pairs = try arena.alloc([2]u32, dealers.len * players.len);
    for (dealers, 0..) |d, i| for (players, 0..) |p, j| {
        pairs[i * players.len + j] = .{ d, p };
    };
    const no_acks = try pick_set([2]u32, arena, u, pairs);
    const bad_shares = try pick_set([2]u32, arena, u, pairs);
    const sig_pairs = try pick_set([2]u32, arena, u, pairs);
    const bad_player_sigs = try arena.alloc(PlayerMasks, sig_pairs.len);
    for (bad_player_sigs, sig_pairs) |*entry, pair| {
        entry.* = .{ .dealer = pair[0], .player = pair[1], .masks = try arbitrary_masks(arena, u) };
    }
    const bad_reveals = try pick_set([2]u32, arena, u, pairs);
    const sig_dealers = try pick_set(u32, arena, u, dealers);
    const bad_dealer_sigs = try arena.alloc(DealerMasks, sig_dealers.len);
    for (bad_dealer_sigs, sig_dealers) |*entry, dealer| {
        entry.* = .{ .dealer = dealer, .masks = try arbitrary_masks(arena, u) };
    }
    const replace_shares = try pick_set(u32, arena, u, dealers);
    const shift_dealers = try pick_set(u32, arena, u, dealers);
    const shift_degrees = try arena.alloc(Shift, shift_dealers.len);
    const expected: i32 = @as(i32, @intCast(N3f1.quorum(players.len))) - 1;
    for (shift_degrees, shift_dealers) |*entry, dealer| {
        const magnitude = u.int_in_range(i32, 1, @max(expected, 1));
        const negative = try u.arbitrary(bool);
        entry.* = .{ .dealer = dealer, .shift = if (negative) -magnitude else magnitude };
    }
    return .{
        .dealers = dealers,
        .players = players,
        .no_acks = no_acks,
        .bad_shares = bad_shares,
        .bad_player_sigs = bad_player_sigs,
        .bad_reveals = bad_reveals,
        .bad_dealer_sigs = bad_dealer_sigs,
        .replace_shares = replace_shares,
        .shift_degrees = shift_degrees,
    };
}

/// commonware `Plan::arbitrary`, allocated in `arena`; `IncorrectFormat` when invalid.
pub fn arbitrary_plan(arena: Allocator, u: *Unstructured) !Plan {
    const n = u.int_in_range(u32, 1, max_num_participants);
    var rounds: std.ArrayList(Round) = .empty;
    var last: ?[]const u32 = null;
    // `arbitrary_loop(None, Some(max_rounds))`: a continuation bit before each round.
    while (rounds.items.len < max_rounds and (u.arbitrary(bool) catch false)) {
        const r = try arbitrary_round(arena, u, n, last);
        const previous: ?u32 = if (last) |p| @intCast(p.len) else null;
        if (!r.expect_failure(previous)) {
            const sorted = try arena.dupe(u32, r.players);
            std.mem.sort(u32, sorted, {}, std.sort.asc(u32));
            last = sorted;
        }
        try rounds.append(arena, r);
    }
    const plan: Plan = .{ .num_participants = n, .rounds = rounds.items };
    if (!plan.validate()) return UError.IncorrectFormat;
    return plan;
}
