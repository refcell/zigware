//! Feldman-Desmedt log selection (commonware `dkg::feldman_desmedt`): checking dealer logs
//! against a round (`check_dealer_log`), the `Logs` accumulator with its cached
//! `pre_verify` results, `select`, and `observe`, which computes a round's public output
//! from the agreed logs.
//!
//! Where commonware's `Failure::InsufficientLogs` carries data in an error, `select`,
//! `observe`, and `Player.finalize` return `error.InsufficientLogs` and fill an optional
//! `*Failure` with the counts, faults, and unavailable dealers.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const parallel = @import("parallel");
const math = @import("math");
const primitives = @import("../../primitives/root.zig");
const transcript_mod = @import("../../../transcript.zig");
const signer = @import("../../../signer.zig");
const messages = @import("messages.zig");
const round = @import("round.zig");

const Allocator = std.mem.Allocator;
const Set = utils.ordered.Set;
const Map = utils.ordered.Map;
const Transcript = transcript_mod.Transcript;
const Summary = transcript_mod.Summary;
const Scalar = primitives.group.Scalar;
const Sharing = primitives.sharing.Sharing;
const Poly = primitives.sharing.Poly;
const DealerLog = messages.DealerLog;
const Output = messages.Output;
const Info = round.Info;

/// Why a configured dealer's signed log proves a protocol fault.
pub const FaultReason = union(enum) {
    /// An acknowledgement signature does not verify.
    invalid_ack,
    /// A reveal does not match the dealer's commitment.
    invalid_reveal,
    invalid_commitment_degree: struct { expected: u32, actual: u32 },
    /// A reshare commitment does not preserve the dealer's previous share.
    mismatched_reshare_commitment,
    /// The log's player set differs from the round's.
    mismatched_log_players,
    /// The log publishes more than `max_reveals` reveals. A log that omits its results
    /// (`too_many_reveals`) is unavailable, not faulty.
    excessive_reveals,
};

/// The result of checking one dealer log (commonware `Result<DealerLogOutcome,
/// DealerLogError>`).
pub const Check = union(enum) {
    /// The configured dealer's log holds verified results.
    available,
    /// The configured dealer omitted its results to avoid excessive reveals.
    unavailable,
    /// The identity is not a dealer in the round.
    unexpected_dealer,
    fault: FaultReason,

    pub fn eql(a: Check, b: Check) bool {
        return std.meta.eql(a, b);
    }
};

/// Why a round failed: too few usable dealer logs (commonware `Failure::InsufficientLogs`).
pub fn Failure(comptime P: type) type {
    return struct {
        const Self = @This();

        pub const Fault = struct { dealer: P, reason: FaultReason };

        required: u32,
        found: u32,
        /// Configured dealers whose signed logs prove a fault, sorted by dealer. Attribution
        /// assumes `record` receives only pairs that passed `check_log`.
        faults: []Fault,
        /// Configured dealers with no usable log, including missing logs and logs that omit
        /// their results.
        unavailable: Set(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.faults);
            self.unavailable.deinit(gpa);
            self.* = undefined;
        }

        /// The fault proven by `dealer`'s log, if any.
        pub fn fault(self: *const Self, dealer: P) ?FaultReason {
            for (self.faults) |entry| {
                if (utils.ordered.order(P, entry.dealer, dealer) == .eq) return entry.reason;
            }
            return null;
        }
    };
}

/// Checks `log` from `dealer` against `info`'s round under fault model `M`: membership,
/// the public message, the player set, the reveal count, every ack signature (one batch),
/// and every reveal (one random linear combination). `rng` draws the batch randomness, and
/// `strategy` runs the ack batch.
pub fn check_dealer_log(
    comptime V: type,
    comptime P: type,
    comptime M: type,
    gpa: Allocator,
    rng: anytype,
    strategy: anytype,
    info: *const Info(V, P),
    round_transcript: *const Transcript,
    dealer: P,
    log: *const DealerLog(V, P),
) Allocator.Error!Check {
    if (info.dealer_index(dealer) == null) return .unexpected_dealer;
    if (pub_msg_fault(V, P, M, info, dealer, log)) |fault| return .{ .fault = fault };
    const results = log.results_for(info.players) catch {
        return .{ .fault = .mismatched_log_players };
    } orelse return .unavailable;
    const ack = try round.transcript_for_ack(gpa, round_transcript, V, P, dealer, log.pub_msg);
    const ack_summary = ack.summarize();
    var acks: std.ArrayList(signer.BatchEntry(P)) = .empty;
    defer acks.deinit(gpa);
    var pairs: std.ArrayList([2]Scalar) = .empty;
    defer pairs.deinit(gpa);
    var reveal_sum = Scalar.zero;
    defer reveal_sum.zeroize();
    const max_reveals = info.max_reveals(M);
    for (info.players.items, results) |*player, *result| switch (result.*) {
        // The summary binds the namespace: Transcript.sign signs under an empty one.
        .ack => |*value| try acks.append(gpa, .{
            .namespace = "",
            .message = &ack_summary.bytes,
            .public_key = player,
            .signature = &value.sig,
        }),
        .reveal => |priv_msg| {
            if (pairs.items.len == max_reveals) return .{ .fault = .excessive_reveals };
            const coeff = if (pairs.items.len == 0) Scalar.one else Scalar.random(rng);
            try pairs.append(gpa, .{ coeff, info.player_scalar(player.*).? });
            reveal_sum = reveal_sum.add(coeff.mul(priv_msg.share));
        },
    };
    if (!P.verify_batch(rng, acks.items, signer.entries, strategy)) {
        return .{ .fault = .invalid_ack };
    }
    const lhs = try log.pub_msg.commitment.lin_comb_eval(gpa, Scalar, pairs.items);
    if (!lhs.eql(V.Public.generator.mul(reveal_sum))) return .{ .fault = .invalid_reveal };
    return .available;
}

fn pub_msg_fault(
    comptime V: type,
    comptime P: type,
    comptime M: type,
    info: *const Info(V, P),
    dealer: P,
    log: *const DealerLog(V, P),
) ?FaultReason {
    info.check_dealer_pub_msg(M, dealer, log.pub_msg) catch |err| return switch (err) {
        error.InvalidCommitmentDegree => .{ .invalid_commitment_degree = .{
            .expected = info.degree(M),
            .actual = log.pub_msg.commitment.degree_exact(),
        } },
        error.MismatchedReshareCommitment => .mismatched_reshare_commitment,
    };
    return null;
}

/// Accumulates the dealer logs of one round, caching check results so `pre_verify` work is
/// reused until a dealer's log is replaced. Borrows its `Info`; owns the recorded logs.
pub fn Logs(comptime V: type, comptime P: type, comptime M: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct {
            dealer: P,
            log: DealerLog(V, P),
            /// Null until checked.
            known: ?Check = null,
        };

        info: *const Info(V, P),
        /// Sorted by dealer, without duplicates.
        entries: std.ArrayList(Entry) = .empty,

        pub fn init(info: *const Info(V, P)) Self {
            return .{ .info = info };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.entries.items) |*entry| entry.log.deinit(gpa);
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var out: Self = .init(self.info);
            errdefer out.deinit(gpa);
            try out.entries.ensureTotalCapacity(gpa, self.entries.items.len);
            for (self.entries.items) |entry| {
                var copy = entry;
                copy.log = try entry.log.clone(gpa);
                out.entries.appendAssumeCapacity(copy);
            }
            return out;
        }

        fn search(self: *const Self, dealer: P) struct { found: bool, index: usize } {
            const items = self.entries.items;
            var low: usize = 0;
            var high: usize = items.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                switch (utils.ordered.order(P, items[mid].dealer, dealer)) {
                    .eq => return .{ .found = true, .index = mid },
                    .lt => low = mid + 1,
                    .gt => high = mid,
                }
            }
            return .{ .found = false, .index = low };
        }

        /// Records `dealer`'s log, taking ownership of it, and returns whether it replaced
        /// an earlier log. Does not authenticate the log: faults are attributable only for
        /// pairs that passed `check_log`.
        pub fn record(self: *Self, gpa: Allocator, dealer: P, log: DealerLog(V, P)) !bool {
            const slot = self.search(dealer);
            if (slot.found) {
                const entry = &self.entries.items[slot.index];
                entry.log.deinit(gpa);
                entry.* = .{ .dealer = dealer, .log = log };
                return true;
            }
            var owned = log;
            errdefer owned.deinit(gpa);
            try self.entries.insert(gpa, slot.index, .{ .dealer = dealer, .log = owned });
            return false;
        }

        /// The cached check for `dealer`, if its log has been checked.
        pub fn known(self: *const Self, dealer: P) ?Check {
            const slot = self.search(dealer);
            return if (slot.found) self.entries.items[slot.index].known else null;
        }

        /// The recorded log of `dealer`.
        pub fn get(self: *const Self, dealer: P) ?*const DealerLog(V, P) {
            const slot = self.search(dealer);
            return if (slot.found) &self.entries.items[slot.index].log else null;
        }

        /// Checks `pending` entries (indices into `entries`) across `strategy`, as commonware's
        /// `check_dealers` does. Each check draws its randomness from a seed taken from `rng`
        /// up front, so results do not depend on the order or the thread checks run on.
        fn check_dealers(
            self: *Self,
            gpa: Allocator,
            rng: anytype,
            pending: []const usize,
            strategy: anytype,
        ) !void {
            const jobs = try gpa.alloc(Job, pending.len);
            defer gpa.free(jobs);
            for (jobs, pending) |*job, index| {
                job.* = .{ .index = index, .seed = undefined };
                rng.fill_bytes(&job.seed.bytes);
            }
            const checks = try gpa.alloc(Check, pending.len);
            defer gpa.free(checks);
            const op: CheckOp(@TypeOf(strategy)) = .{
                .logs = self,
                .gpa = gpa,
                .strategy = strategy,
                .transcript = self.info.round_transcript(),
            };
            try strategy.try_map_into(jobs, checks, op);
            for (jobs, checks) |job, check| self.entries.items[job.index].known = check;
            assert(checks.len == pending.len);
        }

        const Job = struct { index: usize, seed: Summary };

        fn CheckOp(comptime S: type) type {
            return struct {
                logs: *const Self,
                gpa: Allocator,
                strategy: S,
                transcript: Transcript,

                pub fn map(op: @This(), job: *const Job) Allocator.Error!Check {
                    const entry = &op.logs.entries.items[job.index];
                    assert(entry.known == null);
                    const resumed = Transcript.resume_from(job.seed, round.transcript_version);
                    var local_rng = resumed.noise(round.noise_pre_verify);
                    return check_dealer_log(
                        V,
                        P,
                        M,
                        op.gpa,
                        &local_rng,
                        op.strategy,
                        op.logs.info,
                        &op.transcript,
                        entry.dealer,
                        &entry.log,
                    );
                }
            };
        }

        /// Checks the logs recorded so far, so `select` has less to do. Optimistically
        /// checks only as many unchecked logs as are still needed; if any of those fail, it
        /// checks every remaining unchecked log.
        pub fn pre_verify(self: *Self, gpa: Allocator, rng: anytype, strategy: anytype) !void {
            var need = self.info.required_commitments(M);
            var pending: std.ArrayList(usize) = .empty;
            defer pending.deinit(gpa);
            var cursor: usize = 0;
            while (need > 0 and cursor < self.entries.items.len) : (cursor += 1) {
                const entry = self.entries.items[cursor];
                if (entry.known) |check| {
                    if (check == .available) need -= 1;
                } else {
                    need -= 1;
                    try pending.append(gpa, cursor);
                }
            }
            try self.check_dealers(gpa, rng, pending.items, strategy);
            var all_usable = true;
            for (pending.items) |index| all_usable = all_usable and
                self.entries.items[index].known.? == .available;
            if (all_usable) return;
            // Some dealers misbehaved and may try to waste our time: assume the worst and
            // check everything left.
            pending.clearRetainingCapacity();
            for (self.entries.items[cursor..], cursor..) |entry, index| {
                if (entry.known == null) try pending.append(gpa, index);
            }
            try self.check_dealers(gpa, rng, pending.items, strategy);
        }

        /// The first `required_commitments` usable logs in dealer order, borrowed from
        /// `self`, or `error.InsufficientLogs` (filling `failure` when given).
        pub fn select(
            self: *Self,
            gpa: Allocator,
            rng: anytype,
            failure: ?*Failure(P),
            strategy: anytype,
        ) !Selection(V, P) {
            try self.pre_verify(gpa, rng, strategy);
            const required = self.info.required_commitments(M);
            var dealers: std.ArrayList(P) = .empty;
            defer dealers.deinit(gpa);
            var logs: std.ArrayList(*const DealerLog(V, P)) = .empty;
            defer logs.deinit(gpa);
            for (self.entries.items) |*entry| {
                if (dealers.items.len == required) break;
                const check = entry.known orelse continue;
                if (check != .available) continue;
                try dealers.append(gpa, entry.dealer);
                try logs.append(gpa, &entry.log);
            }
            if (dealers.items.len < required) {
                if (failure) |out| out.* = try self.describe_failure(
                    gpa,
                    @intCast(dealers.items.len),
                );
                return error.InsufficientLogs;
            }
            const keys: Set(P) = .{ .items = try dealers.toOwnedSlice(gpa) };
            const values = logs.toOwnedSlice(gpa) catch |err| {
                gpa.free(keys.items);
                return err;
            };
            return .{ .dealers = keys, .logs = values };
        }

        fn describe_failure(
            self: *const Self,
            gpa: Allocator,
            found: u32,
        ) Allocator.Error!Failure(P) {
            var unavailable: std.ArrayList(P) = .empty;
            defer unavailable.deinit(gpa);
            for (self.info.dealers.items) |dealer| {
                const check = self.known(dealer) orelse {
                    try unavailable.append(gpa, dealer);
                    continue;
                };
                if (check == .unavailable or check == .unexpected_dealer) {
                    try unavailable.append(gpa, dealer);
                }
            }
            // Entries are sorted by dealer, so the faults are too.
            var faults: std.ArrayList(Failure(P).Fault) = .empty;
            defer faults.deinit(gpa);
            for (self.entries.items) |entry| {
                const check = entry.known orelse continue;
                if (check != .fault) continue;
                try faults.append(gpa, .{ .dealer = entry.dealer, .reason = check.fault });
            }
            var unavailable_set = try Set(P).from_dedup(gpa, unavailable.items);
            errdefer unavailable_set.deinit(gpa);
            return .{
                .required = self.info.required_commitments(M),
                .found = found,
                .faults = try faults.toOwnedSlice(gpa),
                .unavailable = unavailable_set,
            };
        }
    };
}

/// The selected dealers (sorted) and their logs, borrowed from the `Logs` that selected
/// them.
pub fn Selection(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        dealers: Set(P),
        logs: []*const DealerLog(V, P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.dealers.deinit(gpa);
            gpa.free(self.logs);
            self.* = undefined;
        }

        pub fn len(self: Self) usize {
            assert(self.dealers.len() == self.logs.len);
            return self.logs.len;
        }
    };
}

/// A round's public output and, for a reshare, the interpolator over the selected dealers.
pub fn Observed(comptime V: type, comptime P: type) type {
    return struct {
        output: Output(V, P),
        weights: ?math.poly.Interpolator(P, Scalar),
    };
}

/// The players whose shares at least `reveal_threshold` selected dealers revealed.
fn revealed_players(
    comptime V: type,
    comptime P: type,
    comptime M: type,
    gpa: Allocator,
    info: *const Info(V, P),
    selected: Selection(V, P),
) Allocator.Error!Set(P) {
    const threshold = info.reveal_threshold(M);
    const counts = try gpa.alloc(u32, info.players.len());
    defer gpa.free(counts);
    @memset(counts, 0);
    var revealed: std.ArrayList(P) = .empty;
    defer revealed.deinit(gpa);
    for (selected.logs) |log| {
        // Proof: `select` keeps only logs whose results match the round's players.
        const results = (log.results_for(info.players) catch unreachable).?;
        for (results, counts, info.players.items) |result, *count, player| {
            if (!result.is_reveal()) continue;
            count.* += 1;
            if (count.* == threshold) try revealed.append(gpa, player);
        }
    }
    return Set(P).from_dedup(gpa, revealed.items);
}

/// Interpolates the selected reshare commitments coefficient by coefficient.
fn interpolate_commitments(
    comptime V: type,
    comptime P: type,
    gpa: Allocator,
    weights: math.poly.Interpolator(P, Scalar),
    selected: Selection(V, P),
    strategy: anytype,
) Allocator.Error!Poly(V.Public) {
    assert(selected.len() > 0);
    const count = selected.logs[0].pub_msg.commitment.coeffs.len;
    const coeffs = try gpa.alloc(V.Public, count);
    errdefer gpa.free(coeffs);
    const column = try gpa.alloc(V.Public, selected.len());
    defer gpa.free(column);
    for (coeffs, 0..) |*coeff, c| {
        for (column, selected.logs) |*value, log| {
            // Proof: `select` checked that every commitment has the round's degree.
            assert(log.pub_msg.commitment.coeffs.len == count);
            value.* = log.pub_msg.commitment.coeffs[c];
        }
        // Proof: `select` keeps only dealers in the interpolator's subset.
        coeff.* = (try weights.interpolate_strategy(
            V.Public,
            gpa,
            selected.dealers.items,
            column,
            strategy,
        )).?;
    }
    return Poly(V.Public).from_owned(coeffs);
}

/// The public polynomial (and reshare weights) of the selected logs: the sum of their
/// commitments, or for a reshare their interpolation, which keeps the previous public key.
fn public_poly(
    comptime V: type,
    comptime P: type,
    gpa: Allocator,
    info: *const Info(V, P),
    selected: Selection(V, P),
    weights_out: *?math.poly.Interpolator(P, Scalar),
    strategy: anytype,
) !Poly(V.Public) {
    const previous = info.previous orelse {
        var public = try Poly(V.Public).zero(gpa);
        errdefer public.deinit(gpa);
        for (selected.logs) |log| try public.add_assign(gpa, log.pub_msg.commitment);
        weights_out.* = null;
        return public;
    };
    const mode = previous.public.mode;
    // Proof: `Info.init` checked that the dealers are previous players.
    var weights = (try mode.subset_interpolator(
        P,
        gpa,
        previous.players.items,
        selected.dealers.items,
    )).?;
    errdefer weights.deinit(gpa);
    const public = try interpolate_commitments(V, P, gpa, weights, selected, strategy);
    // Each commitment's constant is the dealer's previous share commitment, so a valid
    // subset interpolates to the previous public key.
    assert(previous.public.public().eql(public.constant()));
    weights_out.* = weights;
    return public;
}

/// Computes the round's output from the selected logs (commonware `Observe::reckon`).
pub fn reckon(
    comptime V: type,
    comptime P: type,
    comptime M: type,
    gpa: Allocator,
    info: *const Info(V, P),
    selected: Selection(V, P),
    strategy: anytype,
) !Observed(V, P) {
    var revealed = try revealed_players(V, P, M, gpa, info, selected);
    errdefer revealed.deinit(gpa);
    var weights: ?math.poly.Interpolator(P, Scalar) = null;
    var public = try public_poly(V, P, gpa, info, selected, &weights, strategy);
    errdefer if (weights) |*w| w.deinit(gpa);
    var sharing = Sharing(V).init(gpa, info.mode, info.num_players(), public) catch |err| {
        public.deinit(gpa);
        return err;
    };
    errdefer sharing.deinit(gpa);
    var dealers = try selected.dealers.clone(gpa);
    errdefer dealers.deinit(gpa);
    const players = try info.players.clone(gpa);
    return .{
        .output = .{
            .summary = info.summary,
            .public = sharing,
            .dealers = dealers,
            .players = players,
            .revealed = revealed,
        },
        .weights = weights,
    };
}

/// The round's public output from the agreed logs, or `error.InsufficientLogs` (filling
/// `failure` when given). Every participant must agree on the logs.
pub fn observe(
    comptime V: type,
    comptime P: type,
    comptime M: type,
    gpa: Allocator,
    rng: anytype,
    logs: *Logs(V, P, M),
    failure: ?*Failure(P),
    strategy: anytype,
) !Output(V, P) {
    var selected = try logs.select(gpa, rng, failure, strategy);
    defer selected.deinit(gpa);
    var observed = try reckon(V, P, M, gpa, logs.info, selected, strategy);
    if (observed.weights) |*weights| weights.deinit(gpa);
    return observed.output;
}
