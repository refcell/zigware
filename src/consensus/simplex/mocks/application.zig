//! A mock application for simplex tests (commonware `simplex/mocks/application.rs`): produces
//! and verifies payloads with simulated latency and relays them through a mock `Relay`.
//!
//! Commonware runs it as an actor answering oneshot requests one at a time. Here it is the
//! automaton itself, with blocking calls made from the voter's request tasks; one `busy` mutex
//! serializes the simulated work the way the actor's loop does, while a verification waiting
//! for its payload does not hold it (commonware parks such requests as waiters). Latency
//! samples come from p2p's `Normal`, drawn from the runtime RNG.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const p2p = @import("p2p");
const consensus_types = @import("../../types.zig");
const traits = @import("../../traits.zig");
const types = @import("../types.zig");
const lookahead = @import("../lookahead.zig");
const context = @import("../actors/context.zig");
const relay_mod = @import("relay.zig");

const Epoch = consensus_types.Epoch;
const Rnd = consensus_types.Round;
const Normal = p2p.simulated.Normal;

const genesis_bytes = "genesis";

/// `H::hash((Bytes::from("genesis"), epoch).encode())`.
pub fn genesis(comptime H: type, epoch: Epoch) H.Digest {
    var buffer: [1 + genesis_bytes.len + 10]u8 = undefined;
    var writer: codec.Writer = .init(&buffer);
    codec.write([]const u8, genesis_bytes, &writer);
    epoch.write(&writer);
    return H.hash(&.{writer.written()});
}

/// Simulated latency in milliseconds: `(mean, std_dev)`.
pub const Latency = struct { mean: f64, std_dev: f64 };

/// How certification requests are answered.
pub fn Certifier(comptime D: type) type {
    return union(enum) {
        /// Always certify.
        always,
        /// A predicate over the round and payload.
        custom: *const fn (round: Rnd, payload: D) bool,
        /// Drop the request (the voter sees a closed response).
        cancel,
        /// Never answer.
        pending,
    };
}

pub fn Config(comptime H: type, comptime P: type) type {
    return struct {
        relay: *relay_mod.Relay(H.Digest, P),
        /// Identifies the participant this instance serves.
        me: P,
        propose_latency: Latency,
        verify_latency: Latency,
        certify_latency: Latency,
        should_certify: Certifier(H.Digest) = .always,
    };
}

pub fn Application(comptime H: type, comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Digest = H.Digest;
        pub const Context = types.Context(H.Digest, P);
        const D = H.Digest;
        const Handoff = traits.Handoff(D);
        const Plan = lookahead.Plan(P);
        const Contents = std.AutoHashMapUnmanaged(D, []u8);
        /// `(Round, D, u64)` encoded.
        const contents_max = Rnd.max_encode_size + D.fixed_size + 8;

        gpa: Allocator,
        io: Io,
        me: P,
        relay: *relay_mod.Relay(D, P),
        propose_latency: Normal,
        verify_latency: Normal,
        certify_latency: Normal,
        should_certify: Certifier(D),
        fail_verification: bool = false,
        drop_proposals: bool = false,
        /// Holds `propose` (and `prepare` unless the decision is `wait`) open until canceled.
        stall_proposals: bool = false,
        drop_verifications: bool = false,
        /// Rejects a payload whose contents name another round or parent instead of
        /// panicking (commonware's `mocks` feature, which the consensus fuzzers enable).
        reject_mismatches: bool = false,
        /// The decision attached to a handoff candidate; `wait` builds nothing.
        handoff: std.meta.Tag(Handoff) = .wait,
        /// Guards the maps below and wakes verifications waiting for a payload.
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        /// Serializes simulated work, as commonware's actor loop does.
        busy: Io.Mutex = .init,
        pending: Contents = .empty,
        seen: Contents = .empty,

        /// Must not move after `register`: the relay holds its address.
        pub fn init(gpa: Allocator, io: Io, cfg: Config(H, P)) !Self {
            return .{
                .gpa = gpa,
                .io = io,
                .me = cfg.me,
                .relay = cfg.relay,
                .propose_latency = try .init(cfg.propose_latency.mean, cfg.propose_latency.std_dev),
                .verify_latency = try .init(cfg.verify_latency.mean, cfg.verify_latency.std_dev),
                .certify_latency = try .init(cfg.certify_latency.mean, cfg.certify_latency.std_dev),
                .should_certify = cfg.should_certify,
            };
        }

        /// Registers on the relay so broadcasts reach this instance.
        pub fn register(self: *Self) Allocator.Error!void {
            try self.relay.register(.{ .key = self.me, .context = self, .deliver = deliver });
        }

        fn free_contents(gpa: Allocator, map: *Contents) void {
            var values = map.valueIterator();
            while (values.next()) |value| gpa.free(value.*);
            map.deinit(gpa);
        }

        pub fn deinit(self: *Self) void {
            free_contents(self.gpa, &self.pending);
            free_contents(self.gpa, &self.seen);
            self.* = undefined;
        }

        fn deliver(opaque_self: *anyopaque, payload: D, contents: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(opaque_self));
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.remember(&self.seen, payload, contents);
            self.condition.broadcast(self.io);
        }

        /// Stores a copy of `contents` under `payload` (the caller holds `mutex`).
        fn remember(self: *Self, map: *Contents, payload: D, contents: []const u8) void {
            const entry = map.getOrPut(self.gpa, payload) catch @panic("out of memory");
            if (entry.found_existing) return;
            entry.value_ptr.* = self.gpa.dupe(u8, contents) catch @panic("out of memory");
        }

        /// Sleeps for one latency sample, in whole milliseconds (negative samples are zero).
        fn simulate(self: *Self, latency: Normal) Io.Cancelable!void {
            const rng: context.IoRng = .{ .io = self.io };
            const sample = latency.sample(rng);
            const millis: u64 = if (sample > 0) @intFromFloat(sample) else 0;
            try self.io.sleep(.fromMilliseconds(@intCast(millis)), .awake);
        }

        fn build(self: *Self, request: Context) Io.Cancelable!D {
            try self.simulate(self.propose_latency);
            var bytes: [8]u8 = undefined;
            self.io.random(&bytes);
            var buffer: [contents_max]u8 = undefined;
            var writer: codec.Writer = .init(&buffer);
            request.round.write(&writer);
            codec.write(D, request.parent[1], &writer);
            codec.write(u64, std.mem.readInt(u64, &bytes, .little), &writer);
            const contents = writer.written();
            const digest = H.hash(&.{contents});
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.remember(&self.pending, digest, contents);
            return digest;
        }

        /// Builds a payload on `request`'s parent. The parent need not be verified locally.
        pub fn propose(self: *Self, io: Io, request: Context) Io.Cancelable!?D {
            _ = io; // The same runtime as `self.io`.
            if (self.drop_proposals) return null;
            if (self.stall_proposals) try self.stall();
            try self.busy.lock(self.io);
            defer self.busy.unlock(self.io);
            return try self.build(request);
        }

        /// Never returns normally: waits until canceled (commonware parks the response).
        fn stall(self: *Self) Io.Cancelable!void {
            assert(self.stall_proposals);
            // Each sleep ends early only on cancelation.
            while (true) try self.io.sleep(.fromSeconds(3600), .awake);
        }

        /// Builds a handoff candidate unless the decision is `wait`.
        pub fn prepare(self: *Self, io: Io, request: Context) Io.Cancelable!?Handoff {
            _ = io; // The same runtime as `self.io`.
            if (self.handoff == .wait) return .wait;
            if (self.drop_proposals) return null;
            if (self.stall_proposals) try self.stall();
            try self.busy.lock(self.io);
            defer self.busy.unlock(self.io);
            const digest = try self.build(request);
            return switch (self.handoff) {
                .wait => unreachable, // Proof: handled above.
                .vote => .{ .vote = digest },
                .stage => .{ .stage = digest },
            };
        }

        /// Waits for `payload`'s contents, then checks they name `request`'s round and parent.
        pub fn verify(self: *Self, io: Io, request: Context, payload: D) Io.Cancelable!?bool {
            _ = io; // The same runtime as `self.io`.
            if (self.drop_verifications) return null;
            var contents: [contents_max]u8 = undefined;
            const len = try self.wait_for(payload, &contents);
            try self.busy.lock(self.io);
            defer self.busy.unlock(self.io);
            try self.simulate(self.verify_latency);
            if (self.fail_verification) return false;
            var reader: codec.Reader = .init(contents[0..len]);
            const round = Rnd.read(self.gpa, &reader, {}) catch @panic("invalid payload");
            const parent = codec.read(D, self.gpa, &reader) catch @panic("invalid payload");
            const matches = round == request.round and
                codec.order(D, parent, request.parent[1]) == .eq;
            if (!matches and self.reject_mismatches) return false;
            if (round != request.round) @panic("invalid round (in payload)");
            if (codec.order(D, parent, request.parent[1]) != .eq) {
                @panic("invalid parent (in payload)");
            }
            return true;
        }

        /// Copies `payload`'s contents into `out` once they have been seen.
        fn wait_for(self: *Self, payload: D, out: *[contents_max]u8) Io.Cancelable!usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Each wake re-checks the seen payloads; waits end on a delivery or cancel.
            while (true) {
                if (self.seen.get(payload)) |contents| {
                    assert(contents.len <= contents_max);
                    @memcpy(out[0..contents.len], contents);
                    return contents.len;
                }
                try self.condition.wait(self.io, &self.mutex);
            }
        }

        pub fn certify(self: *Self, io: Io, round: Rnd, payload: D) Io.Cancelable!?bool {
            _ = io; // The same runtime as `self.io`.
            {
                try self.busy.lock(self.io);
                defer self.busy.unlock(self.io);
                try self.simulate(self.certify_latency);
            }
            return switch (self.should_certify) {
                .always => true,
                .custom => |predicate| predicate(round, payload),
                .cancel => null,
                .pending => {
                    // Never answers: wait until canceled.
                    while (true) try self.io.sleep(.fromSeconds(3600), .awake);
                },
            };
        }

        /// Relays a payload as `plan` directs (commonware `Relay::broadcast`).
        pub fn broadcast(self: *Self, payload: D, plan: Plan) actor.Feedback {
            var buffer: [contents_max]u8 = undefined;
            const contents, const recipients = self.plan_contents(payload, plan, &buffer) orelse
                return .ok;
            self.relay.broadcast(self.me, recipients, payload, contents);
            return .ok;
        }

        fn plan_contents(
            self: *Self,
            payload: D,
            plan: Plan,
            out: *[contents_max]u8,
        ) ?struct { []const u8, p2p.Recipients(P) } {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const contents: []const u8, const recipients: p2p.Recipients(P) = switch (plan) {
                // A held candidate is sent on `prepare`; its later `propose` does not resend.
                .prepare => prepare: {
                    const held = self.pending.get(payload) orelse @panic("missing payload");
                    self.remember(&self.seen, payload, held);
                    break :prepare .{ held, .all };
                },
                .propose => propose: {
                    const held = self.pending.get(payload) orelse @panic("missing payload");
                    if (self.seen.contains(payload)) return null;
                    self.remember(&self.seen, payload, held);
                    break :propose .{ held, .all };
                },
                .forward => |forward| forward: {
                    const known = self.seen.get(payload) orelse self.pending.get(payload) orelse
                        return null;
                    self.remember(&self.seen, payload, known);
                    break :forward .{ known, forward.recipients };
                },
            };
            assert(contents.len <= contents_max);
            @memcpy(out[0..contents.len], contents);
            return .{ out[0..contents.len], recipients };
        }
    };
}
