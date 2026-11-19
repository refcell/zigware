//! The voter-actor test harness (commonware `simplex/actors/voter/mod.rs` test helpers):
//! one voter actor over the mock application, relay, and reporter, with its batcher and
//! resolver mailboxes held by the test (`setup_voter`, `start_voter_with_floor`), plus the
//! certificate builders and journal seeding the tests share. `Harness(F)` is generic over a
//! signing fixture `F`, the way commonware runs these tests over every scheme; `fixtures`
//! lists them, and tests/root.zig runs ed25519 per push and all of them with `-Dslow-tests`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor_pkg = @import("actor");
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const parallel = @import("parallel");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const consensus_types = @import("../../../../types.zig");
const types = @import("../../../types.zig");
const config_mod = @import("../../../config.zig");
pub const elector_mod = @import("../../../elector.zig");
const build_options = @import("build_options");
const ed25519 = @import("../../../scheme/ed25519.zig");
const secp256r1 = @import("../../../scheme/secp256r1.zig");
const multisig = @import("../../../scheme/bls12381_multisig.zig");
const vrf = @import("../../../scheme/bls12381_threshold/vrf.zig");
const application_mod = @import("../../../mocks/application.zig");
const relay_mod = @import("../../../mocks/relay.zig");
const reporter_mod = @import("../../../mocks/reporter.zig");
const voter = @import("../actor.zig");
const traits_mod = @import("../../../../traits.zig");
const batcher_ingress = @import("../../batcher/ingress.zig");
const resolver_ingress = @import("../../resolver/ingress.zig");

const Sha = cryptography.Sha256;
const PeerKey = cryptography.ed25519.PublicKey;
const RoundRobinConfig = elector_mod.RoundRobin(Sha);
const primitives = cryptography.bls12381.primitives;

/// A fixture electing round robin from the test's elector config.
fn RoundRobinFixture(comptime S: type, comptime module: type, comptime kind: Kind) type {
    return struct {
        pub const Scheme = S;
        pub const Elector = elector_mod.RoundRobinElector;
        pub const fixture_kind = kind;
        pub const random_elector = false;

        pub fn make(
            gpa: Allocator,
            rng: anytype,
            namespace: []const u8,
            n: u32,
        ) !cryptography.certificate.mocks.Fixture(S) {
            if (kind == .ed25519) return module.fixture(Sha.Digest, gpa, rng, namespace, n);
            return module.fixture(S, gpa, rng, namespace, n);
        }

        pub fn build_elector(gpa: Allocator, n: u32, config: RoundRobinConfig) !Elector {
            return config.build(gpa, n);
        }

        pub fn deinit_elector(elector: *Elector, gpa: Allocator) void {
            elector.deinit(gpa);
        }
    };
}

/// A threshold VRF fixture with commonware's `Random::new(RandomVersion::V1)` elector.
fn RandomVrfFixture(comptime V: type) type {
    return struct {
        pub const Scheme = vrf.Scheme(Sha.Digest, PeerKey, V);
        pub const Elector = elector_mod.RandomElector(Sha, V);
        pub const fixture_kind: Kind = .vrf;
        pub const random_elector = true;

        pub fn make(
            gpa: Allocator,
            rng: anytype,
            namespace: []const u8,
            n: u32,
        ) !cryptography.certificate.mocks.Fixture(Scheme) {
            return vrf.fixture(Scheme, gpa, rng, namespace, n);
        }

        pub fn build_elector(gpa: Allocator, n: u32, config: RoundRobinConfig) !Elector {
            _ = gpa;
            _ = config; // Tests that configure terms run on round-robin fixtures only.
            return elector_mod.Random(Sha).init(.v1).build(V, n);
        }

        pub fn deinit_elector(_: *Elector, _: Allocator) void {}
    };
}

pub const Kind = enum { ed25519, secp256r1, multisig, vrf };

pub const Ed25519Fixture = RoundRobinFixture(ed25519.Scheme(Sha.Digest), ed25519, .ed25519);

/// commonware's six voter-test schemes, in its order. The threshold VRF schemes appear twice:
/// with the Random elector commonware passes to elector-generic tests, and with round robin
/// for the tests that fix it.
pub const fixtures = .{
    RandomVrfFixture(primitives.MinPk),
    RandomVrfFixture(primitives.MinSig),
    RoundRobinFixture(vrf.Scheme(Sha.Digest, PeerKey, primitives.MinPk), vrf, .vrf),
    RoundRobinFixture(vrf.Scheme(Sha.Digest, PeerKey, primitives.MinSig), vrf, .vrf),
    RoundRobinFixture(multisig.Scheme(Sha.Digest, PeerKey, primitives.MinPk), multisig, .multisig),
    RoundRobinFixture(multisig.Scheme(Sha.Digest, PeerKey, primitives.MinSig), multisig, .multisig),
    Ed25519Fixture,
    RoundRobinFixture(secp256r1.Scheme(Sha.Digest, PeerKey), secp256r1, .secp256r1),
};

/// Which fixtures a ported test runs on (commonware's per-test fixture lists).
pub const Coverage = enum {
    /// commonware runs it over ed25519 only.
    ed25519,
    /// Over all six schemes with the test's elector: Random for threshold VRF.
    schemes,
    /// Over all six schemes with round robin (the test fixes the elector).
    schemes_round_robin,
};

/// Whether fixture `F` runs tests of `coverage` in this build.
pub fn runs(comptime F: type, comptime coverage: Coverage) bool {
    if (F.fixture_kind != .ed25519 and !build_options.slow_tests) return false;
    return switch (coverage) {
        .ed25519 => F.fixture_kind == .ed25519,
        .schemes => F.fixture_kind != .vrf or F.random_elector,
        .schemes_round_robin => !F.random_elector,
    };
}

/// The voter harness over fixture `F`.
pub fn Harness(comptime F: type) type {
    return struct {
        pub const fixture_type = F;

        /// Skips the calling test unless it runs on this fixture.
        pub fn covers(comptime coverage: Coverage) error{SkipZigTest}!void {
            if (!comptime runs(F, coverage)) return error.SkipZigTest;
        }

        pub const Sha256 = cryptography.Sha256;
        pub const Digest = Sha256.Digest;
        pub const Key = cryptography.ed25519.PublicKey;
        pub const Scheme = F.Scheme;
        pub const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
        pub const Net = p2p.simulated.Network(Key);
        pub const Ctx = runtime.deterministic.Context;
        pub const Application = application_mod.Application(Sha256, Key);
        pub const Relay = relay_mod.Relay(Digest, Key);
        pub const Reporter = reporter_mod.Reporter(Scheme, Digest);
        pub const Elector = F.Elector;
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

        /// Which certification requests the test answers itself (commonware's
        /// `Certifier::Controlled` and `hold(view, ..)`); `none` lets the application answer.
        pub const Hold = union(enum) { none, all, view: u64 };

        /// The mock application as the voter's automaton, recording each request when it
        /// arrives (commonware's `set_propose_observer` and `set_verify_observer`).
        pub const Automaton = struct {
            pub const Context = harness_context;
            pub const Digest = Sha256.Digest;
            const D = Sha256.Digest;
            const requests_max = 256;

            application: *Application,
            io: Io,
            mutex: Io.Mutex = .init,
            proposals: [requests_max]Context = undefined,
            proposals_count: u32 = 0,
            verifications: [requests_max]View = undefined,
            verifications_count: u32 = 0,
            hold: Hold = .none,
            held: [requests_max]Held = undefined,
            held_count: u32 = 0,
            hold_handoffs: bool = false,
            handoffs: [requests_max]HeldHandoff = undefined,
            handoffs_count: u32 = 0,
            /// When set, `verify` holds each request until the voter drops it (commonware
            /// `set_verify_holder`).
            hold_verifications: bool = false,
            dropped: [requests_max]View = undefined,
            dropped_count: u32 = 0,
            /// Certification requests received (commonware's tracking `Certifier::Custom`).
            certify_calls: u32 = 0,

            /// A built handoff candidate the test answers.
            pub const HeldHandoff = struct {
                view: View,
                candidate: traits_mod.Handoff(D),
                taken: bool = false,
                /// The voter canceled the request (commonware's `is_closed`).
                closed: bool = false,
                answer: ?traits_mod.Handoff(D) = null,
                answered: Io.Event = .unset,

                pub fn is_closed(self: *const HeldHandoff) bool {
                    return @atomicLoad(bool, &self.closed, .acquire);
                }

                /// The candidate's payload.
                pub fn digest(self: *const HeldHandoff) D {
                    return switch (self.candidate) {
                        .vote, .stage => |payload| payload,
                        .wait => unreachable, // Wait is answered without holding.
                    };
                }
            };

            /// A certification request the test answers.
            pub const Held = struct {
                view: View,
                taken: bool = false,
                answer: bool = false,
                answered: Io.Event = .unset,
                /// The voter canceled the request (commonware's `is_closed`).
                closed: bool = false,

                pub fn is_closed(self: *const Held) bool {
                    return @atomicLoad(bool, &self.closed, .acquire);
                }
            };

            fn record_proposal(self: *Automaton, request: harness_context) void {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                assert(self.proposals_count < requests_max);
                self.proposals[self.proposals_count] = request;
                self.proposals_count += 1;
            }

            pub fn propose(self: *Automaton, io: Io, request: harness_context) Io.Cancelable!?D {
                self.record_proposal(request);
                return self.application.propose(io, request);
            }

            pub fn prepare(
                self: *Automaton,
                io: Io,
                request: harness_context,
            ) Io.Cancelable!?traits_mod.Handoff(D) {
                self.record_proposal(request);
                const built = try self.application.prepare(io, request) orelse return null;
                if (!self.hold_handoffs or built == .wait) return built;
                // commonware's handoff controller: the test answers the built candidate.
                const slot = self.park_handoff(request.round.view, built);
                slot.answered.wait(self.io) catch |err| {
                    @atomicStore(bool, &slot.closed, true, .release);
                    return err;
                };
                return slot.answer;
            }

            fn park_handoff(
                self: *Automaton,
                view: View,
                built: traits_mod.Handoff(D),
            ) *HeldHandoff {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                assert(self.handoffs_count < requests_max);
                const slot = &self.handoffs[self.handoffs_count];
                slot.* = .{ .view = view, .candidate = built };
                self.handoffs_count += 1;
                return slot;
            }

            /// Takes the newest held handoff candidate, waiting up to 5 s of simulated time
            /// (commonware `take_proposal_response`).
            pub fn take_handoff(self: *Automaton, ctx: Ctx) !*HeldHandoff {
                var waited: u64 = 0;
                while (waited < 5_000) : (waited += 1) {
                    if (self.newest_handoff()) |slot| return slot;
                    try ctx.sleep(.fromMilliseconds(1));
                }
                return error.NoHandoffRequest;
            }

            fn newest_handoff(self: *Automaton) ?*HeldHandoff {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                var index = self.handoffs_count;
                while (index > 0) {
                    index -= 1;
                    const slot = &self.handoffs[index];
                    if (slot.taken) continue;
                    slot.taken = true;
                    return slot;
                }
                return null;
            }

            /// Answers a taken handoff request; `null` drops it (commonware drops the sender).
            pub fn answer_handoff(
                self: *Automaton,
                slot: *HeldHandoff,
                answer: ?traits_mod.Handoff(D),
            ) void {
                assert(slot.taken);
                slot.answer = answer;
                slot.answered.set(self.io);
            }

            /// Proposal and handoff requests received for `view`.
            pub fn requests_for(self: *Automaton, view: u64) u32 {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                var count: u32 = 0;
                for (self.proposals[0..self.proposals_count]) |request| {
                    count += @intFromBool(request.round.view.get() == view);
                }
                return count;
            }

            /// The `index`th recorded proposal request for `view`.
            pub fn request_for(self: *Automaton, view: u64, index: u32) ?harness_context {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                var seen: u32 = 0;
                for (self.proposals[0..self.proposals_count]) |request| {
                    if (request.round.view.get() != view) continue;
                    if (seen == index) return request;
                    seen += 1;
                }
                return null;
            }

            pub fn verify(
                self: *Automaton,
                io: Io,
                request: harness_context,
                payload: D,
            ) Io.Cancelable!?bool {
                {
                    self.mutex.lockUncancelable(self.io);
                    defer self.mutex.unlock(self.io);
                    assert(self.verifications_count < requests_max);
                    self.verifications[self.verifications_count] = request.round.view;
                    self.verifications_count += 1;
                }
                if (self.hold_verifications) return self.hold_verification(request.round.view);
                return self.application.verify(io, request, payload);
            }

            /// Never answers: waits until the voter cancels the request, then records it.
            fn hold_verification(self: *Automaton, view: View) Io.Cancelable!?bool {
                assert(self.hold_verifications);
                assert(view.get() > 0);
                // Bounded by the voter: it ends only when the request is canceled.
                while (true) {
                    self.io.sleep(.fromSeconds(3600), .awake) catch |err| {
                        self.mutex.lockUncancelable(self.io);
                        defer self.mutex.unlock(self.io);
                        assert(self.dropped_count < requests_max);
                        self.dropped[self.dropped_count] = view;
                        self.dropped_count += 1;
                        return err;
                    };
                }
            }

            pub fn certify(self: *Automaton, io: Io, at: Round, payload: D) Io.Cancelable!?bool {
                _ = @atomicRmw(u32, &self.certify_calls, .Add, 1, .acq_rel);
                const held = switch (self.hold) {
                    .none => return self.application.certify(io, at, payload),
                    .all => true,
                    .view => |view| at.view.get() == view,
                };
                // commonware's `Certifier::Controlled` answers the others at once.
                if (!held) return true;
                const slot = self.park_certification(at.view);
                slot.answered.wait(self.io) catch |err| {
                    @atomicStore(bool, &slot.closed, true, .release);
                    return err;
                };
                return slot.answer;
            }

            fn park_certification(self: *Automaton, view: View) *Held {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                assert(self.held_count < requests_max);
                const slot = &self.held[self.held_count];
                slot.* = .{ .view = view };
                self.held_count += 1;
                return slot;
            }

            /// Takes the held certification request for `view`, waiting up to 5 s of
            /// simulated time (commonware `take_certification_request`).
            pub fn take_certification(self: *Automaton, ctx: Ctx, view: u64) !*Held {
                var waited: u64 = 0;
                while (waited < 5_000) : (waited += 1) {
                    if (self.find_held(view, true)) |slot| return slot;
                    try ctx.sleep(.fromMilliseconds(1));
                }
                return error.NoCertificationRequest;
            }

            /// Whether a held certification request for `view` has arrived (taken or not).
            pub fn certification_requested(self: *Automaton, view: u64) bool {
                return self.find_held(view, false) != null;
            }

            fn find_held(self: *Automaton, view: u64, take: bool) ?*Held {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                for (self.held[0..self.held_count]) |*slot| {
                    if (slot.view.get() != view or (take and slot.taken)) continue;
                    if (take) slot.taken = true;
                    return slot;
                }
                return null;
            }

            /// Answers a taken certification request.
            pub fn answer_certification(self: *Automaton, slot: *Held, answer: bool) void {
                assert(slot.taken);
                slot.answer = answer;
                slot.answered.set(self.io);
            }

            /// Whether a proposal (or handoff) request for `view` arrived.
            pub fn proposal_requested(self: *Automaton, view: u64) bool {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                for (self.proposals[0..self.proposals_count]) |request| {
                    if (request.round.view.get() == view) return true;
                }
                return false;
            }

            /// Whether a verification request for `view` arrived.
            pub fn verification_requested(self: *Automaton, view: u64) bool {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                for (self.verifications[0..self.verifications_count]) |requested| {
                    if (requested.get() == view) return true;
                }
                return false;
            }

            /// Whether the voter dropped a held verification of `view` (commonware's held
            /// response `is_closed`).
            pub fn verification_dropped(self: *Automaton, view: u64) bool {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                for (self.dropped[0..self.dropped_count]) |dropped| {
                    if (dropped.get() == view) return true;
                }
                return false;
            }
        };

        pub const Params = struct {
            pub const Scheme = harness_scheme;
            pub const Elector = F.Elector;
            pub const Digest = harness_digest;
            pub const Blocker = Net.Control;
            pub const Automaton = harness_automaton;
            pub const Relay = *Application;
            pub const Reporter = *reporter_mod.Reporter(harness_scheme, harness_digest);
            pub const Sender = Net.Sender;
        };
        const harness_scheme = Scheme;
        const harness_digest = Digest;
        const harness_automaton = Automaton;
        const harness_context = Application.Context;
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
            /// The round-robin elector, with commonware's `with_term` settings when a test sets
            /// them.
            elector: elector_mod.RoundRobin(Sha256) = elector_mod.RoundRobin(Sha256).default(),
            /// Routes the voter's journal through this gate (commonware `DelayedSyncContext`).
            sync_gates: ?*runtime.storage.mocks.SyncGates = null,
            /// Certification requests held for the test.
            hold_certifications: Hold = .none,
            /// Holds built handoff candidates for the test (commonware `handoff_responses`).
            hold_handoffs: bool = false,
            /// The voter's metrics scope (commonware's context label, such as `restarted`).
            scope: []const u8 = "voter",
            /// The voter's tracer (commonware `test_collect_traces`).
            tracer: runtime.telemetry.traces.Tracer = .none,
        };

        /// commonware `start_voter_with_floor`'s voter: 5 s leader, 6 s certification, and 60 min
        /// retry timeouts, over `partition` from `floor` (null for genesis).
        pub fn floor_start(partition: []const u8, floor: ?Finalization, skip_budget: u64) Options {
            return .{
                .leader_timeout_ms = 5_000,
                .certification_timeout_ms = 6_000,
                .timeout_retry_ms = 60 * 60 * 1_000,
                .partition = partition,
                .floor = floor,
                .skip_budget = skip_budget,
                .batcher_capacity = 8,
            };
        }

        /// commonware `RoundRobin::default().with_term(length, stall_timeout, optimistic_views)`.
        pub fn term_elector(
            length: u32,
            stall_timeout_ms: u64,
            optimistic_views: u64,
        ) elector_mod.RoundRobin(Sha256) {
            const term_length: consensus_types.TermLength = .new(utils.NonZero(u32).init(length).?);
            const stall: Duration = .from_millis(stall_timeout_ms);
            const builder = elector_mod.RoundRobin(Sha256).default();
            return builder.with_term(term_length, stall, .new(optimistic_views));
        }

        /// The index of the leader `elector` picks for `view` of the default epoch among 5.
        pub fn leader_of(gpa: Allocator, elector: elector_mod.RoundRobin(Sha256), view: u64) !u32 {
            return leader_among(gpa, elector, 5, view);
        }

        /// `leader_of` among `n` validators.
        pub fn leader_among(
            gpa: Allocator,
            elector: elector_mod.RoundRobin(Sha256),
            n: u32,
            view: u64,
        ) !u32 {
            var built = try elector.build(gpa, n);
            defer built.deinit(gpa);
            return built.elect(.new(default_epoch, .new(view)), {}).get();
        }

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
                self.fixture = try F.make(gpa, &rng, namespace, n);
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

        /// A peer watching what the voter at index 0 broadcasts on `channel` (0 votes,
        /// 1 certificates) over a lossless zero-latency link. Must not move.
        pub const Observer = struct {
            sender: Net.Sender,
            receiver: Net.Receiver,

            /// Registers before the voter starts, as commonware's tests do.
            pub fn start(self: *Observer, net: *const Network, index: usize, channel: u64) !void {
                assert(index != 0);
                const observer = net.keys()[index];
                const registered = try net.oracle().control(observer).register(channel, test_quota);
                self.sender, self.receiver = .{ registered.sender, registered.receiver };
                errdefer self.deinit();
                try net.oracle().add_link(net.keys()[0], observer, .{
                    .latency = .from_millis(0),
                    .jitter = .from_millis(0),
                    .success_rate = 1.0,
                });
            }

            pub fn deinit(self: *Observer) void {
                self.sender.deinit();
                self.receiver.deinit();
                self.* = undefined;
            }

            /// The next certificate broadcast (the caller frees it).
            pub fn next_certificate(
                self: *Observer,
                gpa: Allocator,
                net: *const Network,
            ) !Certificate {
                var message = try self.receiver.recv();
                defer message.deinit();
                const cfg = net.schemes()[0].certificate_codec_config();
                return codec.decode_cfg(Certificate, gpa, message.payload, cfg);
            }

            /// Whether anything arrives within `limit_ms` of simulated time (it is dropped).
            pub fn any_within(self: *Observer, ctx: Ctx, limit_ms: u64) !bool {
                var waited: u64 = 0;
                while (waited < limit_ms) : (waited += 1) {
                    if (self.receiver.try_recv()) |message| {
                        var owned = message;
                        owned.deinit();
                        return true;
                    } else |_| {}
                    try ctx.sleep(.fromMilliseconds(1));
                }
                return false;
            }
        };

        /// A relay listener under validator `index`'s key recording each payload it is sent
        /// (commonware `relay.register(observer)`). Must not move while registered.
        pub const RelayObserver = struct {
            const payloads_max = 64;

            net: *Network,
            key: Key,
            mutex: Io.Mutex = .init,
            payloads: [payloads_max]Digest = undefined,
            count: u32 = 0,
            read: u32 = 0,

            pub fn start(self: *RelayObserver, net: *Network, index: usize) !void {
                self.* = .{ .net = net, .key = net.keys()[index] };
                try net.relay.register(.{ .key = self.key, .context = self, .deliver = deliver });
            }

            pub fn deinit(self: *RelayObserver) void {
                self.net.relay.deregister(self.key);
                self.* = undefined;
            }

            fn deliver(context: *anyopaque, payload: Digest, contents: []const u8) void {
                _ = contents;
                const self: *RelayObserver = @ptrCast(@alignCast(context));
                self.mutex.lockUncancelable(self.net.io);
                defer self.mutex.unlock(self.net.io);
                assert(self.count < payloads_max);
                self.payloads[self.count] = payload;
                self.count += 1;
            }

            /// The next relayed payload not yet read, if any.
            pub fn try_next(self: *RelayObserver) ?Digest {
                self.mutex.lockUncancelable(self.net.io);
                defer self.mutex.unlock(self.net.io);
                if (self.read == self.count) return null;
                self.read += 1;
                return self.payloads[self.read - 1];
            }

            /// The next relayed payload within `limit_ms` of simulated time.
            pub fn next(self: *RelayObserver, ctx: Ctx, limit_ms: u64) !?Digest {
                var waited: u64 = 0;
                while (waited <= limit_ms) : (waited += 1) {
                    if (self.try_next()) |payload| return payload;
                    try ctx.sleep(.fromMilliseconds(1));
                }
                return null;
            }
        };

        /// One running voter with the mailboxes the test holds (commonware `setup_voter`'s
        /// returned tuple). Must not move.
        pub const VoterStack = struct {
            gpa: Allocator,
            io: Io,
            application: Application,
            automaton: Automaton,
            /// The journal storage when `Options.sync_gates` is set.
            gated: runtime.storage.mocks.SyncGated,
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
                try self.start_application(net, net.keys()[options.local_index], options);
                errdefer self.application.deinit();
                // Kept across restarts, as commonware's observers are.
                self.automaton = .{
                    .application = &self.application,
                    .io = io,
                    .hold = options.hold_certifications,
                    .hold_handoffs = options.hold_handoffs,
                };
                self.reporter = .init(gpa, io, &net.fixture.verifier);
                errdefer self.reporter.deinit();
                self.page_cache = try .init(gpa, page_size, page_cache_size);
                errdefer self.page_cache.deinit();
                try self.start_voter(ctx, net, options);
            }

            /// Starts the voter half over the kept application, reporter, and page cache.
            fn start_voter(self: *VoterStack, ctx: Ctx, net: *Network, options: Options) !void {
                const gpa = self.gpa;
                const io = self.io;
                assert(self.task == null);
                const index = options.local_index;
                const me = net.keys()[index];
                const scheme = &net.schemes()[index];
                const n: u32 = @intCast(net.keys().len);
                self.elector = try F.build_elector(gpa, n, options.elector);
                errdefer F.deinit_elector(&self.elector, gpa);
                self.partition = @splat(0);
                const partition = options.partition orelse
                    try std.fmt.bufPrint(&self.partition, "voter_test_{d}", .{index});
                const journal_storage = if (options.sync_gates) |gates| gated: {
                    self.gated = .init(gpa, ctx.storage, gates);
                    break :gated self.gated.storage();
                } else ctx.storage;
                const floor: Floor = if (options.floor) |finalization|
                    .{ .finalized = finalization }
                else
                    .{ .genesis = application_mod.genesis(Sha256, options.epoch) };
                self.voter, self.mailbox = try Voter.init(gpa, io, .{
                    .scheme = scheme,
                    .elector = self.elector,
                    .blocker = net.oracle().control(me),
                    .automaton = &self.automaton,
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
                    .storage = journal_storage,
                    .scope = ctx.scope.child(options.scope),
                });
                self.voter.tracer = options.tracer;
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

            fn start_application(
                self: *VoterStack,
                net: *Network,
                me: Key,
                options: Options,
            ) !void {
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
                return self.voter.run(
                    batcher,
                    resolver,
                    &self.vote_sender,
                    &self.certificate_sender,
                );
            }

            /// Stops the voter and everything `start` built.
            pub fn stop(self: *VoterStack) void {
                self.stop_voter();
                self.page_cache.deinit();
                self.reporter.deinit();
                self.application.deinit();
                self.* = undefined;
            }

            /// Aborts the voter (commonware `handle.abort()`); its journal stays in storage.
            fn stop_voter(self: *VoterStack) void {
                if (self.task) |*task| {
                    task.cancel(self.io) catch {};
                    self.task = null;
                }
                self.mailbox.deinit();
                self.voter.deinit();
                F.deinit_elector(&self.elector, self.gpa);
                self.vote_sender.deinit();
                self.vote_receiver.deinit();
                self.certificate_sender.deinit();
                self.certificate_receiver.deinit();
                self.batcher.deinit();
                self.resolver.deinit();
            }

            /// Aborts the voter and starts a new one over the same journal, application, and
            /// reporter (commonware's `handle.abort()` then a second `Actor::new`), with fresh
            /// batcher and resolver mailboxes.
            pub fn restart(self: *VoterStack, ctx: Ctx, net: *Network, options: Options) !void {
                self.stop_voter();
                try self.start_voter(ctx, net, options);
            }

            /// Aborts the voter and starts a replacement over the same journal with a fresh
            /// recording automaton and `options`' application behavior (commonware's restart
            /// helpers, which build a new mock application with new observers).
            pub fn replace(self: *VoterStack, ctx: Ctx, net: *Network, options: Options) !void {
                self.stop_voter();
                self.automaton = .{
                    .application = &self.application,
                    .io = self.io,
                    .hold = options.hold_certifications,
                    .hold_handoffs = options.hold_handoffs,
                };
                self.application.should_certify = options.certifier;
                self.application.stall_proposals = options.stall_proposals;
                self.application.drop_proposals = options.drop_proposals;
                self.application.fail_verification = options.fail_verification;
                self.application.handoff = options.handoff;
                try self.start_voter(ctx, net, options);
            }

            /// Waits up to 1 s of simulated time for a proposal request for `view`
            /// (commonware `wait_for_request` over `propose_requests`).
            pub fn wait_proposal_request(self: *VoterStack, ctx: Ctx, view: u64) !void {
                var waited: u64 = 0;
                while (!self.automaton.proposal_requested(view)) : (waited += 1) {
                    if (waited >= 1_000) return error.NoProposalRequest;
                    try ctx.sleep(.fromMilliseconds(1));
                }
            }

            /// Waits up to 1 s of simulated time for a verification request for `view`.
            pub fn wait_verification_request(self: *VoterStack, ctx: Ctx, view: u64) !void {
                var waited: u64 = 0;
                while (!self.automaton.verification_requested(view)) : (waited += 1) {
                    if (waited >= 1_000) return error.NoVerificationRequest;
                    try ctx.sleep(.fromMilliseconds(1));
                }
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

            /// Expects the next resolver message to be an `updated` certificate of `kind` at
            /// `view`.
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

            /// Whether our nullify vote for `view` reaches the batcher within `limit_ms` of
            /// simulated time (other messages are skipped).
            pub fn nullify_within(self: *VoterStack, ctx: Ctx, view: u64, limit_ms: u64) !bool {
                var waited: u64 = 0;
                // Bounded by `limit_ms` of simulated time.
                while (waited < limit_ms) {
                    const message = self.batcher.try_recv() catch |err| switch (err) {
                        error.Empty => {
                            try ctx.sleep(.fromMilliseconds(1));
                            waited += 1;
                            continue;
                        },
                        else => return error.MailboxClosed,
                    };
                    if (message != .constructed or message.constructed != .nullify) continue;
                    if (message.constructed.nullify.view().get() == view) return true;
                }
                return false;
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
            var page_cache: runtime.buffer.paged.CacheRef = try .init(
                gpa,
                page_size,
                page_cache_size,
            );
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

        /// Finalizes `target - 1` (payload `hash(be64(target - 1))`) and waits for the update
        /// announcing `target` (commonware `advance_to_view`). Returns the finalized payload.
        pub fn advance_to_view(
            stack: *VoterStack,
            ctx: Ctx,
            net: *const Network,
            target: u64,
        ) !Digest {
            assert(target > 1);
            const previous = target - 1;
            var be: [8]u8 = undefined;
            std.mem.writeInt(u64, &be, previous, .big);
            const payload = Sha256.hash(&.{&be});
            const round: Round = .new(default_epoch, .new(previous));
            const proposal: Proposal = .init(round, .new(previous - 1), payload);
            const gpa = ctx.gpa();
            const finalization = try build(
                gpa,
                .finalization,
                net.schemes(),
                proposal,
                net.quorum(),
            );
            try stack.mailbox.recovered(gpa, .{ .finalization = finalization });
            // Bounded: views only advance, and each wait is limited.
            while (true) {
                const update = try stack.next_update(ctx, 5_000);
                if (update.current.get() < target) continue;
                try std.testing.expectEqual(target, update.current.get());
                return payload;
            }
        }

        /// Relays `payload`'s contents from validator `sender` the way the mock application builds
        /// them: `round`, the parent's payload, and a zero nonce (commonware
        /// `relay.broadcast(&leader, Recipients::All, (payload, contents))`).
        pub fn relay_contents(
            net: *Network,
            sender: usize,
            payload: Digest,
            round: Round,
            parent: Digest,
            nonce: u64,
        ) void {
            var buffer: [128]u8 = undefined;
            const contents = mock_contents(&buffer, round, parent, nonce);
            net.relay.broadcast(net.keys()[sender], .all, payload, contents);
        }

        /// The mock application's payload contents: `round`, the parent's payload, and
        /// `nonce`, written into `buffer` (commonware `(round, parent, nonce).encode()`).
        pub fn mock_contents(
            buffer: *[128]u8,
            round: Round,
            parent: Digest,
            nonce: u64,
        ) []const u8 {
            var writer: codec.Writer = .init(buffer);
            round.write(&writer);
            codec.write(Digest, parent, &writer);
            codec.write(u64, nonce, &writer);
            return writer.written();
        }

        /// The mock application's genesis payload in `epoch`.
        pub fn genesis(epoch: Epoch) Digest {
            return application_mod.genesis(Sha256, epoch);
        }

        /// One expected labeled counter value.
        pub const Sample = struct { []const u8, u64 };

        /// Expects the nonzero series of counter `family` (`<scope>_<family>_total{label="v"}`)
        /// to be exactly `expected` (commonware `labeled_metric_snapshot`).
        pub fn expect_counters(
            ctx: Ctx,
            family: []const u8,
            label: []const u8,
            expected: []const Sample,
        ) !void {
            return expect_counters_in(ctx, "", family, label, expected);
        }

        /// `expect_counters` over the series of metrics scope `prefix` only (all when empty).
        pub fn expect_counters_in(
            ctx: Ctx,
            prefix: []const u8,
            family: []const u8,
            label: []const u8,
            expected: []const Sample,
        ) !void {
            const gpa = ctx.gpa();
            const encoded = try ctx.scope.encode(gpa);
            defer gpa.free(encoded);
            var pattern_buffer: [96]u8 = undefined;
            const pattern = try std.fmt.bufPrint(&pattern_buffer, "_{s}_total{{{s}=\"", .{
                family,
                label,
            });
            var matched: usize = 0;
            var lines = std.mem.splitScalar(u8, encoded, '\n');
            // Bounded by the encoded text.
            while (lines.next()) |line| {
                if (!std.mem.startsWith(u8, line, prefix)) continue;
                const at = std.mem.indexOf(u8, line, pattern) orelse continue;
                const rest = line[at + pattern.len ..];
                const quote = std.mem.indexOfScalar(u8, rest, '"') orelse continue;
                const space = std.mem.lastIndexOfScalar(u8, line, ' ') orelse continue;
                const count = try std.fmt.parseInt(u64, line[space + 1 ..], 10);
                if (count == 0) continue;
                const value = rest[0..quote];
                for (expected) |sample| {
                    if (!std.mem.eql(u8, sample[0], value)) continue;
                    try std.testing.expectEqual(sample[1], count);
                    matched += 1;
                    break;
                } else {
                    std.debug.print(
                        "unexpected {s} {s}={s}: {d}\n",
                        .{ family, label, value, count },
                    );
                    return error.UnexpectedCounter;
                }
            }
            try std.testing.expectEqual(expected.len, matched);
        }

        /// The value of counter `family`'s series `label="value"`, or 0 when absent.
        pub fn counter_value(
            ctx: Ctx,
            family: []const u8,
            label: []const u8,
            value: []const u8,
        ) !u64 {
            const gpa = ctx.gpa();
            const encoded = try ctx.scope.encode(gpa);
            defer gpa.free(encoded);
            var pattern_buffer: [128]u8 = undefined;
            const pattern = try std.fmt.bufPrint(
                &pattern_buffer,
                "_{s}_total{{{s}=\"{s}\"}}",
                .{ family, label, value },
            );
            var lines = std.mem.splitScalar(u8, encoded, '\n');
            // Bounded by the encoded text.
            while (lines.next()) |line| {
                if (std.mem.indexOf(u8, line, pattern) == null) continue;
                const space = std.mem.lastIndexOfScalar(u8, line, ' ') orelse continue;
                return std.fmt.parseInt(u64, line[space + 1 ..], 10);
            }
            return 0;
        }

        /// Waits up to 5 s of simulated time for counter `family`'s series `label="value"` to
        /// count (commonware `wait_for_handoff_event`, `wait_for_handoff_abandoned`).
        pub fn wait_counter(
            ctx: Ctx,
            family: []const u8,
            label: []const u8,
            value: []const u8,
        ) !void {
            var waited: u64 = 0;
            // Bounded by 5 s of simulated time.
            while (try counter_value(ctx, family, label, value) == 0) : (waited += 1) {
                if (waited > 5_000) return error.CounterNotCounted;
                try ctx.sleep(.fromMilliseconds(1));
            }
        }

        /// commonware `assert_handoff_metrics`.
        pub fn expect_handoff_metrics(
            ctx: Ctx,
            events: []const Sample,
            abandoned: []const Sample,
        ) !void {
            try expect_handoff_metrics_in(ctx, "", events, abandoned);
        }

        /// `expect_handoff_metrics` over metrics scope `prefix` only.
        pub fn expect_handoff_metrics_in(
            ctx: Ctx,
            prefix: []const u8,
            events: []const Sample,
            abandoned: []const Sample,
        ) !void {
            try expect_counters_in(ctx, prefix, "handoff_events", "event", events);
            try expect_counters_in(ctx, prefix, "handoff_abandoned", "reason", abandoned);
        }

        /// The position among debug events of the first `content` event whose innermost span is
        /// `span_name` at `view` (commonware `trace_position`).
        pub fn trace_position(
            collector: *runtime.telemetry.traces.Collector,
            content: []const u8,
            span_name: []const u8,
            view: u64,
        ) !usize {
            var buffer: [20]u8 = undefined;
            const wanted = try std.fmt.bufPrint(&buffer, "{d}", .{view});
            const events = collector.get_by_level(.debug);
            var index: usize = 0;
            // Bounded by the recorded events.
            while (events.get(index)) |event| : (index += 1) {
                if (!std.mem.eql(u8, event.metadata.content, content)) continue;
                if (event.spans.len == 0) continue;
                const span = event.spans[0];
                if (!std.mem.eql(u8, span.content, span_name)) continue;
                for (span.fields) |field| {
                    if (!std.mem.eql(u8, field.name, "view")) continue;
                    if (std.mem.eql(u8, field.value, wanted)) return index;
                }
            }
            return error.MissingTrace;
        }

        /// A proposal at `view` of `epoch` over `view - 1`, with payload `hash(label)`.
        pub fn proposal_at(epoch: Epoch, view: u64, label: []const u8) Proposal {
            assert(view > 0);
            return .init(.new(epoch, .new(view)), .new(view - 1), Sha256.hash(&.{label}));
        }

        /// `build` signed by `count` of `schemes` other than `skip` (commonware
        /// `build_*(&peers(schemes, local_index), ..)`).
        pub fn build_peers(
            gpa: Allocator,
            comptime kind: std.meta.Tag(Certificate),
            schemes: []const Scheme,
            skip: usize,
            subject: if (kind == .nullification) Round else Proposal,
            count: u32,
        ) !@FieldType(Certificate, @tagName(kind)) {
            var peers: [16]Scheme = undefined;
            var len: usize = 0;
            for (schemes, 0..) |scheme, index| {
                if (index == skip) continue;
                peers[len] = scheme;
                len += 1;
            }
            return build(gpa, kind, peers[0..len], subject, count);
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
                    const next = try stack.next_batcher(ctx, 1_000);
                    const message = next orelse return error.NoUpdate;
                    try std.testing.expect(message == .update);
                    try std.testing.expectEqual(@as(u64, 1), message.update.current.get());
                }
            }.body, .{});
        }
    };
}
