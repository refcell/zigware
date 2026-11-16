//! A mock reporter for simplex tests (commonware `simplex/mocks/reporter.rs`): verifies every
//! activity, records participation, certificates, and faults, and lets a test wait for a
//! finalized view (commonware's ring subscription).
//!
//! Activities arrive borrowed; the reporter keeps only views, payloads, and counts, so it never
//! owns certificates. `wait_for_finalized` replaces `Monitor::subscribe`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const parallel = @import("parallel");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");
const context = @import("../actors/context.zig");

const View = consensus_types.View;
const Participant = consensus_types.Participant;
const Rnd = consensus_types.Round;

pub fn Reporter(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Activity = types.Activity(S, D);
        pub const Notarization = types.Notarization(S, D);
        pub const Finalization = types.Finalization(S, D);
        const ViewSet = std.AutoHashMapUnmanaged(View, void);
        /// The signers of a view's votes, one bit per participant index (commonware keeps a
        /// set of public keys per view; test committees stay below 64 validators).
        pub const Signers = u64;
        const ViewSigners = std.AutoHashMapUnmanaged(View, Signers);
        /// A finalized payload and how many times its finalization was reported.
        pub const Finalized = struct { payload: D, count: u32 };
        /// A verified fault: who committed it and which kind.
        pub const Fault = struct { signer: Participant, kind: std.meta.Tag(Activity) };

        gpa: Allocator,
        io: Io,
        scheme: *const S,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        notarizes: ViewSigners = .empty,
        nullifies: ViewSigners = .empty,
        finalizes: ViewSigners = .empty,
        notarizations: ViewSet = .empty,
        /// The first notarization reported for each view (commonware keeps them all).
        notarization_certificates: std.AutoHashMapUnmanaged(View, Notarization) = .empty,
        certifications: ViewSet = .empty,
        nullifications: ViewSet = .empty,
        finalizations: std.AutoHashMapUnmanaged(View, Finalized) = .empty,
        /// The first finalization reported for each view.
        finalization_certificates: std.AutoHashMapUnmanaged(View, Finalization) = .empty,
        faults: std.ArrayList(Fault) = .empty,
        invalid_votes: u64 = 0,
        invalid_certificates: u64 = 0,
        latest: View = .zero(),
        /// The payload each signer's notarize and finalize votes named, per view.
        vote_payloads: std.AutoHashMapUnmanaged(VoteKey, D) = .empty,
        /// Signers seen voting for two payloads in one view (commonware's twins campaign
        /// checks this per payload).
        equivocators: Signers = 0,

        const VoteKey = struct { view: View, signer: u32, finalize: bool };

        /// `scheme` verifies activities (a verifier is enough).
        pub fn init(gpa: Allocator, io: Io, scheme: *const S) Self {
            return .{ .gpa = gpa, .io = io, .scheme = scheme };
        }

        pub fn deinit(self: *Self) void {
            self.notarizes.deinit(self.gpa);
            self.nullifies.deinit(self.gpa);
            self.finalizes.deinit(self.gpa);
            self.notarizations.deinit(self.gpa);
            var certificates = self.notarization_certificates.valueIterator();
            while (certificates.next()) |certificate| certificate.deinit(self.gpa);
            self.notarization_certificates.deinit(self.gpa);
            self.certifications.deinit(self.gpa);
            self.nullifications.deinit(self.gpa);
            self.finalizations.deinit(self.gpa);
            var finalizations = self.finalization_certificates.valueIterator();
            while (finalizations.next()) |certificate| certificate.deinit(self.gpa);
            self.finalization_certificates.deinit(self.gpa);
            self.faults.deinit(self.gpa);
            self.vote_payloads.deinit(self.gpa);
            self.* = undefined;
        }

        fn verified(self: *Self, value: anytype) bool {
            var rng: context.IoRng = .{ .io = self.io };
            return value.verify(self.gpa, &rng, self.scheme, parallel.sequential) catch
                @panic("out of memory");
        }

        /// Checks that `value` round-trips through its codec.
        fn round_trips(self: *Self, comptime T: type, value: T, cfg: codec.Cfg(T)) void {
            const bytes = codec.encode(T, self.gpa, value) catch @panic("out of memory");
            defer self.gpa.free(bytes);
            var decoded = codec.decode_cfg(T, self.gpa, bytes, cfg) catch @panic("bad encoding");
            codec.free(T, self.gpa, decoded);
            decoded = undefined;
        }

        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            switch (activity) {
                .notarize => |vote| self.record_vote(vote, &self.notarizes),
                .nullify => |vote| self.record_vote(vote, &self.nullifies),
                .finalize => |vote| self.record_vote(vote, &self.finalizes),
                .notarization, .certification => |*certificate| {
                    if (!self.record_certificate(certificate)) return .ok;
                    put(self.gpa, &self.notarizations, certificate.view());
                    self.keep_notarization(certificate);
                    if (activity == .certification) {
                        put(self.gpa, &self.certifications, certificate.view());
                    }
                },
                .nullification => |*nullification| {
                    if (!self.record_certificate(nullification)) return .ok;
                    put(self.gpa, &self.nullifications, nullification.view());
                },
                .finalization => |*certificate| {
                    if (!self.record_certificate(certificate)) return .ok;
                    self.record_finalization(certificate);
                },
                inline .conflicting_notarize, .conflicting_finalize, .nullify_finalize => |*fault| {
                    if (!self.verified(fault)) {
                        self.invalid_votes += 1;
                        return .ok;
                    }
                    const kind = std.meta.activeTag(activity);
                    const record: Fault = .{ .signer = fault.signer(), .kind = kind };
                    self.faults.append(self.gpa, record) catch @panic("out of memory");
                },
            }
            return .ok;
        }

        fn keep_notarization(self: *Self, certificate: *const Notarization) void {
            const map = &self.notarization_certificates;
            const entry = map.getOrPut(self.gpa, certificate.view()) catch
                @panic("out of memory");
            if (entry.found_existing) return;
            entry.value_ptr.* = certificate.clone(self.gpa) catch {
                map.removeByPtr(entry.key_ptr);
                @panic("out of memory");
            };
            assert(map.contains(certificate.view()));
        }

        /// A copy of the first notarization reported for `view`, if any (the caller frees
        /// it).
        pub fn notarization(self: *Self, view: View) Allocator.Error!?Notarization {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const kept = self.notarization_certificates.getPtr(view) orelse return null;
            return try kept.clone(self.gpa);
        }

        /// A copy of the first finalization reported for `view`, if any (the caller frees
        /// it).
        pub fn finalization(self: *Self, view: View) Allocator.Error!?Finalization {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const kept = self.finalization_certificates.getPtr(view) orelse return null;
            return try kept.clone(self.gpa);
        }

        fn put(gpa: Allocator, set: *ViewSet, view: View) void {
            set.put(gpa, view, {}) catch @panic("out of memory");
        }

        fn record_vote(self: *Self, vote: anytype, signers: *ViewSigners) void {
            if (!self.verified(&vote)) {
                self.invalid_votes += 1;
                return;
            }
            self.round_trips(@TypeOf(vote), vote, {});
            const signer = vote.attestation.signer.get();
            assert(signer < @bitSizeOf(Signers));
            const entry = signers.getOrPut(self.gpa, vote.view()) catch @panic("out of memory");
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* |= @as(Signers, 1) << @intCast(signer);
            if (@hasField(@TypeOf(vote), "proposal")) {
                const finalize = signers == &self.finalizes;
                self.record_payload(vote.view(), signer, finalize, vote.proposal.payload);
            }
        }

        /// Records the payload `signer` voted for at `view`, flagging a second payload.
        fn record_payload(self: *Self, view: View, signer: u32, finalize: bool, payload: D) void {
            const key: VoteKey = .{ .view = view, .signer = signer, .finalize = finalize };
            const entry = self.vote_payloads.getOrPut(self.gpa, key) catch
                @panic("out of memory");
            if (!entry.found_existing) {
                entry.value_ptr.* = payload;
            } else if (codec.order(D, entry.value_ptr.*, payload) != .eq) {
                self.equivocators |= @as(Signers, 1) << @intCast(signer);
            }
            assert(self.vote_payloads.contains(key));
        }

        /// The signers seen voting for two payloads in one view.
        pub fn equivocating_signers(self: *Self) Signers {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.equivocators;
        }

        fn record_certificate(self: *Self, certificate: anytype) bool {
            if (!self.verified(certificate)) {
                self.invalid_certificates += 1;
                return false;
            }
            const T = @TypeOf(certificate.*);
            self.round_trips(T, certificate.*, self.scheme.certificate_codec_config());
            return true;
        }

        fn record_finalization(self: *Self, certificate: *const Finalization) void {
            const view = certificate.view();
            const entry = self.finalizations.getOrPut(self.gpa, view) catch @panic("out of memory");
            if (entry.found_existing) {
                // Every finalization of a view names the same payload, or safety failed.
                const payload = certificate.proposal.payload;
                assert(codec.order(D, entry.value_ptr.payload, payload) == .eq);
                entry.value_ptr.count += 1;
            } else {
                entry.value_ptr.* = .{ .payload = certificate.proposal.payload, .count = 1 };
                const copy = certificate.clone(self.gpa) catch @panic("out of memory");
                self.finalization_certificates.put(self.gpa, view, copy) catch
                    @panic("out of memory");
            }
            if (view.get() > self.latest.get()) self.latest = view;
            self.condition.broadcast(self.io);
        }

        /// Waits until a finalization at or above `view` was reported.
        pub fn wait_for_finalized(self: *Self, view: View) Io.Cancelable!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Each wake re-checks the latest finalized view.
            while (self.latest.get() < view.get()) try self.condition.wait(self.io, &self.mutex);
            assert(self.latest.get() >= view.get());
        }

        /// Waits until finalizations of `count` distinct views above `view` were reported
        /// (commonware counts monitor events past the twins prefix).
        pub fn wait_for_finalizations_above(
            self: *Self,
            view: View,
            count: u32,
        ) Io.Cancelable!void {
            assert(count > 0);
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Each wake recounts; finalizations only grow.
            while (self.finalizations_above(view) < count) {
                try self.condition.wait(self.io, &self.mutex);
            }
        }

        fn finalizations_above(self: *const Self, view: View) u32 {
            var count: u32 = 0;
            var views = self.finalizations.keyIterator();
            while (views.next()) |finalized_view| {
                if (finalized_view.get() > view.get()) count += 1;
            }
            return count;
        }

        /// The highest finalized view reported so far.
        pub fn latest_finalized(self: *Self) View {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.latest;
        }

        /// The payload finalized at `view`, if any.
        pub fn finalized(self: *Self, view: View) ?D {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const entry = self.finalizations.get(view) orelse return null;
            return entry.payload;
        }

        /// Which votes of a view were reported, by signer.
        pub const Votes = struct { notarize: Signers, nullify: Signers, finalize: Signers };

        /// The signers of each kind of vote reported at `view`.
        pub fn votes(self: *Self, view: View) Votes {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return .{
                .notarize = self.notarizes.get(view) orelse 0,
                .nullify = self.nullifies.get(view) orelse 0,
                .finalize = self.finalizes.get(view) orelse 0,
            };
        }

        /// The highest view with a reported vote of `kind` (zero when there is none).
        pub fn max_vote_view(self: *Self, comptime kind: std.meta.FieldEnum(Votes)) View {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const signers = switch (kind) {
                .notarize => &self.notarizes,
                .nullify => &self.nullifies,
                .finalize => &self.finalizes,
            };
            var highest: View = .zero();
            var views = signers.keyIterator();
            while (views.next()) |view| {
                if (view.get() > highest.get()) highest = view.*;
            }
            return highest;
        }

        /// Whether a notarization (or certification) of `view` was reported.
        pub fn notarized(self: *Self, view: View) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.notarizations.contains(view);
        }

        /// Whether a certification of `view` was reported.
        pub fn certified(self: *Self, view: View) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.certifications.contains(view);
        }

        /// The lowest finalized view above `floor`, if any.
        pub fn first_finalized_above(self: *Self, floor: View) ?View {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            var lowest: ?View = null;
            var views = self.finalizations.keyIterator();
            while (views.next()) |view| {
                if (view.get() <= floor.get()) continue;
                if (lowest == null or view.get() < lowest.?.get()) lowest = view.*;
            }
            assert(lowest == null or lowest.?.get() > floor.get());
            return lowest;
        }

        /// Whether a nullification of `view` was reported.
        pub fn nullified(self: *Self, view: View) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.nullifications.contains(view);
        }

        /// The highest view with a reported nullification (zero when none).
        pub fn latest_nullified(self: *Self) View {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            var highest: View = .zero();
            var views = self.nullifications.keyIterator();
            while (views.next()) |view| {
                if (view.get() > highest.get()) highest = view.*;
            }
            assert(highest.get() == 0 or self.nullifications.contains(highest));
            return highest;
        }

        const PayloadKey = struct { view: View, finalize: bool };
        const Payloads = std.AutoHashMapUnmanaged(PayloadKey, D);

        /// commonware's hailstorm fork checks over views in [1, `end`): every notarize vote
        /// of a view names one payload, as does every finalize vote; the view's notarization
        /// and finalization name those payloads; and no signer both nullified and finalized
        /// it. A signer seen voting for two payloads in any view is a fork too.
        pub fn check_no_forks(self: *Self, end: View) error{ Fork, OutOfMemory }!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.equivocators != 0) return error.Fork;
            var payloads: Payloads = .empty;
            defer payloads.deinit(self.gpa);
            var entries = self.vote_payloads.iterator();
            while (entries.next()) |entry| {
                const key = entry.key_ptr.*;
                if (key.view.get() < 1 or key.view.get() >= end.get()) continue;
                const payload_key: PayloadKey = .{ .view = key.view, .finalize = key.finalize };
                const slot = try payloads.getOrPut(self.gpa, payload_key);
                if (!slot.found_existing) {
                    slot.value_ptr.* = entry.value_ptr.*;
                } else if (codec.order(D, slot.value_ptr.*, entry.value_ptr.*) != .eq) {
                    return error.Fork;
                }
            }
            var view: u64 = 1;
            while (view < end.get()) : (view += 1) try self.check_view(&payloads, .new(view));
        }

        fn check_view(self: *Self, payloads: *const Payloads, view: View) error{Fork}!void {
            assert(view.get() > 0);
            if (payloads.get(.{ .view = view, .finalize = false })) |payload| {
                if (self.notarization_certificates.getPtr(view)) |kept| {
                    const named = kept.proposal.payload;
                    if (codec.order(D, named, payload) != .eq) return error.Fork;
                }
            }
            if (payloads.get(.{ .view = view, .finalize = true })) |payload| {
                if (self.finalizations.get(view)) |finalized_view| {
                    if (codec.order(D, finalized_view.payload, payload) != .eq) return error.Fork;
                }
            }
            const finalizers = self.finalizes.get(view) orelse 0;
            const nullifiers = self.nullifies.get(view) orelse 0;
            if (finalizers & nullifiers != 0) return error.Fork;
        }

        pub fn assert_no_faults(self: *Self) void {
            assert(self.faults.items.len == 0); // Faults detected.
        }

        /// The faults reported so far (borrowed; read once the engines stopped).
        pub fn fault_list(self: *Self) []const Fault {
            return self.faults.items;
        }

        /// How many invalid votes and certificates were reported.
        pub const Invalid = struct { votes: u64, certificates: u64 };

        pub fn invalid(self: *Self) Invalid {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return .{ .votes = self.invalid_votes, .certificates = self.invalid_certificates };
        }

        pub fn assert_no_invalid(self: *Self) void {
            assert(self.invalid_votes == 0); // Invalid votes detected.
            assert(self.invalid_certificates == 0); // Invalid certificates detected.
        }
    };
}
