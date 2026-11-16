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
        certifications: ViewSet = .empty,
        nullifications: ViewSet = .empty,
        finalizations: std.AutoHashMapUnmanaged(View, Finalized) = .empty,
        faults: std.ArrayList(Fault) = .empty,
        invalid_votes: u64 = 0,
        invalid_certificates: u64 = 0,
        latest: View = .zero(),

        /// `scheme` verifies activities (a verifier is enough).
        pub fn init(gpa: Allocator, io: Io, scheme: *const S) Self {
            return .{ .gpa = gpa, .io = io, .scheme = scheme };
        }

        pub fn deinit(self: *Self) void {
            self.notarizes.deinit(self.gpa);
            self.nullifies.deinit(self.gpa);
            self.finalizes.deinit(self.gpa);
            self.notarizations.deinit(self.gpa);
            self.certifications.deinit(self.gpa);
            self.nullifications.deinit(self.gpa);
            self.finalizations.deinit(self.gpa);
            self.faults.deinit(self.gpa);
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
                .notarization, .certification => |*notarization| {
                    if (!self.record_certificate(notarization)) return .ok;
                    put(self.gpa, &self.notarizations, notarization.view());
                    if (activity == .certification) {
                        put(self.gpa, &self.certifications, notarization.view());
                    }
                },
                .nullification => |*nullification| {
                    if (!self.record_certificate(nullification)) return .ok;
                    put(self.gpa, &self.nullifications, nullification.view());
                },
                .finalization => |*finalization| {
                    if (!self.record_certificate(finalization)) return .ok;
                    self.record_finalization(finalization);
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

        fn record_finalization(self: *Self, finalization: *const types.Finalization(S, D)) void {
            const view = finalization.view();
            const entry = self.finalizations.getOrPut(self.gpa, view) catch @panic("out of memory");
            if (entry.found_existing) {
                // Every finalization of a view names the same payload, or safety failed.
                const payload = finalization.proposal.payload;
                assert(codec.order(D, entry.value_ptr.payload, payload) == .eq);
                entry.value_ptr.count += 1;
            } else {
                entry.value_ptr.* = .{ .payload = finalization.proposal.payload, .count = 1 };
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

        /// Whether a notarization (or certification) of `view` was reported.
        pub fn notarized(self: *Self, view: View) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.notarizations.contains(view);
        }

        /// Whether a nullification of `view` was reported.
        pub fn nullified(self: *Self, view: View) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.nullifications.contains(view);
        }

        pub fn assert_no_faults(self: *Self) void {
            assert(self.faults.items.len == 0); // Faults detected.
        }

        /// The faults reported so far (borrowed; read once the engines stopped).
        pub fn fault_list(self: *Self) []const Fault {
            return self.faults.items;
        }

        pub fn assert_no_invalid(self: *Self) void {
            assert(self.invalid_votes == 0); // Invalid votes detected.
            assert(self.invalid_certificates == 0); // Invalid certificates detected.
        }
    };
}
