//! The reporter of each honest engine in a fuzz run: it keeps the verified certificates the
//! invariants need (commonware's mock reporter `notarizations`, `nullifications`, and
//! `finalizations`, read by `invariants::extract`) and wakes waiters on finalization.
//!
//! As in commonware's mock, a notarization or nullification replaces an earlier one of its
//! view, the first finalization of a view stays, and certificates that fail verification
//! are dropped. Signer counts come from the encoded certificate's leading `Signers` bitmap
//! for attributable schemes (commonware `get_signature_count`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const simplex = @import("../simplex/root.zig");
const IoRng = @import("../simplex/actors/context.zig").IoRng;
const fuzz_types = @import("types.zig");

const Digest = fuzz_types.Digest;
const Certified = fuzz_types.Certified;
const Nullification = fuzz_types.Nullification;
const Voted = fuzz_types.Voted;

pub fn Recorder(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Activity = simplex.types.Activity(S, Digest);

        gpa: Allocator,
        io: Io,
        /// Verifies reported certificates.
        scheme: *const S,
        participants: u32,
        /// This replica's participant index: its own votes are recorded too.
        me: u32,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        notarizations: std.AutoHashMapUnmanaged(u64, Certified) = .empty,
        nullifications: std.AutoHashMapUnmanaged(u64, Nullification) = .empty,
        finalizations: std.AutoHashMapUnmanaged(u64, Certified) = .empty,
        notarize_votes: std.AutoHashMapUnmanaged(u64, Voted) = .empty,
        nullify_votes: std.AutoHashMapUnmanaged(u64, Voted) = .empty,
        finalize_votes: std.AutoHashMapUnmanaged(u64, Voted) = .empty,
        latest: u64 = 0,

        pub fn init(gpa: Allocator, io: Io, scheme: *const S, participants: u32, me: u32) Self {
            assert(participants > 0);
            assert(me < participants);
            return .{
                .gpa = gpa,
                .io = io,
                .scheme = scheme,
                .participants = participants,
                .me = me,
            };
        }

        pub fn deinit(self: *Self) void {
            self.notarizations.deinit(self.gpa);
            self.nullifications.deinit(self.gpa);
            self.finalizations.deinit(self.gpa);
            self.notarize_votes.deinit(self.gpa);
            self.nullify_votes.deinit(self.gpa);
            self.finalize_votes.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            switch (activity) {
                .notarization, .certification => |*notarization| {
                    const record = self.certified(notarization) orelse return .ok;
                    self.notarizations.put(self.gpa, record.view, record) catch oom();
                },
                .nullification => |*nullification| {
                    if (!self.verified(nullification)) return .ok;
                    const record: Nullification = .{
                        .view = nullification.round.view.get(),
                        .signature_count = self.signature_count(&nullification.certificate),
                    };
                    self.nullifications.put(self.gpa, record.view, record) catch oom();
                },
                .finalization => |*finalization| {
                    const record = self.certified(finalization) orelse return .ok;
                    const entry = self.finalizations.getOrPut(self.gpa, record.view) catch oom();
                    if (!entry.found_existing) entry.value_ptr.* = record;
                    self.latest = @max(self.latest, record.view);
                    self.condition.broadcast(self.io);
                },
                .notarize => |*vote| if (vote.attestation.signer.get() == self.me) {
                    const proposal = vote.proposal;
                    const voted: Voted =
                        .{ .view = proposal.view().get(), .parent = proposal.parent.get() };
                    self.notarize_votes.put(self.gpa, voted.view, voted) catch oom();
                },
                .nullify => |*vote| if (vote.attestation.signer.get() == self.me) {
                    const voted: Voted = .{ .view = vote.round.view.get() };
                    self.nullify_votes.put(self.gpa, voted.view, voted) catch oom();
                },
                .finalize => |*vote| if (vote.attestation.signer.get() == self.me) {
                    const voted: Voted = .{ .view = vote.proposal.view().get() };
                    self.finalize_votes.put(self.gpa, voted.view, voted) catch oom();
                },
                else => {},
            }
            return .ok;
        }

        fn oom() noreturn {
            @panic("out of memory");
        }

        fn verified(self: *Self, certificate: anytype) bool {
            var rng: IoRng = .{ .io = self.io };
            return certificate.verify(self.gpa, &rng, self.scheme, parallel.sequential) catch
                oom();
        }

        fn certified(self: *Self, certificate: anytype) ?Certified {
            if (!self.verified(certificate)) return null;
            const proposal = certificate.proposal;
            return .{
                .view = proposal.view().get(),
                .payload = proposal.payload,
                .parent = proposal.parent.get(),
                .signature_count = self.signature_count(&certificate.certificate),
            };
        }

        fn signature_count(self: *Self, certificate: *const S.Certificate) ?u32 {
            if (!S.is_attributable()) return null;
            const bytes = codec.encode(S.Certificate, self.gpa, certificate.*) catch oom();
            defer self.gpa.free(bytes);
            var reader: codec.Reader = .init(bytes);
            const Signers = cryptography.certificate.Signers;
            var signers = Signers.read(self.gpa, &reader, self.participants) catch
                @panic("certificate signers must decode");
            defer signers.deinit(self.gpa);
            const count: u32 = @intCast(signers.count());
            assert(count <= self.participants);
            return count;
        }

        /// Waits until a finalization at or above `view` was reported.
        pub fn wait_for_finalized(self: *Self, view: u64) Io.Cancelable!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Each wake re-checks the latest finalized view.
            while (self.latest < view) try self.condition.wait(self.io, &self.mutex);
            assert(self.latest >= view);
        }

        /// The recorded certificates, each sorted by view, allocated in `arena`.
        pub fn replica(self: *Self, arena: Allocator) Allocator.Error!fuzz_types.Replica {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return .{
                .notarizations = try sorted(Certified, arena, &self.notarizations),
                .nullifications = try sorted(Nullification, arena, &self.nullifications),
                .finalizations = try sorted(Certified, arena, &self.finalizations),
                .notarize_votes = try sorted(Voted, arena, &self.notarize_votes),
                .nullify_votes = try sorted(Voted, arena, &self.nullify_votes),
                .finalize_votes = try sorted(Voted, arena, &self.finalize_votes),
            };
        }

        fn sorted(
            comptime T: type,
            arena: Allocator,
            map: *const std.AutoHashMapUnmanaged(u64, T),
        ) Allocator.Error![]const T {
            const items = try arena.alloc(T, map.count());
            var it = map.valueIterator();
            var index: usize = 0;
            while (it.next()) |value| : (index += 1) items[index] = value.*;
            assert(index == items.len);
            std.sort.block(T, items, {}, struct {
                fn less_than(_: void, a: T, b: T) bool {
                    return a.view < b.view;
                }
            }.less_than);
            return items;
        }
    };
}
