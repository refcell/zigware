//! The reshare application wrapper (commonware `reshare/application.rs`).
//!
//! `Application(A, T)` wraps a marshal application `A` and implements the reshare
//! application contract: proposals from the midpoint on carry this node's dealer log when one
//! is available, the final block carries the payload the actor derives (`Mailbox.epoch_info`),
//! and verification rejects a final block whose payload differs from the derived one and a
//! non-final block carrying anything but a dealer log from the midpoint on. When the actor
//! cannot derive the final payload, verification stays pending until canceled.
//!
//! zigware's marshal contract (`consensus.marshal.application.build`) has no `Input` type, so
//! the reshare payload reaches the inner application as an extra argument:
//! `A.propose(*A, ctx, consensus_context, ancestry, payload: ?Payload) !?Digested(Block)` and,
//! optionally, `A.prepare(..., payload)` (always called with null, as commonware forwards
//! `payload: None`). `A.verify(*A, ctx, consensus_context, ancestry) !bool` is unchanged. The
//! inner application owns `payload` and `ancestry`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const utils = @import("utils");
const mailbox_mod = @import("mailbox.zig");

const Height = consensus.Height;
const EpochPhase = consensus.types.EpochPhase;
const FixedEpocher = consensus.types.FixedEpocher;
const Handoff = consensus.Handoff;
const log = std.log.scoped(.dkg_reshare);

/// Wraps marshal application `A` (pointer-free value, cloned like the inner) with the reshare
/// mailbox of the actor types `T`.
pub fn Application(comptime A: type, comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Block = T.Block;
        pub const Mailbox = mailbox_mod.Mailbox(T);
        pub const Payload = mailbox_mod.PayloadOf(T);
        const Digested = broadcast.Digested(Block);
        /// The inner application's type when `A` is a pointer to it.
        const Inner = switch (@typeInfo(A)) {
            .pointer => |pointer| pointer.child,
            else => A,
        };
        const by_value = @typeInfo(A) != .pointer;

        inner: A,
        reshare: Mailbox,
        epocher: FixedEpocher,

        /// Wraps `inner` (taken) with `reshare` (taken). `blocks_per_epoch` must equal the
        /// actor's.
        pub fn init(inner: A, reshare: Mailbox, blocks_per_epoch: u64) Self {
            const length = utils.NonZero(u64).init(blocks_per_epoch).?;
            const result: Self = .{ .inner = inner, .reshare = reshare, .epocher = .new(length) };
            assert(result.epocher.length == blocks_per_epoch);
            return result;
        }

        pub fn clone(self: *const Self) Self {
            const clones = comptime by_value and @hasDecl(A, "clone");
            const inner = if (clones) self.inner.clone() else self.inner;
            return .{ .inner = inner, .reshare = self.reshare.clone(), .epocher = self.epocher };
        }

        pub fn deinit(self: *Self) void {
            if (comptime by_value and @hasDecl(A, "deinit")) self.inner.deinit();
            self.reshare.deinit();
            self.* = undefined;
        }

        pub fn final_block(self: *const Self, height: Height) bool {
            const bounds = self.epocher.containing(height) orelse return false;
            return bounds.last.get() == height.get();
        }

        pub fn phase(self: *const Self, height: Height) ?EpochPhase {
            const bounds = self.epocher.containing(height) orelse return null;
            return bounds.phase();
        }

        fn inclusion_phase(value: ?EpochPhase) bool {
            const known = value orelse return false;
            return known == .midpoint or known == .late;
        }

        /// The height of the block that would extend `ancestry`'s head.
        fn next_height(ancestry: anytype) ?Height {
            const parent = ancestry.peek() orelse return null;
            return parent.inner().height().next();
        }

        /// Prepares a block unless this node's dealer log is due at its height or it is the
        /// epoch's final block; both are left to `propose` (commonware `prepare`). A dealer
        /// log found here is released at once, since consensus may discard a prepared block.
        pub fn prepare(
            self: *Self,
            ctx: anytype,
            consensus_context: anytype,
            ancestry: anytype,
        ) anyerror!Handoff(Digested) {
            var owned = ancestry;
            errdefer owned.deinit();
            const height = next_height(&owned) orelse {
                owned.deinit();
                return .wait;
            };
            if (self.final_block(height)) {
                owned.deinit();
                return .wait;
            }
            if (inclusion_phase(self.phase(height))) {
                if (try self.reshare.next_log(height)) |reservation| {
                    // Dropping the reservation releases the dealer log for later proposals.
                    var released = reservation;
                    released.deinit();
                    owned.deinit();
                    return .wait;
                }
            }
            if (comptime !@hasDecl(Inner, "prepare")) {
                owned.deinit();
                return .wait;
            }
            return self.inner.prepare(ctx, consensus_context, owned, @as(?Payload, null));
        }

        /// Selects the reshare payload for the block extending `ancestry` and asks the inner
        /// application to build on it (commonware `propose`). Null without asking the inner
        /// application when the parent is missing or the final block's info is unavailable.
        pub fn propose(
            self: *Self,
            ctx: anytype,
            consensus_context: anytype,
            ancestry: anytype,
        ) anyerror!?Digested {
            var owned = ancestry;
            errdefer owned.deinit();
            const height = next_height(&owned) orelse {
                log.debug("proposal rejected: missing parent ancestry", .{});
                owned.deinit();
                return null;
            };
            if (self.final_block(height)) {
                var response = try self.reshare.epoch_info(try owned.clone());
                switch (response) {
                    .unavailable => {
                        log.debug("proposal skipped: final block epoch info unavailable", .{});
                        response.deinit();
                        owned.deinit();
                        return null;
                    },
                    .available => |available| {
                        const payload = available.payload;
                        return self.inner.propose(ctx, consensus_context, owned, payload);
                    },
                }
            }
            if (!inclusion_phase(self.phase(height))) {
                return self.inner.propose(ctx, consensus_context, owned, @as(?Payload, null));
            }
            var reservation = try self.reshare.next_log(height);
            const payload: ?Payload = if (reservation) |*value| value.take_payload() else null;
            const built = self.inner.propose(ctx, consensus_context, owned, payload);
            const proposed = built catch |err| {
                if (reservation) |*value| value.deinit();
                return err;
            };
            if (reservation) |*value| {
                if (proposed != null) value.included() else value.deinit();
            }
            return proposed;
        }

        /// Checks the block at `ancestry`'s head against the reshare contract, then asks the
        /// inner application (commonware `verify`).
        pub fn verify(
            self: *Self,
            ctx: anytype,
            consensus_context: anytype,
            ancestry: anytype,
        ) anyerror!bool {
            var owned = ancestry;
            errdefer owned.deinit();
            const tip = owned.peek() orelse
                return self.inner.verify(ctx, consensus_context, owned);
            const height = tip.inner().height();
            const gpa = self.reshare.gpa;
            var carried = try tip.inner().payload(gpa);
            defer if (carried) |*value| value.deinit(gpa);
            if (self.final_block(height)) {
                var response = try self.reshare.epoch_info(try owned.clone());
                defer response.deinit();
                switch (response) {
                    .available => |available| if (!payloads_equal(available.payload, carried)) {
                        log.debug("verification rejected: final block payload mismatch", .{});
                        owned.deinit();
                        return false;
                    },
                    .unavailable => {
                        // Consensus journals `false` as a failed certification, so a block
                        // this node cannot check stays unresolved until consensus cancels it.
                        owned.deinit();
                        return pending(self.reshare.io);
                    },
                }
            } else if (!allowed_before_final(carried, self.phase(height))) {
                log.debug("verification rejected: misplaced reshare payload", .{});
                owned.deinit();
                return false;
            }
            return self.inner.verify(ctx, consensus_context, owned);
        }

        /// Before the final block only a dealer log may be carried, and only from the midpoint
        /// on; a height outside every epoch allows none.
        fn allowed_before_final(carried: ?Payload, height_phase: ?EpochPhase) bool {
            const payload = carried orelse return true;
            return switch (payload) {
                .dealer_log => inclusion_phase(height_phase),
                .epoch_info => false,
            };
        }

        fn payloads_equal(a: ?Payload, b: ?Payload) bool {
            if (a == null or b == null) return a == null and b == null;
            return a.?.eql(b.?);
        }

        fn pending(io: Io) anyerror!bool {
            while (true) try io.sleep(.fromSeconds(3_600), .awake);
        }
    };
}
