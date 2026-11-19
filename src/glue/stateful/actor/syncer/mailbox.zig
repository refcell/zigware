//! The `Syncer` actor's ingress (commonware `glue/src/stateful/actor/syncer/mailbox.rs`).
//!
//! `Mailbox.retarget` hands the running state sync a finalized tip and waits until its
//! coordinator recorded it, or returns the converged `Artifact` if the sync finished first.
//! While the mailbox is full only the newest update is kept: `retarget` has one caller, which
//! awaits each update before sending the next, so a replaced update never had a live caller.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const utils = @import("utils");
const db_sync = @import("../../db/sync.zig");

const oneshot = utils.channel.oneshot;
const Anchor = db_sync.Anchor;
const TipUpdate = db_sync.TipUpdate;

/// Databases `DBs` and the anchor (digest `D`) of the block they reflect (commonware
/// `Artifact`).
pub fn Artifact(comptime DBs: type, comptime D: type) type {
    return struct {
        /// The database handle set.
        databases: DBs,
        /// Anchor of the block reflected by `databases`.
        anchor: Anchor(D),
    };
}

/// Messages to the syncer: tip updates of digest `D` and sync targets `T`, answered with
/// artifact `A` once the sync converged.
pub fn Message(comptime A: type, comptime D: type, comptime T: type) type {
    return union(enum) {
        const Self = @This();
        pub const Update = TipUpdate(D, T);

        /// A target update; `response` gets null once it is accepted, or the artifact if
        /// state sync already converged.
        retarget: struct { update: Update, response: oneshot.Sender(?A) },

        /// Releases an unhandled message: its observer and response fail.
        pub fn discard(message: Self) void {
            var owned = message;
            owned.retarget.update.discard();
            owned.retarget.response.deinit();
        }

        /// The newest update while the mailbox is full.
        pub const Overflow = struct {
            slot: ?Self = null,

            pub const empty: Overflow = .{};

            pub fn deinit(overflow: *Overflow, _: Allocator) void {
                if (overflow.slot) |message| discard(message);
                overflow.* = undefined;
            }

            pub fn is_empty(overflow: *const Overflow) bool {
                return overflow.slot == null;
            }

            pub fn drain(overflow: *Overflow, pusher: anytype) void {
                const message = overflow.slot orelse return;
                overflow.slot = pusher.push(message);
            }
        };

        /// Replaces the retained update, dropping its response.
        pub fn handle(_: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (overflow.slot) |replaced| discard(replaced);
            overflow.slot = message;
            assert(!overflow.is_empty());
        }
    };
}

/// The ingress of the syncer actor.
pub fn Mailbox(comptime A: type, comptime D: type, comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Msg = Message(A, D, T);
        /// `SyncerStopped`: the syncer dropped an update without answering (commonware
        /// panics).
        pub const Error = error{SyncerStopped} || Allocator.Error || Io.Cancelable;

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(Msg),

        pub fn init(gpa: Allocator, io: Io, sender: actor.mailbox.Sender(Msg)) Self {
            return .{ .gpa = gpa, .io = io, .sender = sender };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Sends a target update and waits until the sync coordinator records it: null once
        /// recorded, or the converged artifact if state sync finished first.
        pub fn retarget(self: Self, anchor: Anchor(D), targets: T) Error!?A {
            while (true) {
                var observed = try Msg.Update.with_observation(self.gpa, self.io, anchor, targets);
                defer observed.observed.deinit();
                var pair = oneshot.channel(?A, self.gpa, self.io) catch |err| {
                    observed.update.discard();
                    return err;
                };
                defer pair.receiver.deinit();
                // On failure the mailbox released the message, so `recv` ends at once.
                _ = try self.sender.enqueue(.{ .retarget = .{
                    .update = observed.update,
                    .response = pair.sender,
                } });
                const answer = pair.receiver.recv() catch |err| switch (err) {
                    error.Closed => return error.SyncerStopped,
                    error.Canceled => return error.Canceled,
                };
                if (answer) |artifact| return artifact;
                // Enqueueing can race with convergence, so wait for the coordinator to record
                // it. A dropped observation retries until recorded or answered with the
                // artifact.
                observed.observed.recv() catch |err| switch (err) {
                    error.Closed => continue,
                    error.Canceled => return error.Canceled,
                };
                return null;
            }
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("mailbox_test.zig");
}
