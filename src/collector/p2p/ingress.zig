//! The engine's mailbox (commonware `collector/src/p2p/ingress.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const actor = @import("actor");
const p2p = @import("p2p");

const Feedback = actor.Feedback;

fn free_value(comptime T: type, gpa: Allocator, value: T) void {
    if (comptime @typeInfo(T) == .@"struct" and @hasDecl(T, "deinit")) {
        var owned = value;
        owned.deinit(gpa);
    }
}

/// Messages that can be sent to a `Mailbox`. `request` and `some` recipients are owned and
/// freed with `gpa`.
pub fn Message(comptime P: type, comptime R: type) type {
    return union(enum) {
        const Self = @This();
        pub const Overflow = std.Deque(Self);

        send: Send,
        cancel: Cancel,

        pub const Send = struct {
            gpa: Allocator,
            request: R,
            recipients: p2p.Recipients(P),
        };
        pub const Cancel = struct { commitment: R.Commitment };

        /// Releases everything the message owns (Rust `Drop`).
        pub fn discard(message: Self) void {
            switch (message) {
                .send => |send| {
                    send.recipients.deinit(send.gpa);
                    free_value(R, send.gpa, send.request);
                },
                .cancel => {},
            }
        }

        /// The overflow policy (commonware `Policy::handle`). Sends stay separate even for
        /// one commitment, so peers never receive bytes meant for another send. A cancel
        /// drops queued sends it supersedes and coalesces queued cancels of the same
        /// commitment, keeping one (the actor may already have state for it).
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            const cancel = switch (message) {
                .send => {
                    overflow.pushBack(gpa, message) catch |err| {
                        discard(message);
                        return err;
                    };
                    return;
                },
                .cancel => |cancel| cancel,
            };
            var canceled = false;
            var kept: usize = 0;
            const len = overflow.len;
            for (0..len) |index| {
                const queued = overflow.at(index);
                const keep = switch (queued) {
                    .send => |send| !send.request.commitment().eql(cancel.commitment),
                    .cancel => |other| !other.commitment.eql(cancel.commitment) or !canceled,
                };
                if (queued == .cancel and queued.cancel.commitment.eql(cancel.commitment)) {
                    canceled = true;
                }
                if (!keep) {
                    discard(queued);
                    continue;
                }
                overflow.atPtr(kept).* = queued;
                kept += 1;
            }
            while (overflow.len > kept) _ = overflow.popBack();
            assert(overflow.len <= len);
            if (!canceled) try overflow.pushBack(gpa, message); // a cancel owns nothing
        }
    };
}

/// A mailbox for an engine (commonware's `Originator`). Clone with `clone`, release with
/// `deinit`.
pub fn Mailbox(comptime P: type, comptime R: type) type {
    return struct {
        const Self = @This();
        const Msg = Message(P, R);
        pub const PublicKey = P;
        pub const Request = R;

        gpa: Allocator,
        sender: actor.mailbox.Sender(Msg),

        pub fn clone(mailbox: Self) Self {
            return .{ .gpa = mailbox.gpa, .sender = mailbox.sender.clone() };
        }

        pub fn deinit(mailbox: *Self) void {
            mailbox.sender.deinit();
            mailbox.* = undefined;
        }

        /// Enqueues `request` (owned from now on) to `recipients` (copied).
        pub fn send(mailbox: Self, recipients: p2p.Recipients(P), request: R) !Feedback {
            const owned: p2p.Recipients(P) = switch (recipients) {
                .some => |peers| .{ .some = mailbox.gpa.dupe(P, peers) catch |err| {
                    free_value(R, mailbox.gpa, request);
                    return err;
                } },
                else => recipients,
            };
            return mailbox.sender.enqueue(.{ .send = .{
                .gpa = mailbox.gpa,
                .request = request,
                .recipients = owned,
            } });
        }

        /// Enqueues cancellation of the request with `commitment`, ignoring later responses.
        pub fn cancel(mailbox: Self, commitment: R.Commitment) !Feedback {
            return mailbox.sender.enqueue(.{ .cancel = .{ .commitment = commitment } });
        }
    };
}
