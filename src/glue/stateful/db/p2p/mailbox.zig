//! The QMDB sync resolver's mailbox (commonware `glue/src/stateful/db/p2p/mailbox.rs`).
//!
//! `Mailbox(DB, F, Op, D)` is the `qmdb.sync` Source a sync engine fetches from: `serve`
//! enqueues a fetch to the resolver actor and waits for its first candidate response, and the
//! returned `Feedback` judges it and receives later candidates. `attach_database` hands the
//! actor a database to serve peers from.
//!
//! While the actor's mailbox is full, only the latest attachment is kept, and fetches whose
//! caller stopped waiting are dropped (commonware's `Pending` overflow).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("../mod.zig");

const mpsc = utils.channel.mpsc;
const sync = storage.qmdb.sync;

/// Candidate responses for one fetch; each arrives with the sender of its verdict.
pub fn Reply(comptime R: type) type {
    return mpsc.Sender(sync.source.Candidate(R));
}

/// Messages from the `Mailbox` to the resolver actor.
pub fn Message(comptime DB: type, comptime F: type, comptime Op: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();
        pub const Request = sync.Request(F);
        pub const Response = sync.Response(F, Op, D);

        /// A database to serve peer requests from, replacing any earlier one.
        attach_database: db.Shared(DB),
        /// A fetch of the response to `request` from peers.
        get_operations: struct { request: Request, response: Reply(Response) },

        /// Whether the caller stopped waiting for this message's response.
        pub fn response_closed(self: *const Self) bool {
            return switch (self.*) {
                .attach_database => false,
                .get_operations => |*fetch| fetch.response.is_closed(),
            };
        }

        /// Releases the message (a dropped attachment keeps its database open: the caller
        /// that attached it owns it).
        pub fn discard(message: Self) void {
            var owned = message;
            switch (owned) {
                .attach_database => {},
                .get_operations => |*fetch| fetch.response.deinit(),
            }
        }

        /// Messages retained while the mailbox is full.
        pub const Overflow = struct {
            database: ?db.Shared(DB) = null,
            messages: std.Deque(Self) = .empty,

            pub const empty: Overflow = .{};

            pub fn deinit(overflow: *Overflow, gpa: Allocator) void {
                while (overflow.messages.popFront()) |message| discard(message);
                overflow.messages.deinit(gpa);
                overflow.* = undefined;
            }

            pub fn is_empty(overflow: *const Overflow) bool {
                return overflow.database == null and overflow.messages.len == 0;
            }

            /// Hands the latest attachment, then the live fetches in order, to `pusher`
            /// until ready is full again.
            pub fn drain(overflow: *Overflow, pusher: anytype) void {
                if (overflow.database) |database| {
                    overflow.database = null;
                    if (pusher.push(.{ .attach_database = database })) |returned| {
                        overflow.database = returned.attach_database;
                        return;
                    }
                }
                while (overflow.messages.popFront()) |message| {
                    if (message.response_closed()) {
                        discard(message);
                        continue;
                    }
                    const returned = pusher.push(message) orelse continue;
                    // Proof: the slot `popFront` freed is still free.
                    overflow.messages.pushFrontAssumeCapacity(returned);
                    break;
                }
            }
        };

        /// Keeps the latest attachment and every fetch whose caller still waits.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message.response_closed()) {
                discard(message);
                return;
            }
            switch (message) {
                .attach_database => |database| overflow.database = database,
                .get_operations => overflow.messages.pushBack(gpa, message) catch |err| {
                    discard(message);
                    return err;
                },
            }
        }
    };
}

/// The resolver mailbox for one QMDB history, and the sync `Source` over it.
pub fn Mailbox(comptime DB: type, comptime F: type, comptime O: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Family = F;
        pub const Digest = D;
        pub const Op = O;
        pub const Msg = Message(DB, F, O, D);
        pub const Response = Msg.Response;
        /// `ResponseDropped`: the resolver actor dropped the fetch before a response
        /// (commonware's error); `OutOfMemory`: the reply channel could not be allocated.
        pub const Error = error{ResponseDropped} || Allocator.Error;

        io: Io,
        sender: actor.mailbox.Sender(Msg),

        pub fn init(io: Io, sender: actor.mailbox.Sender(Msg)) Self {
            return .{ .io = io, .sender = sender };
        }

        pub fn clone(self: Self) Self {
            return .{ .io = self.io, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Attaches `database` for serving peer requests, replacing any earlier one. Reads in
        /// progress keep the database they started with. Fails only when the overflow cannot
        /// grow.
        pub fn attach_database(self: Self, database: db.Shared(DB)) Allocator.Error!void {
            _ = try self.sender.enqueue(.{ .attach_database = database });
        }

        /// Fetches `request` from peers: the first candidate response and its feedback.
        pub fn serve(
            self: *Self,
            gpa: Allocator,
            request: Msg.Request,
        ) (Error || Io.Cancelable)!sync.Served(Response) {
            const pair = try mpsc.channel(sync.source.Candidate(Response), gpa, self.io, 1);
            var candidates = pair.receiver;
            errdefer candidates.deinit();
            // On failure the mailbox released the reply sender, so `recv` would end at once.
            _ = try self.sender.enqueue(.{
                .get_operations = .{ .request = request, .response = pair.sender },
            });
            const first = try candidates.recv() orelse return error.ResponseDropped;
            return .{ .response = first.response, .feedback = .init(first.verdict, candidates) };
        }
    };
}
