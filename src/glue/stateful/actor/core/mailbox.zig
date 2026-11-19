//! The `Stateful` actor's mailbox (commonware `glue/src/stateful/actor/core/mailbox.rs`).
//!
//! `Mailbox(P)` is the marshal application consensus drives (`prepare`, `propose`, `verify`)
//! and the `Reporter` of marshal's finalized `Update`s. It forwards each call to the actor as a
//! `Message`. When the mailbox is full, overflow keeps every message in order and drops a
//! request once its caller has gone (commonware's `Pending`).
//!
//! `P` declares `App` (with `Block` and optionally `Context`, the consensus context, defaulting
//! to `Block.Context`; `Input`, the per-proposal input, defaulting to `void`; and
//! `deinit_input(*Input)` when inputs own memory) and `Databases`.
//!
//! # Answers
//!
//! - `prepare` answers `.wait` and `propose` answers null when the actor declines or stops.
//! - `verify` answers the actor's verdict. The actor drops the verdict unsent when it cannot
//!   decide (a waiting verification, commonware's pending future); `verify` then waits until
//!   consensus cancels it, so a waiting block is never voted against. Commonware panics when
//!   the actor stops during a verify; here that also reads as no verdict.
//!
//! Differences from commonware: a queued verification owns its ancestry (commonware holds a
//! weak handle the caller owns). Blocks are reference counted, so a cancelled caller's blocks
//! live until the actor drops the obsolete request.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const utils = @import("utils");
const boxed = @import("../processor/boxed.zig");

const oneshot = utils.channel.oneshot;
const Exact = utils.acknowledgement.Exact;
const Handoff = consensus.Handoff;

/// `MailboxOf` keyed by `P`'s `App` and `Databases` only, so every `P` declaring the same two
/// (the actor's, its processing loop's, and its syncing mode's) shares one message type.
pub fn Mailbox(comptime P: type) type {
    return MailboxOf(P.App, P.Databases);
}

fn MailboxOf(comptime App_: type, comptime Databases_: type) type {
    const P = struct {
        pub const App = App_;
        pub const Databases = Databases_;
    };
    return struct {
        const Self = @This();
        pub const App = P.App;
        pub const Databases = P.Databases;
        pub const Block = App.Block;
        pub const Digested = broadcast.Digested(Block);
        pub const Ancestry = boxed.Boxed(Block);
        pub const Context = if (@hasDecl(App, "Context")) App.Context else Block.Context;
        pub const Input = if (@hasDecl(App, "Input")) App.Input else void;
        pub const Update = consensus.marshal.Update(Block, Exact);

        /// A prepare's answer in a oneshot; a vote or stage nobody received is released.
        pub const Built = struct {
            handoff: Handoff(Digested),

            pub fn discard(self: Built) void {
                switch (self.handoff) {
                    .vote, .stage => |block| block.discard(),
                    .wait => {},
                }
            }
        };

        /// The response channel of a proposal, by kind (commonware `Proposal`).
        pub const Proposal = union(enum) {
            /// A proposal before the parent certifies: the block under a decision, or `.wait`.
            prepare: oneshot.Sender(Built),
            /// An ordinary proposal: the block, or nothing (the sender dropped unsent).
            propose: oneshot.Sender(Digested),

            pub fn is_cancelled(self: *const Proposal) bool {
                return switch (self.*) {
                    inline else => |*sender| sender.is_closed(),
                };
            }

            /// Answers that no block was built.
            pub fn decline(self: *Proposal) void {
                switch (self.*) {
                    .prepare => |*sender| sender.send(.{ .handoff = .wait }) catch {},
                    .propose => |*sender| sender.deinit(),
                }
                self.* = undefined;
            }
        };

        /// A request to prepare or propose a block. It is also the verifications handler's
        /// `Recover`: a proposal recovering its parent's state.
        pub const ProposalRequest = struct {
            context: Context,
            /// The parent first.
            ancestry: Ancestry,
            upstream: Input,
            proposal: Proposal,

            pub fn is_cancelled(self: *const ProposalRequest) bool {
                return self.proposal.is_cancelled();
            }

            /// Declines and releases the request.
            pub fn decline(self: *ProposalRequest) void {
                self.release_inputs();
                self.proposal.decline();
                self.* = undefined;
            }

            /// Releases the request unanswered (`propose` reads null, `prepare` `.wait`).
            pub fn deinit(self: *ProposalRequest) void {
                self.release_inputs();
                switch (self.proposal) {
                    inline else => |*sender| sender.deinit(),
                }
                self.* = undefined;
            }

            fn release_inputs(self: *ProposalRequest) void {
                self.ancestry.deinit();
                if (comptime @hasDecl(App, "deinit_input")) App.deinit_input(&self.upstream);
            }
        };

        /// A request to verify the block at the head of `ancestry`.
        pub const VerificationRequest = struct {
            ancestry: Ancestry,
            verification: oneshot.Sender(bool),
        };

        /// Messages the actor loop handles.
        pub const Message = union(enum) {
            propose: ProposalRequest,
            verify: VerificationRequest,
            /// A finalized block and its marshal acknowledgement.
            finalized: struct { block: Digested, acknowledgement: Exact },
            /// A request for the database set (see `subscribe_databases`).
            subscribe_databases: oneshot.Sender(Databases),

            /// Whether the caller stopped waiting (a finalization is never obsolete).
            pub fn is_obsolete(self: *const Message) bool {
                return switch (self.*) {
                    .propose => |*request| request.is_cancelled(),
                    .verify => |*request| request.verification.is_closed(),
                    .subscribe_databases => |*sender| sender.is_closed(),
                    .finalized => false,
                };
            }

            /// Releases a message unanswered; a dropped finalization cancels its
            /// acknowledgement.
            pub fn discard(message: Message) void {
                var owned = message;
                switch (owned) {
                    .propose => |*request| request.deinit(),
                    .verify => |*request| {
                        request.ancestry.deinit();
                        request.verification.deinit();
                    },
                    .finalized => |*value| {
                        value.block.deinit();
                        value.acknowledgement.deinit();
                    },
                    .subscribe_databases => |*sender| sender.deinit(),
                }
            }

            /// FIFO overflow that drops requests whose callers left.
            pub const Overflow = struct {
                pending: std.Deque(Message) = .empty,

                pub const empty: Overflow = .{};

                pub fn deinit(overflow: *Overflow, gpa: Allocator) void {
                    while (overflow.pending.popFront()) |message| discard(message);
                    overflow.pending.deinit(gpa);
                    overflow.* = undefined;
                }

                pub fn is_empty(overflow: *const Overflow) bool {
                    return overflow.pending.len == 0;
                }

                pub fn drain(overflow: *Overflow, pusher: anytype) void {
                    while (overflow.pending.popFront()) |message| {
                        if (message.is_obsolete()) {
                            discard(message);
                            continue;
                        }
                        const returned = pusher.push(message) orelse continue;
                        // Proof: the slot `popFront` freed is still free.
                        overflow.pending.pushFrontAssumeCapacity(returned);
                        break;
                    }
                }
            };

            pub fn handle(
                gpa: Allocator,
                overflow: *Overflow,
                message: Message,
            ) Allocator.Error!void {
                if (message.is_obsolete()) return discard(message);
                overflow.pending.pushBack(gpa, message) catch |err| {
                    discard(message);
                    return err;
                };
            }
        };

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(Message),

        pub fn init(gpa: Allocator, io: Io, sender: actor.mailbox.Sender(Message)) Self {
            return .{ .gpa = gpa, .io = io, .sender = sender };
        }

        pub fn clone(self: *const Self) Self {
            return .{ .gpa = self.gpa, .io = self.io, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        fn enqueue(self: *const Self, message: Message) !actor.Feedback {
            const feedback = try self.sender.enqueue(message);
            assert(feedback != .backoff or !self.sender.is_closed());
            return feedback;
        }

        /// The database set once startup completes (after state sync, if it runs); later
        /// calls resolve in mailbox order. Holders must not prune these databases.
        /// `error.ActorStopped` when the actor stops first (commonware panics).
        pub fn subscribe_databases(self: *const Self) !Databases {
            const pair = try oneshot.channel(Databases, self.gpa, self.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            _ = try self.enqueue(.{ .subscribe_databases = pair.sender });
            return receiver.recv() catch |err| switch (err) {
                error.Closed => error.ActorStopped,
                else => |other| other,
            };
        }

        /// Boxes `ancestry` (taken, also on error).
        fn box(self: *const Self, ancestry: anytype) !Ancestry {
            if (@TypeOf(ancestry) == Ancestry) return ancestry;
            return Ancestry.init(self.gpa, ancestry);
        }

        /// Builds through the application's `prepare` on the actor; `.wait` when it declines.
        pub fn prepare(
            self: *Self,
            ctx: anytype,
            context: Context,
            ancestry: anytype,
            upstream: Input,
        ) !Handoff(Digested) {
            _ = ctx; // The actor owns the runtime context of every application call.
            const pair = try oneshot.channel(Built, self.gpa, self.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            // A message the mailbox cannot queue is released by its policy.
            _ = try self.enqueue(.{ .propose = .{
                .context = context,
                .ancestry = try self.box(ancestry),
                .upstream = upstream,
                .proposal = .{ .prepare = pair.sender },
            } });
            const built = receiver.recv() catch |err| switch (err) {
                error.Closed => return .wait,
                else => |other| return other,
            };
            return built.handoff;
        }

        /// Builds through the application's `propose` on the actor; null when it declines.
        pub fn propose(
            self: *Self,
            ctx: anytype,
            context: Context,
            ancestry: anytype,
            upstream: Input,
        ) !?Digested {
            _ = ctx;
            const pair = try oneshot.channel(Digested, self.gpa, self.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            _ = try self.enqueue(.{ .propose = .{
                .context = context,
                .ancestry = try self.box(ancestry),
                .upstream = upstream,
                .proposal = .{ .propose = pair.sender },
            } });
            return receiver.recv() catch |err| switch (err) {
                error.Closed => null,
                else => |other| other,
            };
        }

        /// The actor's verdict on the block at the head of `ancestry`. No verdict (the actor
        /// could not decide, or stopped) waits until consensus cancels: never `false`.
        pub fn verify(self: *Self, ctx: anytype, context: Context, ancestry: anytype) !bool {
            _ = ctx;
            _ = context; // The block carries its context.
            const pair = try oneshot.channel(bool, self.gpa, self.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            _ = try self.enqueue(.{ .verify = .{
                .ancestry = try self.box(ancestry),
                .verification = pair.sender,
            } });
            return receiver.recv() catch |err| switch (err) {
                error.Closed => abstain(self.io),
                else => |other| other,
            };
        }

        /// Waits until cancelled (commonware's pending verification).
        fn abstain(io: Io) Io.Cancelable!bool {
            // Each pass sleeps an hour; only cancellation ends the loop.
            while (true) try io.sleep(.fromSeconds(3_600), .awake);
        }

        /// Forwards a finalized block (taken with its acknowledgement); tips need nothing.
        pub fn report(self: *Self, activity: Update) actor.Feedback {
            switch (activity) {
                .tip => return .ok,
                .block => |value| {
                    const message: Message = .{ .finalized = .{
                        .block = value.block,
                        .acknowledgement = value.ack,
                    } };
                    // An overflow that cannot grow drops the report and cancels its
                    // acknowledgement, which stops marshal as commonware's abort would.
                    return self.enqueue(message) catch .closed;
                },
            }
        }
    };
}
