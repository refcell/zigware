//! Messages to the marshal actor and the mailbox that sends them (commonware
//! `marshal/core/mailbox.rs`).
//!
//! When the actor's inbox is full, overflow coalesces the messages that only carry the latest
//! intent: floors collapse to the highest round, prunes to the highest height, and finalized
//! hints to one entry per height with the union of their targets. Everything else keeps FIFO
//! order, minus requests whose responder closed and height-bound reads below a pending prune.
//! Overflow hands the floor first, then the prune, then the queue, so the actor raises its
//! floor before it sees the reads that follow.
//!
//! A message owns what it carries (blocks, certificates, owned `some` recipients, hint
//! targets, and responders) and the allocator that frees them if the mailbox drops it (Rust's
//! `Drop`). Rust's tracing spans are not carried.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");
const variant = @import("variant.zig");
const floor = @import("floor.zig");
const ancestry = @import("../ancestry.zig");

const oneshot = utils.channel.oneshot;
const Feedback = actor.Feedback;
const Height = types.Height;
const Round = types.Round;
const Processed = floor.Processed;
const Timed = runtime.telemetry.metrics.histogram.Timed;

/// A block by height, by digest, or the latest finalized one (commonware
/// `marshal::Identifier`).
pub fn Identifier(comptime D: type) type {
    return union(enum) {
        height: Height,
        digest: D,
        latest,
    };
}

/// How a digest-keyed subscription behaves when the block is missing locally.
pub const DigestFallback = union(enum) {
    /// Wait for local availability only.
    wait,
    /// Request the notarized proposal for this round from peers. Use it only with a trusted
    /// round for the digest: digest-keyed subscriptions cannot request exact commitments.
    fetch_by_round: Round,

    pub fn commitment_fallback(self: DigestFallback) CommitmentFallback {
        return switch (self) {
            .wait => .wait,
            .fetch_by_round => |round| .{ .fetch_by_round = round },
        };
    }
};

/// How a commitment-keyed subscription behaves when the block is missing locally.
pub const CommitmentFallback = union(enum) {
    /// Wait for local availability only, as for candidate data before notarization.
    wait,
    /// Request the notarized proposal for this round from peers. Peers serve it only once
    /// they hold its notarization; the request stays eligible until the processed round
    /// floor covers the round.
    fetch_by_round: Round,
    /// Request the exact commitment from peers, retaining the request up to this height (a
    /// local hint, never sent). Use it only without a parent round, with a locally
    /// validated retention bound, such as when repairing a finalized gap.
    fetch_by_commitment: Height,
};

/// A message to the marshal actor under scheme `S` and variant `V`.
pub fn Message(comptime S: type, comptime V: type) type {
    comptime variant.assert_variant(V);
    return struct {
        const Self = @This();
        pub const Block = V.Block;
        pub const Digest = V.Block.Digest;
        pub const Commitment = V.Commitment;
        pub const PublicKey = S.PublicKey;
        pub const Finalization = simplex_types.Finalization(S, V.Commitment);
        pub const Notarization = simplex_types.Notarization(S, V.Commitment);
        pub const Recipients = p2p.Recipients(S.PublicKey);
        pub const Info = struct { height: Height, digest: Digest };
        pub const Anchor = struct { processed: Processed, block: Block };
        pub const Overflow = Pending(S, V);

        /// Frees what the body owns.
        gpa: Allocator,
        body: Body,

        pub const Body = union(enum) {
            /// `(height, digest)` of a finalized block, or null.
            get_info: struct { identifier: Identifier(Digest), response: oneshot.Sender(?Info) },
            /// A block from local storage. By height or latest only finalized blocks; by
            /// digest possibly unfinalized or unverified ones.
            get_block: struct { identifier: Identifier(Digest), response: oneshot.Sender(?Block) },
            get_finalization: struct { height: Height, response: oneshot.Sender(?Finalization) },
            get_processed: struct { response: oneshot.Sender(?Processed) },
            /// The processed position and the stored block that backs it.
            get_anchor: struct { response: oneshot.Sender(?Anchor) },
            /// A finalized block may be available at `height` from `targets` (owned, non-empty).
            hint_finalized: struct { height: Height, targets: []PublicKey },
            subscribe_by_digest: struct {
                digest: Digest,
                fallback: DigestFallback,
                response: oneshot.Sender(Block),
            },
            subscribe_by_commitment: struct {
                commitment: Commitment,
                fallback: CommitmentFallback,
                response: oneshot.Sender(Block),
            },
            /// Fetch the block notarized at `round` unless `commitment` is already local.
            hint_notarized: struct { round: Round, commitment: Commitment },
            get_verified: struct { round: Round, response: oneshot.Sender(?Block) },
            forward: struct { round: Round, commitment: Commitment, recipients: Recipients },
            /// Broadcast a locally proposed block, then persist it; `ack` fires once durable.
            proposed: struct {
                round: Round,
                block: Block,
                recipients: Recipients,
                ack: oneshot.Sender(void),
            },
            /// Broadcast a held term-start candidate without persisting it.
            prepared: struct { round: Round, block: Block, recipients: Recipients },
            /// A block reached the verify stage; `ack` fires once it is durable.
            verified: struct { round: Round, block: Block, ack: oneshot.Sender(void) },
            /// A block reached the certify stage; `ack` fires once it is durable.
            certified: struct { round: Round, block: Block, ack: oneshot.Sender(void) },
            /// A candidate sync floor, verified by the actor before use.
            set_floor: Finalization,
            /// Prune finalized blocks and certificates below this height.
            prune: Height,
            notarization: Notarization,
            finalization: Finalization,
            certification: Notarization,
        };

        /// The operation name (commonware `Message::name`).
        pub fn name(self: *const Self) []const u8 {
            return @tagName(self.body);
        }

        /// Whether the message can no longer be served against prune height `current`.
        pub fn stale(self: *const Self, current: ?Height) bool {
            const below = struct {
                fn below(height: Height, bound: ?Height) bool {
                    return bound != null and height.get() < bound.?.get();
                }
            }.below;
            return switch (self.body) {
                // Height-targeted reads below the floor can never be served.
                inline .get_info, .get_block => |body| body.identifier == .height and
                    below(body.identifier.height, current),
                .get_finalization => |body| below(body.height, current),
                // Hints only inform the actor about heights strictly above the floor.
                .hint_finalized => |body| current != null and
                    body.height.get() <= current.?.get(),
                // Durability acks cannot be dropped, and the rest are not bound to a height.
                else => false,
            };
        }

        /// Whether the caller dropped the receiver of this request's response.
        pub fn response_closed(self: *const Self) bool {
            return switch (self.body) {
                inline else => |body| if (comptime has_field(@TypeOf(body), "response"))
                    body.response.is_closed()
                else
                    false,
            };
        }

        /// Releases a message the mailbox drops, closing its responder or ack.
        pub fn discard(message: Self) void {
            const gpa = message.gpa;
            switch (message.body) {
                inline .set_floor, .notarization, .finalization, .certification => |value| {
                    var certificate = value;
                    certificate.deinit(gpa);
                },
                .prune => {},
                inline else => |value| {
                    var body = value;
                    const Body_ = @TypeOf(body);
                    if (comptime has_field(Body_, "response")) body.response.deinit();
                    if (comptime has_field(Body_, "ack")) body.ack.deinit();
                    if (comptime has_field(Body_, "block")) V.deinit_block(gpa, &body.block);
                    if (comptime has_field(Body_, "recipients")) body.recipients.deinit(gpa);
                    if (comptime has_field(Body_, "targets")) gpa.free(body.targets);
                },
            }
        }

        /// The overflow policy (commonware `Policy::handle`): coalesces hints, floors, and
        /// prunes, and queues the rest unless closed or stale.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            // A closed responder cannot be served.
            if (message.response_closed()) return discard(message);
            switch (message.body) {
                .hint_finalized => try overflow.hint_finalized(gpa, message),
                .set_floor => overflow.set_floor(message),
                .prune => overflow.set_prune(message),
                else => {
                    if (message.stale(overflow.height())) return discard(message);
                    errdefer discard(message);
                    try overflow.messages.pushBack(gpa, .{ .message = message });
                    assert(!overflow.is_empty());
                },
            }
        }
    };
}

fn has_field(comptime T: type, comptime field: []const u8) bool {
    return @typeInfo(T) == .@"struct" and @hasField(T, field);
}

/// Messages held while the actor's inbox is full (commonware `Pending`).
pub fn Pending(comptime S: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const M = Message(S, V);
        const PublicKey = S.PublicKey;

        /// The union of every pending hint's targets at one height.
        pub const Hint = struct { gpa: Allocator, targets: []PublicKey };
        /// A queued message, or the place of the coalesced hint at a height.
        pub const Entry = union(enum) { message: M, hint_finalized: Height };

        /// The highest-round floor (a `set_floor` message).
        floor: ?M = null,
        /// The highest prune (a `prune` message).
        prune: ?M = null,
        hints: std.AutoArrayHashMapUnmanaged(u64, Hint) = .empty,
        messages: std.Deque(Entry) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.floor) |message| M.discard(message);
            if (self.prune) |message| M.discard(message);
            while (self.messages.popFront()) |entry| switch (entry) {
                .message => |message| M.discard(message),
                .hint_finalized => {},
            };
            for (self.hints.values()) |hint| hint.gpa.free(hint.targets);
            self.hints.deinit(gpa);
            self.messages.deinit(gpa);
            self.* = undefined;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.floor == null and self.prune == null and self.hints.count() == 0 and
                self.messages.len == 0;
        }

        /// The pending prune height. Only prunes bound height staleness: a pending floor's
        /// height is unknown until its block is decoded.
        pub fn height(self: *const Self) ?Height {
            const message = self.prune orelse return null;
            return message.body.prune;
        }

        /// The pending targets for a hint at `at`, if any.
        pub fn hint_targets(self: *const Self, at: Height) ?[]const PublicKey {
            const hint = self.hints.get(at.get()) orelse return null;
            return hint.targets;
        }

        /// Drops hints at or below the prune height, closed requests, and stale requests.
        fn retain(self: *Self) void {
            const current = self.height();
            var index = self.hints.count();
            while (index > 0) {
                index -= 1;
                if (current == null or self.hints.keys()[index] > current.?.get()) continue;
                const hint = self.hints.values()[index];
                hint.gpa.free(hint.targets);
                self.hints.swapRemoveAt(index);
            }
            const count = self.messages.len;
            for (0..count) |_| {
                const entry = self.messages.popFront().?;
                const keep = switch (entry) {
                    .message => |*message| !message.response_closed() and
                        !message.stale(current),
                    .hint_finalized => |at| self.hints.contains(at.get()),
                };
                if (keep) {
                    self.messages.pushBackAssumeCapacity(entry);
                } else if (entry == .message) {
                    M.discard(entry.message);
                }
            }
            assert(self.messages.len <= count);
        }

        fn set_floor(self: *Self, message: M) void {
            assert(message.body == .set_floor);
            if (self.floor) |*old| {
                const order = old.body.set_floor.round().order(message.body.set_floor.round());
                if (order != .lt) return M.discard(message);
                M.discard(old.*);
            }
            self.floor = message;
        }

        fn set_prune(self: *Self, message: M) void {
            assert(message.body == .prune);
            if (self.height()) |current| {
                if (current.get() >= message.body.prune.get()) return M.discard(message);
            }
            if (self.prune) |old| M.discard(old);
            self.prune = message;
            self.retain();
        }

        fn hint_finalized(self: *Self, gpa: Allocator, message: M) Allocator.Error!void {
            const body = message.body.hint_finalized;
            assert(body.targets.len > 0);
            // The finalized height is already covered by the prune point.
            if (message.stale(self.height())) return M.discard(message);
            errdefer M.discard(message);
            try self.messages.ensureUnusedCapacity(gpa, 1);
            const entry = try self.hints.getOrPut(gpa, body.height.get());
            if (!entry.found_existing) {
                entry.value_ptr.* = .{ .gpa = message.gpa, .targets = body.targets };
                self.messages.pushBackAssumeCapacity(.{ .hint_finalized = body.height });
                return;
            }
            try extend_targets(entry.value_ptr, body.targets);
            M.discard(message);
        }

        /// Adds the targets `pending` lacks.
        fn extend_targets(pending: *Hint, targets: []const PublicKey) Allocator.Error!void {
            var added: usize = 0;
            for (targets, 0..) |target, index| {
                if (contains(pending.targets, target)) continue;
                if (contains(targets[0..index], target)) continue;
                added += 1;
            }
            if (added == 0) return;
            const old_len = pending.targets.len;
            pending.targets = try pending.gpa.realloc(pending.targets, old_len + added);
            var next = old_len;
            for (targets) |target| {
                if (contains(pending.targets[0..next], target)) continue;
                pending.targets[next] = target;
                next += 1;
            }
            assert(next == pending.targets.len);
        }

        fn contains(targets: []const PublicKey, target: PublicKey) bool {
            for (targets) |candidate| {
                if (PublicKey.order(candidate, target) == .eq) return true;
            }
            return false;
        }

        /// Returns a hint taken by `drain` to its place at the front.
        fn restore_hint(self: *Self, message: M) void {
            const body = message.body.hint_finalized;
            // Proof of capacity: `drain` removed this height and popped its entry, and no
            // `handle` runs during a drain (both hold the mailbox lock).
            self.hints.putAssumeCapacityNoClobber(body.height.get(), .{
                .gpa = message.gpa,
                .targets = body.targets,
            });
            self.messages.pushFrontAssumeCapacity(.{ .hint_finalized = body.height });
        }

        /// Pushes `message`; on refusal restores it so the next drain retries from here.
        fn drain_one(self: *Self, message: M, pusher: anytype) bool {
            const rejected = pusher.push(message) orelse return true;
            switch (rejected.body) {
                .set_floor => {
                    assert(self.floor == null);
                    self.floor = rejected;
                },
                .prune => {
                    assert(self.prune == null);
                    self.prune = rejected;
                    self.retain();
                },
                .hint_finalized => self.restore_hint(rejected),
                else => self.messages.pushFrontAssumeCapacity(.{ .message = rejected }),
            }
            return false;
        }

        /// Hands the floor, then the prune, then the queue in FIFO order.
        pub fn drain(self: *Self, pusher: anytype) void {
            if (self.floor) |message| {
                self.floor = null;
                if (!self.drain_one(message, pusher)) return;
            }
            if (self.prune) |message| {
                self.prune = null;
                if (!self.drain_one(message, pusher)) return;
            }
            while (self.messages.popFront()) |entry| {
                const message: M = switch (entry) {
                    .message => |message| message,
                    .hint_finalized => |at| hint: {
                        const removed = self.hints.fetchSwapRemove(at.get()) orelse continue;
                        break :hint .{ .gpa = removed.value.gpa, .body = .{ .hint_finalized = .{
                            .height = at,
                            .targets = removed.value.targets,
                        } } };
                    },
                };
                if (message.response_closed()) {
                    M.discard(message);
                    continue;
                }
                if (!self.drain_one(message, pusher)) break;
            }
        }
    };
}

/// The marshal actor's mailbox (commonware `Mailbox`). Every method takes ownership of the
/// blocks, certificates, and owned recipients it is given.
pub fn Mailbox(comptime S: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const M = Message(S, V);
        pub const Error = Allocator.Error || Io.Cancelable;
        const MarshalBlock = M.Block;
        const Activity = simplex_types.Activity(S, V.Commitment);

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(M),
        /// How many application blocks marshal dispatches before acknowledgements must
        /// advance its processed floor.
        max_pending_acks: u32,

        pub fn init(
            gpa: Allocator,
            io: Io,
            sender: actor.mailbox.Sender(M),
            max_pending_acks: u32,
        ) Self {
            assert(max_pending_acks > 0);
            const max = max_pending_acks;
            return .{ .gpa = gpa, .io = io, .sender = sender, .max_pending_acks = max };
        }

        pub fn clone(self: Self) Self {
            var copy = self;
            copy.sender = self.sender.clone();
            return copy;
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        fn enqueue(self: Self, body: M.Body) Allocator.Error!Feedback {
            return self.sender.enqueue(.{ .gpa = self.gpa, .body = body });
        }

        /// Sends a `tag` request with `fields` and a fresh responder, then waits for the
        /// answer; a closed mailbox or an unanswered request reads as null.
        fn request(
            self: Self,
            comptime T: type,
            comptime tag: std.meta.Tag(M.Body),
            fields: anytype,
        ) Error!?T {
            var pair = try oneshot.channel(?T, self.gpa, self.io);
            defer pair.receiver.deinit();
            var body: @FieldType(M.Body, @tagName(tag)) = undefined;
            inline for (@typeInfo(@TypeOf(fields)).@"struct".field_names) |name| {
                @field(body, name) = @field(fields, name);
            }
            body.response = pair.sender;
            _ = try self.enqueue(@unionInit(M.Body, @tagName(tag), body));
            const answer = pair.receiver.recv() catch |err| switch (err) {
                error.Closed => return null,
                error.Canceled => return error.Canceled,
            };
            return answer;
        }

        /// `(height, digest)` of a finalized block by height, digest, or latest.
        pub fn get_info(self: Self, identifier: Identifier(M.Digest)) Error!?M.Info {
            return self.request(M.Info, .get_info, .{ .identifier = identifier });
        }

        /// A best-effort read of a block from local storage; it never fetches. The caller owns
        /// the block.
        pub fn get_block(self: Self, identifier: Identifier(M.Digest)) Error!?MarshalBlock {
            return self.request(MarshalBlock, .get_block, .{ .identifier = identifier });
        }

        /// A best-effort read of a finalization from local storage; it never fetches.
        pub fn get_finalization(self: Self, height: Height) Error!?M.Finalization {
            return self.request(M.Finalization, .get_finalization, .{ .height = height });
        }

        /// The latest processed position, if any.
        pub fn get_processed(self: Self) Error!?Processed {
            return self.request(Processed, .get_processed, .{});
        }

        /// The latest processed position and the stored block at its anchor, read together.
        pub fn get_anchor(self: Self) Error!?M.Anchor {
            return self.request(M.Anchor, .get_anchor, .{});
        }

        /// The verified block first persisted for `round`, if any. Several candidates can
        /// exist for one round; look up by digest for a particular one.
        pub fn get_verified(self: Self, round: Round) Error!?MarshalBlock {
            return self.request(MarshalBlock, .get_verified, .{ .round = round });
        }

        /// Hints that peers `targets` (borrowed, non-empty) hold the finalization at `height`.
        /// Repeated hints for one height add to its target set. Fire-and-forget.
        pub fn hint_finalized(
            self: Self,
            height: Height,
            targets: []const S.PublicKey,
        ) Allocator.Error!void {
            assert(targets.len > 0);
            const owned = try self.gpa.dupe(S.PublicKey, targets);
            _ = try self.enqueue(.{ .hint_finalized = .{ .height = height, .targets = owned } });
        }

        /// Subscribes to a block by digest. Deinit the receiver to cancel. Delivery makes no
        /// durability promise.
        pub fn subscribe_by_digest(
            self: Self,
            digest: M.Digest,
            fallback: DigestFallback,
        ) Allocator.Error!oneshot.Receiver(MarshalBlock) {
            var pair = try oneshot.channel(MarshalBlock, self.gpa, self.io);
            errdefer pair.receiver.deinit();
            _ = try self.enqueue(.{ .subscribe_by_digest = .{
                .digest = digest,
                .fallback = fallback,
                .response = pair.sender,
            } });
            return pair.receiver;
        }

        /// Subscribes to a block by commitment. Deinit the receiver to cancel. Delivery makes
        /// no durability promise.
        pub fn subscribe_by_commitment(
            self: Self,
            commitment: V.Commitment,
            fallback: CommitmentFallback,
        ) Allocator.Error!oneshot.Receiver(MarshalBlock) {
            var pair = try oneshot.channel(MarshalBlock, self.gpa, self.io);
            errdefer pair.receiver.deinit();
            _ = try self.enqueue(.{ .subscribe_by_commitment = .{
                .commitment = commitment,
                .fallback = fallback,
                .response = pair.sender,
            } });
            return pair.receiver;
        }

        /// Hints that peers hold the block notarized at `round`, without a new subscriber;
        /// skipped when `commitment` is already local.
        pub fn hint_notarized(
            self: Self,
            round: Round,
            commitment: V.Commitment,
        ) Allocator.Error!void {
            _ = try self.enqueue(.{ .hint_notarized = .{
                .round = round,
                .commitment = commitment,
            } });
        }

        /// Broadcasts a locally proposed block, then persists it; `ack` fires once durable
        /// and is dropped (closed) if the mailbox is.
        pub fn proposed(
            self: Self,
            round: Round,
            block: MarshalBlock,
            recipients: M.Recipients,
            ack: oneshot.Sender(void),
        ) Allocator.Error!Feedback {
            return self.enqueue(.{ .proposed = .{
                .round = round,
                .block = block,
                .recipients = recipients,
                .ack = ack,
            } });
        }

        /// Broadcasts a held term-start candidate without persisting it.
        pub fn prepared(
            self: Self,
            round: Round,
            block: MarshalBlock,
            recipients: M.Recipients,
        ) Allocator.Error!Feedback {
            return self.enqueue(.{ .prepared = .{
                .round = round,
                .block = block,
                .recipients = recipients,
            } });
        }

        /// Persists a block at `round`, firing `ack` once durable without waiting for it.
        pub fn verified_deferred(
            self: Self,
            round: Round,
            block: MarshalBlock,
            ack: oneshot.Sender(void),
        ) Allocator.Error!void {
            _ = try self.enqueue(.{ .verified = .{ .round = round, .block = block, .ack = ack } });
        }

        /// Notifies the actor that a block reached the verify stage; returns once it is
        /// durable, or false if the actor is gone.
        pub fn verified(self: Self, round: Round, block: MarshalBlock) Error!bool {
            var pair = oneshot.channel(void, self.gpa, self.io) catch |err| {
                var owned = block;
                V.deinit_block(self.gpa, &owned);
                return err;
            };
            defer pair.receiver.deinit();
            try self.verified_deferred(round, block, pair.sender);
            return durable(&pair.receiver);
        }

        /// Notifies the actor that a block reached the certify stage; returns once it is
        /// durable, or false if the actor is gone.
        pub fn certified(self: Self, round: Round, block: MarshalBlock) Error!bool {
            var pair = oneshot.channel(void, self.gpa, self.io) catch |err| {
                var owned = block;
                V.deinit_block(self.gpa, &owned);
                return err;
            };
            defer pair.receiver.deinit();
            _ = try self.enqueue(.{ .certified = .{
                .round = round,
                .block = block,
                .ack = pair.sender,
            } });
            return durable(&pair.receiver);
        }

        fn durable(receiver: *oneshot.Receiver(void)) Io.Cancelable!bool {
            receiver.recv() catch |err| switch (err) {
                error.Closed => return false,
                error.Canceled => return error.Canceled,
            };
            return true;
        }

        /// Proposes a sync floor. Callers must hold recoverable application state through the
        /// height before it. Use `prune` to drop data without moving the starting point.
        pub fn set_floor(self: Self, finalization: M.Finalization) Allocator.Error!void {
            _ = try self.enqueue(.{ .set_floor = finalization });
        }

        /// Prunes finalized blocks and certificates below `height` (requests above the
        /// processed height are ignored).
        pub fn prune(self: Self, height: Height) Allocator.Error!void {
            _ = try self.enqueue(.{ .prune = height });
        }

        /// Forwards a locally stored block to `recipients`.
        pub fn forward(
            self: Self,
            round: Round,
            commitment: V.Commitment,
            recipients: M.Recipients,
        ) Allocator.Error!Feedback {
            return self.enqueue(.{ .forward = .{
                .round = round,
                .commitment = commitment,
                .recipients = recipients,
            } });
        }

        /// The application's blocks this mailbox provides ancestry for (`BlockProvider`).
        pub const Block = V.ApplicationBlock;
        pub const Shared = broadcast.Digested(V.ApplicationBlock);

        /// The parent of `child` (commonware `BlockProvider::subscribe_parent`), through the
        /// variant's `subscribe_parent(mailbox, child)`: the receiver closes without a value
        /// once marshal can no longer obtain it, or at once for genesis.
        pub fn subscribe_parent(
            self: *const Self,
            child: *const Shared,
        ) Allocator.Error!oneshot.Receiver(Shared) {
            return V.subscribe_parent(self.*, child);
        }

        /// A fetching ancestor stream from `initial` (owned, any order, contiguous), with its
        /// own clone of the mailbox. Callers must already hold a block that is safe to verify,
        /// certify, build on, or repair from; this is not a candidate fetch path.
        pub fn ancestor_stream(
            self: Self,
            initial: []const Shared,
            fetch_duration: ?*const Timed,
        ) Allocator.Error!ancestry.AncestorStream(Self) {
            var provider = self.clone();
            errdefer provider.deinit();
            return .init(self.gpa, self.io, provider, initial, fetch_duration);
        }

        /// The ancestry of the block `start`, leading to genesis, or null when the block
        /// never arrives (commonware `ancestry`).
        pub fn ancestry_from(
            self: Self,
            fallback: DigestFallback,
            start: M.Digest,
            fetch_duration: ?*const Timed,
        ) Error!?ancestry.AncestorStream(Self) {
            var receiver = try self.subscribe_by_digest(start, fallback);
            defer receiver.deinit();
            const block = receiver.recv() catch |err| switch (err) {
                error.Closed => return null,
                error.Canceled => return error.Canceled,
            };
            var shared = V.into_shared(block);
            errdefer shared.deinit();
            return try self.ancestor_stream(&.{shared}, fetch_duration);
        }

        /// The consensus `Reporter`: forwards notarizations, certifications, and finalizations
        /// (borrowed; the mailbox sends a copy) and ignores the rest.
        pub fn report(self: *Self, activity: Activity) Feedback {
            const body: M.Body = switch (activity) {
                .notarization => |*value| .{ .notarization = self.clone_certificate(value) },
                .certification => |*value| .{ .certification = self.clone_certificate(value) },
                .finalization => |*value| .{ .finalization = self.clone_certificate(value) },
                else => return .ok,
            };
            // Rust aborts on allocation failure; a reporter cannot return it.
            return self.enqueue(body) catch @panic("out of memory");
        }

        fn clone_certificate(self: *const Self, certificate: anytype) @TypeOf(certificate.*) {
            return certificate.clone(self.gpa) catch @panic("out of memory");
        }
    };
}

test {
    _ = @import("mailbox_test.zig");
}
