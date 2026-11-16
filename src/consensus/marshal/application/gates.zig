//! Certification gates and staged proposals shared by marshal's application wrappers
//! (commonware `marshal/application/gates.rs`).
//!
//! A gate is the receiver of an in-flight certification task's outcome, keyed by
//! `(round, digest)`. A staged proposal holds a block until consensus locks it in with a propose
//! broadcast, or certification demands durability first. `Gates` is a shared handle (`clone`,
//! `deinit`; commonware's `Arc<Mutex<..>>`) whose entries are ordered by round, so pruning
//! releases them, and wakes the tasks parked on them, in a deterministic order.
//!
//! Commonware's staged ack carries a durable-sync handle; marshal's Zig caches are durable when
//! a put returns, so the ack is `oneshot.Sender(void)`, sent once the block is persisted. A
//! dropped ack means the block was never persisted.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const types = @import("../../types.zig");

const Round = types.Round;
const oneshot = utils.channel.oneshot;

/// The outcome of an in-flight certification gate.
pub const GateOutcome = union(enum) {
    /// A verdict that applies to the notarized proposal.
    ready: bool,
    /// The gate's result does not apply to the notarized proposal: certification must use its
    /// recovery path.
    recover,
};

/// Sent once marshal persists a staged block.
pub const Ack = oneshot.Sender(void);
/// The receiver of a certification gate task.
pub const Gate = oneshot.Receiver(GateOutcome);

/// A proposal staged for its relay broadcast.
pub fn Staged(comptime B: type) type {
    return struct {
        /// The block, shared with the relay send and the eventual persist.
        block: B,
        /// Sent once marshal persists the block.
        ack: Ack,
    };
}

/// The gates and staged proposals of blocks `V.Block` keyed by `(round, D)`. `V` provides
/// `clone_block(*const Block) Block` and `deinit_block(gpa, *Block)`.
pub fn Gates(comptime D: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Block = V.Block;

        const Key = struct {
            round: Round,
            digest: D,

            fn order(a: Key, b: Key) std.math.Order {
                const by_round = a.round.order(b.round);
                if (by_round != .eq) return by_round;
                return utils.ordered.order(D, a.digest, b.digest);
            }
        };
        const GateEntry = struct { key: Key, gate: Gate };
        const ProposalEntry = struct { key: Key, staged: Staged(Block) };
        const SentEntry = struct { key: Key };

        const Shared = struct {
            gpa: Allocator,
            io: Io,
            mutex: Io.Mutex = .init,
            references: std.atomic.Value(u32) = .init(1),
            /// In-flight certification gates, consumed by certification.
            certifications: std.ArrayList(GateEntry) = .empty,
            /// Proposals staged for their relay broadcast, consumed by the lock-in broadcast
            /// (or by certification when it arrives first).
            proposals: std.ArrayList(ProposalEntry) = .empty,
            /// Proposals that must not be sent again. A sent proposal stays marked after its
            /// staged entry is taken, so a block staged again for its round is not resent.
            sent: std.ArrayList(SentEntry) = .empty,
            /// The highest round used to prune. A block staged at or below it is marked sent,
            /// so a late build cannot send it twice after pruning dropped its mark.
            decided: ?Round = null,

            fn lock(shared: *Shared) void {
                shared.mutex.lockUncancelable(shared.io);
            }

            fn unlock(shared: *Shared) void {
                shared.mutex.unlock(shared.io);
            }
        };

        shared: *Shared,

        pub fn init(gpa: Allocator, io: Io) Allocator.Error!Self {
            const shared = try gpa.create(Shared);
            shared.* = .{ .gpa = gpa, .io = io };
            return .{ .shared = shared };
        }

        /// Another handle to the same registry.
        pub fn clone(self: Self) Self {
            const previous = self.shared.references.fetchAdd(1, .monotonic);
            assert(previous > 0 and previous < std.math.maxInt(u32));
            return self;
        }

        /// Drops this handle; the last one releases every gate, staged block, and ack.
        pub fn deinit(self: *Self) void {
            const shared = self.shared;
            self.* = undefined;
            const previous = shared.references.fetchSub(1, .acq_rel);
            assert(previous > 0);
            if (previous > 1) return;
            for (shared.certifications.items) |*entry| entry.gate.deinit();
            for (shared.proposals.items) |*entry| release_staged(shared.gpa, &entry.staged);
            shared.certifications.deinit(shared.gpa);
            shared.proposals.deinit(shared.gpa);
            shared.sent.deinit(shared.gpa);
            shared.gpa.destroy(shared);
        }

        fn release_staged(gpa: Allocator, staged: *Staged(Block)) void {
            V.deinit_block(gpa, &staged.block);
            staged.ack.deinit();
        }

        /// The index of the first entry not below `key` in `entries`, and whether it is `key`.
        fn search(entries: anytype, key: Key) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = entries.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (Key.order(entries[middle].key, key)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return .{ middle, true },
                }
            }
            return .{ low, false };
        }

        /// The number of entries in the round-ordered `entries` at or below `round`.
        fn count_through(entries: anytype, round: Round) usize {
            var count: usize = 0;
            for (entries) |entry| {
                if (entry.key.round.order(round) == .gt) break;
                count += 1;
            }
            return count;
        }

        /// Inserts or replaces the gate at `key`; capacity is reserved.
        fn put_gate(shared: *Shared, key: Key, gate: Gate) void {
            const index, const found = search(shared.certifications.items, key);
            if (found) {
                shared.certifications.items[index].gate.deinit();
                shared.certifications.items[index].gate = gate;
                return;
            }
            assert(shared.certifications.unusedCapacitySlice().len > 0);
            shared.certifications.insertAssumeCapacity(index, .{ .key = key, .gate = gate });
        }

        /// Marks `key` sent and returns whether it already was; capacity is reserved.
        fn mark_sent(shared: *Shared, key: Key) bool {
            const index, const found = search(shared.sent.items, key);
            if (found) return true;
            assert(shared.sent.unusedCapacitySlice().len > 0);
            shared.sent.insertAssumeCapacity(index, .{ .key = key });
            return false;
        }

        /// Registers the certification gate task for `(round, digest)`, replacing any earlier
        /// one. On error the caller keeps `gate`.
        pub fn insert(self: Self, round: Round, digest: D, gate: Gate) Allocator.Error!void {
            const shared = self.shared;
            shared.lock();
            defer shared.unlock();
            try shared.certifications.ensureUnusedCapacity(shared.gpa, 1);
            put_gate(shared, .{ .round = round, .digest = digest }, gate);
        }

        /// Removes and returns the gate for `(round, digest)`, if present.
        pub fn take(self: Self, round: Round, digest: D) ?Gate {
            const shared = self.shared;
            shared.lock();
            defer shared.unlock();
            const index, const found = search(shared.certifications.items, .{
                .round = round,
                .digest = digest,
            });
            if (!found) return null;
            return shared.certifications.orderedRemove(index).gate;
        }

        /// Removes and returns the staged proposal for `(round, digest)`, if present, and
        /// whether it must not be sent (already sent, or staged at or below the decided
        /// cutoff). The block and ack go to marshal exactly once: through the lock-in
        /// broadcast, or certification if it arrives first. A taken proposal counts as sent.
        pub fn take_staged(
            self: Self,
            round: Round,
            digest: D,
        ) Allocator.Error!?struct { Staged(Block), bool } {
            const shared = self.shared;
            const key: Key = .{ .round = round, .digest = digest };
            shared.lock();
            defer shared.unlock();
            const index, const found = search(shared.proposals.items, key);
            if (!found) return null;
            try shared.sent.ensureUnusedCapacity(shared.gpa, 1);
            const staged = shared.proposals.orderedRemove(index).staged;
            return .{ staged, mark_sent(shared, key) };
        }

        /// The staged proposal for `(round, digest)` (a new reference) for a send that does
        /// not persist it, marking it sent so the lock-in broadcast only persists it. Null when
        /// nothing is staged or it must not be sent, so each block goes out once per round.
        /// The entry stays staged: a held candidate may still be abandoned.
        pub fn send_staged(self: Self, round: Round, digest: D) Allocator.Error!?Block {
            const shared = self.shared;
            const key: Key = .{ .round = round, .digest = digest };
            shared.lock();
            defer shared.unlock();
            const index, const found = search(shared.proposals.items, key);
            if (!found) return null;
            try shared.sent.ensureUnusedCapacity(shared.gpa, 1);
            if (mark_sent(shared, key)) return null;
            return V.clone_block(&shared.proposals.items[index].staged.block);
        }

        /// Removes and returns the gate for `(round, digest)`, if present, and hands the staged
        /// proposal it waits on to `persist.call(block, ack)` (taking both) without
        /// broadcasting it. Both are removed under one lock, so a concurrent stage of the same
        /// block cannot leave the returned gate waiting on an ack nothing persists. Consensus
        /// certifies one block per round, so the round's other gates are dropped, which closes
        /// their senders and lets the tasks behind them stop.
        pub fn claim(self: Self, round: Round, digest: D, persist: anytype) ?Gate {
            const shared = self.shared;
            const key: Key = .{ .round = round, .digest = digest };
            shared.lock();
            var gate: ?Gate = null;
            var staged: ?Staged(Block) = null;
            const proposal_index, const proposal_found = search(shared.proposals.items, key);
            if (proposal_found) staged = shared.proposals.orderedRemove(proposal_index).staged;
            var kept: usize = 0;
            for (shared.certifications.items) |*entry| {
                if (entry.key.round.order(round) != .eq) {
                    shared.certifications.items[kept] = entry.*;
                    kept += 1;
                } else if (Key.order(entry.key, key) == .eq) {
                    gate = entry.gate;
                } else {
                    entry.gate.deinit();
                }
            }
            shared.certifications.shrinkRetainingCapacity(kept);
            shared.unlock();
            if (staged) |claimed| persist.call(claimed.block, claimed.ack);
            return gate;
        }

        /// Discards every entry and sent mark at or before `finalized_round`, and raises the
        /// decided cutoff to it. A discarded staged proposal drops its ack, which abandons the
        /// propose handshake for that decided round.
        pub fn retain_after(self: Self, finalized_round: Round) void {
            const shared = self.shared;
            shared.lock();
            defer shared.unlock();
            const decided = shared.decided orelse finalized_round;
            const raised = decided.order(finalized_round) == .lt;
            shared.decided = if (raised) finalized_round else decided;
            const gates = count_through(shared.certifications.items, finalized_round);
            for (shared.certifications.items[0..gates]) |*entry| entry.gate.deinit();
            remove_prefix(GateEntry, &shared.certifications, gates);
            const proposals = count_through(shared.proposals.items, finalized_round);
            for (shared.proposals.items[0..proposals]) |*entry| {
                release_staged(shared.gpa, &entry.staged);
            }
            remove_prefix(ProposalEntry, &shared.proposals, proposals);
            const sent = count_through(shared.sent.items, finalized_round);
            remove_prefix(SentEntry, &shared.sent, sent);
        }

        fn remove_prefix(comptime E: type, list: *std.ArrayList(E), count: usize) void {
            const all = list.items;
            std.mem.copyForwards(E, all[0 .. all.len - count], all[count..]);
            list.shrinkRetainingCapacity(all.len - count);
        }

        /// The number of sent marks (for tests).
        pub fn sent_count(self: Self) usize {
            const shared = self.shared;
            shared.lock();
            defer shared.unlock();
            return shared.sent.items.len;
        }

        /// Stages `block` (taking it) for its relay broadcast and completes the propose
        /// durability handshake for `(round, digest)`.
        ///
        /// Registers a gate and the staged block, then publishes `digest` through
        /// `publish.call(digest)`, so the relay broadcast and certify always find them. Then
        /// waits until marshal persists the staged block (at the lock-in broadcast, or at
        /// certification if that comes first), which can outlive the round, and resolves the
        /// gate as ready. A dropped ack (marshal is gone, the entry was pruned, or the block
        /// was staged again) leaves the gate unresolved, so certify falls back to recovery.
        pub fn stage(
            self: Self,
            round: Round,
            digest: D,
            block: Block,
            publish: anytype,
            name: []const u8,
        ) !void {
            _ = name;
            var waiting = try self.register_staged(.{ .round = round, .digest = digest }, block);
            defer waiting.ack.deinit();
            publish.call(digest);
            waiting.ack.recv() catch |err| {
                waiting.durable.deinit();
                return switch (err) {
                    error.Closed => {},
                    error.Canceled => error.Canceled,
                };
            };
            // A gate whose certification gave up refuses the outcome.
            waiting.durable.send(.{ .ready = true }) catch {};
        }

        /// Stages `block` (taking it, also on error) with a new gate at `key`, returning the
        /// gate's sender and the staged ack's receiver.
        fn register_staged(self: Self, key: Key, block: Block) !struct {
            durable: oneshot.Sender(GateOutcome),
            ack: oneshot.Receiver(void),
        } {
            const shared = self.shared;
            var owned = block;
            errdefer V.deinit_block(shared.gpa, &owned);
            var durable = try oneshot.channel(GateOutcome, shared.gpa, shared.io);
            errdefer durable.sender.deinit();
            errdefer durable.receiver.deinit();
            var ack = try oneshot.channel(void, shared.gpa, shared.io);
            errdefer ack.sender.deinit();
            errdefer ack.receiver.deinit();
            try self.register(key, durable.receiver, .{ .block = owned, .ack = ack.sender });
            return .{ .durable = durable.sender, .ack = ack.receiver };
        }

        /// Registers `gate` and `staged` at `key` under one lock; on error the caller keeps
        /// both.
        fn register(self: Self, key: Key, gate: Gate, staged: Staged(Block)) !void {
            const shared = self.shared;
            shared.lock();
            defer shared.unlock();
            try shared.certifications.ensureUnusedCapacity(shared.gpa, 1);
            try shared.proposals.ensureUnusedCapacity(shared.gpa, 1);
            try shared.sent.ensureUnusedCapacity(shared.gpa, 1);
            put_gate(shared, key, gate);
            if (shared.decided) |decided| {
                if (key.round.order(decided) != .gt) _ = mark_sent(shared, key);
            }
            const index, const found = search(shared.proposals.items, key);
            if (found) {
                release_staged(shared.gpa, &shared.proposals.items[index].staged);
                shared.proposals.items[index].staged = staged;
                return;
            }
            shared.proposals.insertAssumeCapacity(index, .{ .key = key, .staged = staged });
        }
    };
}

/// Resolves a deferred verification's gate from `verdict` (the application's, null when
/// verification stopped early) and whether the candidate store is `durable`. A false verdict
/// needs no durability; a true one does, so true-but-not-durable (marshal gone at shutdown)
/// leaves the gate unresolved (null).
pub fn resolve(verdict: ?bool, durable: bool) ?bool {
    const value = verdict orelse return null;
    if (value and !durable) return null;
    return value;
}

/// The result of `input` unless `output`'s receiver closes first (null).
fn recv_unless_closed(
    comptime T: type,
    comptime U: type,
    io: Io,
    output: *const oneshot.Sender(T),
    input: *oneshot.Receiver(U),
) Io.Cancelable!?(oneshot.RecvError!U) {
    const Outcome = union(enum) {
        closed: Io.Cancelable!void,
        received: oneshot.RecvError!U,
    };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    select.concurrent(.closed, oneshot.Sender(T).closed, .{output.*}) catch {
        return error.Canceled;
    };
    select.concurrent(.received, oneshot.Receiver(U).recv, .{input}) catch {
        select.cancelDiscard();
        return error.Canceled;
    };
    const first = try select.await();
    while (select.cancel()) |rest| {
        if (rest == .received) if (rest.received) |value| discard(U, value) else |_| {};
    }
    return switch (first) {
        .closed => null,
        .received => |result| result,
    };
}

fn discard(comptime U: type, value: U) void {
    if (comptime @typeInfo(U) == .@"struct" and @hasDecl(U, "discard")) U.discard(value);
}

/// Forwards `input` through `map.call(U) ?T` into `output` while `output` still has a
/// receiver; if it closes first, `input` is dropped, which cancels its operation. Takes both.
pub fn forward(
    comptime T: type,
    comptime U: type,
    io: Io,
    output: oneshot.Sender(T),
    input: oneshot.Receiver(U),
    map: anytype,
) Io.Cancelable!void {
    var sender = output;
    var receiver = input;
    defer receiver.deinit();
    const result = recv_unless_closed(T, U, io, &sender, &receiver) catch |err| {
        sender.deinit();
        return err;
    } orelse return sender.deinit();
    const value = result catch return sender.deinit();
    const mapped = map.call(value) orelse return sender.deinit();
    sender.send(mapped) catch {};
}

/// Drives the gate `task` to a certify verdict on `verdict` (taking both). A ready verdict is
/// published; `recover` or a dropped gate falls back to `fallback.call() !Receiver(bool)`,
/// whose verdict is published instead. A closed `verdict` receiver abandons the work.
pub fn drive(
    io: Io,
    verdict: oneshot.Sender(bool),
    task: Gate,
    fallback: anytype,
) !void {
    var sender = verdict;
    var gate = task;
    defer gate.deinit();
    errdefer sender.deinit();
    const outcome = try recv_unless_closed(bool, GateOutcome, io, &sender, &gate) orelse
        return sender.deinit();
    const ready: ?bool = if (outcome) |value| switch (value) {
        .ready => |result| result,
        .recover => null,
    } else |_| null;
    if (ready) |result| return sender.send(result) catch {};
    var recovery = try fallback.call();
    defer recovery.deinit();
    const result = try recv_unless_closed(bool, bool, io, &sender, &recovery) orelse
        return sender.deinit();
    const recovered = result catch return sender.deinit();
    sender.send(recovered) catch {};
}

test {
    _ = @import("gates_test.zig");
}
