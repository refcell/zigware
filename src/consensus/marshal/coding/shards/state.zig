//! The reconstruction state of one commitment (commonware `ReconstructionState` in
//! `marshal/coding/shards/engine.rs`).
//!
//! While awaiting quorum, the state keeps the raw shard received at each index (for
//! equivocation detection), the shards checked so far, and the gossip shards pending batch
//! verification (by sender). Checked shards borrow their bytes from the received shards, so
//! both live until the state is dropped or turns ready. Once the block is cached the state is
//! ready: it keeps no shards and only verifies a late assigned shard.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const p2p = @import("p2p");

const types = @import("../types.zig");

const SortedMap = p2p.simulated.sorted_map.SortedMap;

/// Frees a coding shard owning its bytes and proof.
pub fn free_inner(gpa: Allocator, inner: anytype) void {
    gpa.free(inner.shard);
    inner.deinit(gpa);
}

pub fn State(comptime P: type, comptime B: type, comptime C: type, comptime H: type) type {
    return struct {
        const Self = @This();
        pub const ShardType = types.Shard(B, C, H);
        pub const Commitment = ShardType.Commitment;

        /// A checked shard and the encoded size of the shard it was checked from.
        pub const Sized = struct { shard: C.CheckedShard, size: usize };

        /// Shards accumulated while awaiting quorum.
        pub const Quorum = struct {
            /// The raw shard received at each index (owned).
            received: SortedMap(u16, C.Shard) = .empty,
            /// Shards verified and ready to decode (bytes borrowed from `received`).
            checked: std.ArrayList(Sized) = .empty,
            /// The index of each sender's shard pending batch verification.
            pending: SortedMap(P, u16) = .empty,
            /// Whether a reconstruction job is in flight (commonware `job`). The job owns the
            /// checked shards and the pending shards it took; it borrows their bytes from
            /// `received`, so a discarded job keeps this quorum alive until it ends.
            job: bool = false,

            pub fn deinit(quorum: *Quorum, gpa: Allocator) void {
                for (quorum.received.items()) |*entry| free_inner(gpa, &entry.value);
                quorum.received.deinit(gpa);
                quorum.checked.deinit(gpa);
                quorum.pending.deinit(gpa);
                quorum.* = undefined;
            }
        };

        /// Whether the shard at the local participant's index was verified.
        assigned_verified: bool = false,
        /// The verified assigned shard, until it is relayed to peers.
        pending_relay: ?ShardType = null,
        /// Null once ready (the block is cached).
        quorum: ?Quorum = .{},

        pub fn deinit(state: *Self, gpa: Allocator) void {
            if (state.pending_relay) |*shard| shard.deinit(gpa);
            if (state.quorum) |*quorum| quorum.deinit(gpa);
            state.* = undefined;
        }

        /// Ends shard accumulation once the block is cached, dropping every shard.
        pub fn into_ready(state: *Self, gpa: Allocator) void {
            if (state.quorum) |*quorum| quorum.deinit(gpa);
            state.quorum = null;
            assert(state.quorum == null);
        }

        /// Takes the verified assigned shard to relay it; null if not verified or taken.
        pub fn take_pending_relay(state: *Self) ?ShardType {
            const shard = state.pending_relay orelse return null;
            state.pending_relay = null;
            assert(state.assigned_verified);
            return shard;
        }

        /// Handles a shard (owned) from `sender`; true when it made progress (buffered or
        /// verified). Blocks a sender that is not a participant, sends a shard at an index
        /// that is neither the local participant's nor its own, equivocates while awaiting
        /// quorum, or sends an assigned shard that fails verification. Exact duplicates while
        /// awaiting quorum, and gossip shards once ready, are ignored.
        pub fn on_network_shard(
            state: *Self,
            gpa: Allocator,
            sender: P,
            shard: ShardType,
            scheme: anytype,
            blocker: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            var owned = shard;
            const participant = scheme.participants().index(sender) orelse {
                owned.deinit(gpa);
                _ = blocker.block(sender); // shard sent by non-participant
                return false;
            };
            const sender_index: u16 = @intCast(participant.get());
            const assigned_index: ?u16 = if (scheme.me()) |me| @intCast(me.index().get()) else null;
            const is_assigned = assigned_index == owned.index;
            const is_gossip = owned.index == sender_index;
            if (!is_assigned and !is_gossip) {
                owned.deinit(gpa);
                _ = blocker.block(sender); // neither assigned nor sender-owned
                return false;
            }
            if (state.quorum) |*quorum| {
                if (quorum.received.get(owned.index)) |existing| {
                    if (!existing.eql(&owned.inner)) _ = blocker.block(sender); // equivocation
                    owned.deinit(gpa);
                    return false;
                }
            }
            // The assigned shard is verified eagerly, even once ready, so it is relayed to
            // help slower peers reach quorum.
            if (is_assigned and !state.assigned_verified) {
                return state.verify_assigned(gpa, sender, owned, blocker, strategy);
            }
            const quorum = if (state.quorum) |*value| value else {
                owned.deinit(gpa);
                return false;
            };
            errdefer owned.deinit(gpa);
            try quorum.received.ensure_unused_capacity(gpa, 1);
            try quorum.pending.ensure_unused_capacity(gpa, 1);
            assert(try quorum.received.put(gpa, owned.index, owned.inner) == null);
            _ = try quorum.pending.put(gpa, sender, owned.index);
            return true;
        }

        /// Verifies the assigned shard (owned) and keeps it to relay; while awaiting quorum it
        /// also counts toward reconstruction. Blocks `sender` if it fails verification.
        fn verify_assigned(
            state: *Self,
            gpa: Allocator,
            sender: P,
            shard: ShardType,
            blocker: anytype,
            strategy: anytype,
        ) Allocator.Error!bool {
            var owned = shard;
            const commitment = owned.commitment();
            const root = commitment.root();
            const config = commitment.config();
            const checked = C.check(config, &root, owned.index, &owned.inner, strategy) catch {
                owned.deinit(gpa);
                _ = blocker.block(sender); // invalid assigned shard
                return false;
            };
            errdefer owned.deinit(gpa);
            if (state.quorum) |*quorum| {
                try quorum.checked.ensureUnusedCapacity(gpa, 1);
                try quorum.received.ensure_unused_capacity(gpa, 1);
            }
            const relay = try owned.clone(gpa);
            state.assigned_verified = true;
            assert(state.pending_relay == null);
            state.pending_relay = relay;
            const quorum = if (state.quorum) |*value| value else {
                owned.deinit(gpa);
                return true;
            };
            const size = owned.inner.encode_size();
            // The checked shard borrows the bytes the received map now owns.
            assert(try quorum.received.put(gpa, owned.index, owned.inner) == null);
            quorum.checked.appendAssumeCapacity(.{ .shard = checked, .size = size });
            return true;
        }
    };
}
