//! The processor's speculative state (commonware `glue/src/stateful/actor/processor/mod.rs`:
//! `PendingEntry`, `ExecutionState`, `cache_pending`, `retain_branch`, `descendants`, and
//! `Processor::boundary`).
//!
//! Each unfinalized block with executed state has a pending entry: its round, its parent, and
//! its merkleized batches. The branch anchor is the applied tip (or a finalization in
//! progress, whose batches then also stay pending). An entry is cached only above the anchor's
//! round on the anchor or another cached block, so pending state always forms a tree rooted at
//! the anchor.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const sync = @import("../../db/sync.zig");
const pruning = @import("pruning.zig");

const Round = consensus.Round;

/// Speculative state keyed by block digest `D`, holding merkleized batches `B` (with
/// `clone() B` and `deinit()`, which the state owns).
pub fn Pending(comptime D: type, comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Anchor = sync.Anchor(D);
        pub const Entry = struct { round: Round, parent: D, merkleized: B };
        pub const Boundary = pruning.FinalizationBoundary(D);
        const Map = std.AutoArrayHashMapUnmanaged(D, Entry);
        const Set = std.AutoHashMapUnmanaged(D, void);

        gpa: Allocator,
        entries: Map = .empty,
        branch: Anchor,

        pub fn init(gpa: Allocator, anchor: Anchor) Self {
            return .{ .gpa = gpa, .branch = anchor };
        }

        pub fn deinit(self: *Self) void {
            for (self.entries.values()) |*entry| entry.merkleized.deinit();
            self.entries.deinit(self.gpa);
            self.* = undefined;
        }

        pub fn contains(self: *const Self, digest: D) bool {
            return self.entries.contains(digest);
        }

        pub fn get(self: *const Self, digest: D) ?*const Entry {
            return self.entries.getPtr(digest);
        }

        /// Pending entries other than the branch anchor's own (the pending-blocks gauge).
        pub fn speculative_len(self: *const Self) usize {
            const anchored: usize = @intFromBool(self.entries.contains(self.branch.digest));
            assert(self.entries.count() >= anchored);
            return self.entries.count() - anchored;
        }

        /// Caches `entry` (taking it) as `digest`'s state and returns whether `digest` is
        /// cached. An existing entry keeps its state; a new one is cached only above the
        /// anchor's round on the anchor or a cached parent. A cached digest whose parent or
        /// round differs is an invariant violation (commonware panics).
        pub fn cache(self: *Self, digest: D, entry: Entry) Allocator.Error!bool {
            var owned = entry;
            if (self.entries.getPtr(digest)) |existing| {
                assert(std.meta.eql(existing.parent, owned.parent));
                assert(existing.round.order(owned.round) == .eq);
                owned.merkleized.deinit();
                return true;
            }
            const later = owned.round.order(self.branch.round) == .gt;
            const linked = std.meta.eql(owned.parent, self.branch.digest) or
                self.entries.contains(owned.parent);
            if (!later or !linked) {
                owned.merkleized.deinit();
                return false;
            }
            self.entries.put(self.gpa, digest, owned) catch |err| {
                owned.merkleized.deinit();
                return err;
            };
            return true;
        }

        /// `digest` and its pending descendants in rounds after `round`, into `out` (cleared
        /// first). Walks the tree breadth first with an explicit queue.
        pub fn descendants(self: *const Self, digest: D, round: Round, out: *Set) !void {
            out.clearRetainingCapacity();
            try out.put(self.gpa, digest, {});
            var queue: std.ArrayList(D) = .empty;
            defer queue.deinit(self.gpa);
            try queue.append(self.gpa, digest);
            var head: usize = 0;
            // Each pass over the entries visits one parent; at most every entry is queued once.
            while (head < queue.items.len) : (head += 1) {
                assert(queue.items.len <= self.entries.count() + 1);
                const parent = queue.items[head];
                for (self.entries.keys(), self.entries.values()) |child, entry| {
                    if (entry.round.order(round) != .gt) continue;
                    if (!std.meta.eql(entry.parent, parent)) continue;
                    const result = try out.getOrPut(self.gpa, child);
                    if (result.found_existing) continue;
                    try queue.append(self.gpa, child);
                }
            }
            assert(out.contains(digest));
        }

        /// The cached state that stays valid once the block `digest` at `round` is finalized.
        pub fn boundary(self: *const Self, digest: D, round: Round) !Boundary {
            var result: Boundary = .{ .digest = digest, .round = round };
            errdefer result.deinit(self.gpa);
            try self.descendants(digest, round, &result.compatible);
            return result;
        }

        /// Caches a copy of `batch` as `anchor`'s state (unless cached), discards cached state
        /// that does not descend from `anchor`, and makes `anchor` the branch anchor. Returns
        /// how many forks it pruned. The caller keeps `batch`.
        pub fn retain_branch(self: *Self, anchor: Anchor, parent: D, batch: *const B) !u64 {
            var compatible: Set = .empty;
            defer compatible.deinit(self.gpa);
            try self.descendants(anchor.digest, anchor.round, &compatible);
            if (!self.entries.contains(anchor.digest)) {
                const entry: Entry = .{
                    .round = anchor.round,
                    .parent = parent,
                    .merkleized = batch.clone(),
                };
                self.entries.put(self.gpa, anchor.digest, entry) catch |err| {
                    var dropped = entry.merkleized;
                    dropped.deinit();
                    return err;
                };
            }
            var pruned: u64 = 0;
            var index: usize = 0;
            while (index < self.entries.count()) {
                const digest = self.entries.keys()[index];
                if (compatible.contains(digest)) {
                    index += 1;
                    continue;
                }
                self.entries.values()[index].merkleized.deinit();
                self.entries.swapRemoveAt(index);
                pruned += 1;
            }
            self.branch = anchor;
            assert(self.entries.contains(anchor.digest));
            return pruned;
        }

        /// Discards every pending entry (a restart of speculative state).
        pub fn clear(self: *Self) void {
            for (self.entries.values()) |*entry| entry.merkleized.deinit();
            self.entries.clearRetainingCapacity();
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("pending_test.zig");
}
