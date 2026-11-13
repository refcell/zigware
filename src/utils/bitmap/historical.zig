//! `historical.BitMap(N)`: a `Prunable(N)` bitmap that keeps every committed state as a
//! reverse diff (commonware `utils/src/bitmap/historical`).
//!
//! One full bitmap holds the current state; each commit stores the chunks it changed as they
//! were before the commit, so `get_at_commit` rebuilds an old state by undoing commits from the
//! newest down. Mutations go through a `Dirty` view (`into_dirty`), which records them without
//! touching the current bitmap: reads see them (read-through), `commit` applies them and stores
//! the reverse diff, and `abort` drops them. Rust's type states become two types: a clean
//! `BitMap` and its `Dirty`. Unlike Rust, a failed `commit` leaves the `Dirty` unchanged, so
//! the caller can `abort` it and keep the bitmap.

const std = @import("std");
const Prunable = @import("prunable.zig").Prunable;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Error = error{
    /// The commit number is not greater than the latest commit.
    NonMonotonicCommit,
    /// `maxInt(u64)` is reserved and cannot be a commit number.
    ReservedCommitNumber,
    /// `pruned_chunks * CHUNK_SIZE_BITS` overflows `u64`.
    PrunedChunksOverflow,
};

pub fn BitMap(comptime N: usize) type {
    return struct {
        /// The current (head) state, the only full bitmap.
        current: Bits = .empty,
        /// Reverse diffs in increasing commit order.
        history: std.ArrayList(Commit) = .empty,

        const Self = @This();
        const Bits = Prunable(N);
        const chunk_bits = Bits.CHUNK_SIZE_BITS;

        pub const Chunk = Bits.Chunk;

        /// A chunk's state before a commit.
        pub const ChunkDiff = union(enum) {
            /// Modified by the commit (old value).
            modified: Chunk,
            /// Removed from the end by the commit (old value).
            removed: Chunk,
            /// Added by the commit (it did not exist).
            added,
            /// Pruned by the commit (old value).
            pruned: Chunk,
        };

        pub const DiffEntry = struct { index: usize, diff: ChunkDiff };

        /// The state before a commit: its length, pruned chunks, and changed chunks in
        /// increasing chunk order.
        pub const CommitDiff = struct {
            len: u64,
            pruned_chunks: usize,
            chunk_diffs: []DiffEntry,
        };

        const Commit = struct { number: u64, diff: CommitDiff };

        pub const empty: Self = .{};

        pub fn init_pruned(pruned_chunks_count: usize) Error!Self {
            return .{ .current = try Bits.init_pruned(pruned_chunks_count) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.current.deinit(gpa);
            for (self.history.items) |entry| gpa.free(entry.diff.chunk_diffs);
            self.history.deinit(gpa);
            self.* = undefined;
        }

        /// Starts recording mutations. The returned `Dirty` owns the bitmap until `commit` or
        /// `abort` hands it back.
        pub fn into_dirty(self: Self) Dirty {
            return .{
                .clean = self,
                .base_len = self.current.len(),
                .base_pruned = self.current.pruned_chunks(),
                .projected_len = self.current.len(),
                .projected_pruned = self.current.pruned_chunks(),
            };
        }

        /// Runs `batch(context, *Dirty)` (returning `void` or an error union) and commits it as
        /// `commit_number`. On any error the bitmap is unchanged.
        pub fn apply_batch(
            self: *Self,
            gpa: Allocator,
            commit_number: u64,
            context: anytype,
            comptime batch: anytype,
        ) !void {
            var dirty = self.into_dirty();
            errdefer self.* = dirty.abort(gpa);
            const result = batch(context, &dirty);
            if (comptime @typeInfo(@TypeOf(result)) == .error_union) try result;
            self.* = try dirty.commit(gpa, commit_number);
        }

        /// The bitmap as it was right after `commit_number`, or null when that commit does not
        /// exist (or was pruned). The caller owns the result.
        pub fn get_at_commit(
            self: *const Self,
            gpa: Allocator,
            commit_number: u64,
        ) Allocator.Error!?Bits {
            if (commit_number == std.math.maxInt(u64)) return null;
            const position = self.find_commit(commit_number) orelse return null;
            var state = try self.current.clone(gpa);
            errdefer state.deinit(gpa);
            var index = self.history.items.len;
            while (index > position + 1) {
                index -= 1;
                try apply_reverse_diff(gpa, &state, self.history.items[index].diff);
            }
            assert(state.pruned_chunks() <= self.current.pruned_chunks());
            return state;
        }

        fn find_commit(self: *const Self, commit_number: u64) ?usize {
            var low: usize = 0;
            var high: usize = self.history.items.len;
            // Each pass halves `high - low`: at most 64 passes.
            while (low < high) {
                const middle = low + (high - low) / 2;
                const number = self.history.items[middle].number;
                if (number == commit_number) return middle;
                if (number < commit_number) low = middle + 1 else high = middle;
            }
            return null;
        }

        pub fn commit_exists(self: *const Self, commit_number: u64) bool {
            return self.find_commit(commit_number) != null;
        }

        /// Commit numbers in increasing order.
        pub const CommitIterator = struct {
            entries: []const Commit,
            position: usize = 0,

            pub fn next(it: *CommitIterator) ?u64 {
                if (it.position == it.entries.len) return null;
                it.position += 1;
                return it.entries[it.position - 1].number;
            }
        };

        pub fn commits(self: *const Self) CommitIterator {
            return .{ .entries = self.history.items };
        }

        pub fn commit_count(self: *const Self) usize {
            return self.history.items.len;
        }

        pub fn latest_commit(self: *const Self) ?u64 {
            const last = self.history.getLastOrNull() orelse return null;
            return last.number;
        }

        pub fn earliest_commit(self: *const Self) ?u64 {
            if (self.history.items.len == 0) return null;
            return self.history.items[0].number;
        }

        pub fn len(self: *const Self) u64 {
            return self.current.len();
        }

        pub fn is_empty(self: *const Self) bool {
            return self.current.is_empty();
        }

        pub fn get_bit(self: *const Self, bit: u64) bool {
            return self.current.get_bit(bit);
        }

        pub fn get_chunk_containing(self: *const Self, bit: u64) *const Chunk {
            return self.current.get_chunk_containing(bit);
        }

        pub fn pruned_chunks(self: *const Self) usize {
            return self.current.pruned_chunks();
        }

        /// Drops every commit numbered below `commit_number`; returns how many were dropped.
        pub fn prune_commits_before(self: *Self, gpa: Allocator, commit_number: u64) usize {
            const items = self.history.items;
            var count: usize = 0;
            while (count < items.len and items[count].number < commit_number) : (count += 1) {
                gpa.free(items[count].diff.chunk_diffs);
            }
            std.mem.copyForwards(Commit, items[0 .. items.len - count], items[count..]);
            self.history.shrinkRetainingCapacity(items.len - count);
            assert(self.earliest_commit() == null or self.earliest_commit().? >= commit_number);
            return count;
        }

        pub fn clear_history(self: *Self, gpa: Allocator) void {
            for (self.history.items) |entry| gpa.free(entry.diff.chunk_diffs);
            self.history.clearRetainingCapacity();
        }

        fn find_diff(entries: []const DiffEntry, chunk_index: usize) ?ChunkDiff {
            for (entries) |entry| {
                if (entry.index == chunk_index) return entry.diff;
            }
            return null;
        }

        /// Turns `state` (right after a commit) into the state right before it: restores
        /// pruned chunks, restores the length, then restores changed chunks.
        fn apply_reverse_diff(gpa: Allocator, state: *Bits, diff: CommitDiff) Allocator.Error!void {
            const newer_pruned = state.pruned_chunks();
            if (diff.pruned_chunks > newer_pruned) {
                std.debug.panic("invariant violation: target_pruned ({d}) > newer_pruned ({d})", .{
                    diff.pruned_chunks, newer_pruned,
                });
            }
            const restore = try gpa.alloc(Chunk, newer_pruned - diff.pruned_chunks);
            defer gpa.free(restore);
            for (restore, 0..) |*chunk, offset| {
                const chunk_index = newer_pruned - 1 - offset;
                const found = find_diff(diff.chunk_diffs, chunk_index) orelse ChunkDiff.added;
                if (found != .pruned) {
                    std.debug.panic("chunk {d} should be Pruned in diff", .{chunk_index});
                }
                chunk.* = found.pruned;
            }
            try state.unprune_chunks(gpa, restore);
            if (state.len() < diff.len) {
                try state.extend_to(gpa, diff.len);
            } else {
                state.truncate(diff.len);
            }
            for (diff.chunk_diffs) |entry| {
                if (entry.index < newer_pruned) continue;
                switch (entry.diff) {
                    .modified, .removed => |old| state.set_chunk_by_index(entry.index, &old),
                    // Added chunks sort after every modified one and are gone already.
                    .added => break,
                    .pruned => std.debug.panic(
                        "pruned chunk found at unexpected index {d}",
                        .{entry.index},
                    ),
                }
            }
            assert(state.pruned_chunks() == diff.pruned_chunks);
            assert(state.len() == diff.len);
        }

        /// Pending mutations over a bitmap (Rust `DirtyBitMap`). Invariants: appended bits
        /// occupy `[projected_len - appended_bits.len, projected_len)`; `modified_bits` holds
        /// only positions below that, so a bit is in at most one of them.
        pub const Dirty = struct {
            clean: Self,
            base_len: u64,
            base_pruned: usize,
            projected_len: u64,
            projected_pruned: usize,
            /// New values for bits of the base bitmap.
            modified_bits: std.AutoHashMapUnmanaged(u64, bool) = .empty,
            /// Bits pushed since `into_dirty`, in order.
            appended_bits: std.ArrayList(bool) = .empty,
            /// Old data of chunks pruned since `into_dirty`.
            chunks_to_prune: std.AutoHashMapUnmanaged(usize, Chunk) = .empty,

            pub fn len(self: *const Dirty) u64 {
                return self.projected_len;
            }

            pub fn is_empty(self: *const Dirty) bool {
                return self.projected_len == 0;
            }

            pub fn pruned_chunks(self: *const Dirty) usize {
                return self.projected_pruned;
            }

            fn appended_start(self: *const Dirty) u64 {
                assert(self.appended_bits.items.len <= self.projected_len);
                return self.projected_len - self.appended_bits.items.len;
            }

            fn assert_live(self: *const Dirty, bit: u64) void {
                if (bit >= self.projected_len) {
                    std.debug.panic("bit offset {d} out of bounds (len: {d})", .{
                        bit, self.projected_len,
                    });
                }
                const chunk_index = Bits.to_chunk_index(bit);
                if (chunk_index < self.projected_pruned) {
                    std.debug.panic("bit {d}: chunk {d} is pruned (pruned up to chunk {d})", .{
                        bit, chunk_index, self.projected_pruned,
                    });
                }
            }

            /// The bit as it will be after `commit`.
            pub fn get_bit(self: *const Dirty, bit: u64) bool {
                self.assert_live(bit);
                const start = self.appended_start();
                if (bit >= start) return self.appended_bits.items[@intCast(bit - start)];
                if (self.modified_bits.get(bit)) |value| return value;
                return self.clean.current.get_bit(bit);
            }

            /// The chunk containing `bit` as it will be after `commit`.
            pub fn get_chunk(self: *const Dirty, bit: u64) Chunk {
                self.assert_live(bit);
                const chunk_start = @as(u64, Bits.to_chunk_index(bit)) * chunk_bits;
                const chunk_end = chunk_start +| chunk_bits;
                const past_end = chunk_start >= self.projected_len;
                const before_changes = chunk_end <= self.appended_start() and
                    chunk_end <= self.projected_len;
                const modified_end = @min(chunk_end, self.base_len);
                if (!(past_end or before_changes) or
                    self.any_modified(chunk_start, modified_end))
                {
                    return self.reconstruct_chunk(chunk_start);
                }
                return self.clean.current.get_chunk_containing(bit).*;
            }

            fn any_modified(self: *const Dirty, start: u64, end: u64) bool {
                var bit = start;
                while (bit < end) : (bit += 1) {
                    if (self.modified_bits.contains(bit)) return true;
                }
                return false;
            }

            /// The current chunk at `chunk_start` with modifications and appends applied and
            /// popped bits cleared.
            fn reconstruct_chunk(self: *const Dirty, chunk_start: u64) Chunk {
                const current = &self.clean.current;
                var chunk: Chunk = if (chunk_start < current.len())
                    current.get_chunk_containing(chunk_start).*
                else
                    @splat(0);
                const start = self.appended_start();
                for (0..chunk_bits) |offset| {
                    const bit = chunk_start + offset;
                    const value: ?bool = if (bit >= self.projected_len)
                        false
                    else if (self.modified_bits.get(bit)) |modified|
                        modified
                    else if (bit >= start)
                        self.appended_bits.items[@intCast(bit - start)]
                    else
                        null;
                    const mask = @as(u8, 1) << @intCast(offset % 8);
                    const byte = &chunk[offset / 8];
                    if (value) |set| {
                        if (set) byte.* |= mask else byte.* &= ~mask;
                    }
                }
                return chunk;
            }

            pub fn set_bit(self: *Dirty, gpa: Allocator, bit: u64, value: bool) !void {
                self.assert_live(bit);
                const start = self.appended_start();
                if (bit >= start) {
                    self.appended_bits.items[@intCast(bit - start)] = value;
                } else {
                    try self.modified_bits.put(gpa, bit, value);
                }
                assert(self.get_bit(bit) == value);
            }

            pub fn push(self: *Dirty, gpa: Allocator, bit: bool) Allocator.Error!void {
                try self.appended_bits.append(gpa, bit);
                self.projected_len += 1;
            }

            pub fn push_byte(self: *Dirty, gpa: Allocator, byte: u8) Allocator.Error!void {
                try self.appended_bits.ensureUnusedCapacity(gpa, 8);
                for (0..8) |shift| {
                    self.appended_bits.appendAssumeCapacity((byte >> @intCast(shift)) & 1 == 1);
                }
                self.projected_len += 8;
            }

            pub fn push_chunk(self: *Dirty, gpa: Allocator, chunk: *const Chunk) !void {
                try self.appended_bits.ensureUnusedCapacity(gpa, N * 8);
                for (chunk) |byte| {
                    // Proof: room for every bit was reserved above.
                    self.push_byte(gpa, byte) catch unreachable;
                }
            }

            /// Removes the last bit and returns its value, including pending modifications.
            pub fn pop(self: *Dirty) bool {
                if (self.projected_len == 0) @panic("cannot pop from empty bitmap");
                const start = self.appended_start();
                self.projected_len -= 1;
                const bit = self.projected_len;
                if (bit >= start) return self.appended_bits.pop().?;
                if (self.modified_bits.fetchRemove(bit)) |entry| return entry.value;
                return self.clean.current.get_bit(bit);
            }

            /// Prunes the chunks before the one containing `bit` (`bit <= len`), capturing
            /// their data for the reverse diff.
            pub fn prune_to_bit(self: *Dirty, gpa: Allocator, bit: u64) Allocator.Error!void {
                if (bit > self.projected_len) {
                    std.debug.panic("cannot prune to bit {d}: beyond projected length ({d})", .{
                        bit, self.projected_len,
                    });
                }
                const chunk_num = Bits.to_chunk_index(bit);
                if (chunk_num <= self.projected_pruned) return;
                const added: u32 = @intCast(chunk_num - self.projected_pruned);
                try self.chunks_to_prune.ensureUnusedCapacity(gpa, added);
                const current = &self.clean.current;
                var chunk_index = self.projected_pruned;
                while (chunk_index < chunk_num) : (chunk_index += 1) {
                    if (self.chunks_to_prune.contains(chunk_index)) continue;
                    assert(chunk_index >= current.pruned_chunks());
                    const data = if (chunk_index < current.chunks_len())
                        current.get_chunk(chunk_index)
                    else
                        self.appended_chunk(chunk_index);
                    self.chunks_to_prune.putAssumeCapacity(chunk_index, data);
                }
                self.projected_pruned = chunk_num;
            }

            /// A chunk that exists only in the appended bits.
            fn appended_chunk(self: *const Dirty, chunk_index: usize) Chunk {
                const chunk_start = @as(u64, chunk_index) * chunk_bits;
                const start = self.appended_start();
                var chunk: Chunk = @splat(0);
                for (0..chunk_bits) |offset| {
                    const bit = chunk_start + offset;
                    if (bit >= self.projected_len) break;
                    if (bit >= start and self.appended_bits.items[@intCast(bit - start)]) {
                        chunk[offset / 8] |= @as(u8, 1) << @intCast(offset % 8);
                    }
                }
                return chunk;
            }

            /// Applies the mutations, records the reverse diff as `commit_number`, and returns
            /// the clean bitmap. On error nothing changes.
            pub fn commit(
                self: *Dirty,
                gpa: Allocator,
                commit_number: u64,
            ) (Error || Allocator.Error)!Self {
                if (commit_number == std.math.maxInt(u64)) return error.ReservedCommitNumber;
                if (self.clean.latest_commit()) |latest| {
                    if (commit_number <= latest) return error.NonMonotonicCommit;
                }
                const diff = try self.build_reverse_diff(gpa);
                errdefer gpa.free(diff.chunk_diffs);
                try self.clean.history.ensureUnusedCapacity(gpa, 1);
                const current = &self.clean.current;
                try current.ensure_total_capacity(gpa, @max(self.projected_len, current.len()));
                // Infallible from here: capacity is reserved.
                current.truncate(self.appended_start());
                for (self.appended_bits.items) |bit| {
                    current.push(gpa, bit) catch unreachable; // Proof: capacity reserved above.
                }
                assert(current.len() == self.projected_len);
                var modified = self.modified_bits.iterator();
                while (modified.next()) |entry| current.set_bit(entry.key_ptr.*, entry.value_ptr.*);
                if (self.projected_pruned > self.base_pruned) {
                    current.prune_to_bit(@as(u64, self.projected_pruned) * chunk_bits);
                }
                self.clean.history.appendAssumeCapacity(.{ .number = commit_number, .diff = diff });
                return self.finish(gpa);
            }

            /// Drops the mutations and returns the unchanged bitmap.
            pub fn abort(self: *Dirty, gpa: Allocator) Self {
                return self.finish(gpa);
            }

            fn finish(self: *Dirty, gpa: Allocator) Self {
                self.modified_bits.deinit(gpa);
                self.appended_bits.deinit(gpa);
                self.chunks_to_prune.deinit(gpa);
                const clean = self.clean;
                self.* = undefined;
                return clean;
            }

            fn build_reverse_diff(self: *const Dirty, gpa: Allocator) Allocator.Error!CommitDiff {
                var changes: std.AutoHashMapUnmanaged(usize, ChunkDiff) = .empty;
                defer changes.deinit(gpa);
                // Earlier captures take precedence; pruned chunks override them all.
                try self.capture_modified_chunks(gpa, &changes);
                try self.capture_appended_chunks(gpa, &changes);
                try self.capture_popped_chunks(gpa, &changes);
                var pruned = self.chunks_to_prune.iterator();
                while (pruned.next()) |entry| {
                    try changes.put(gpa, entry.key_ptr.*, .{ .pruned = entry.value_ptr.* });
                }
                const entries = try gpa.alloc(DiffEntry, changes.count());
                var change = changes.iterator();
                var count: usize = 0;
                while (change.next()) |entry| : (count += 1) {
                    entries[count] = .{ .index = entry.key_ptr.*, .diff = entry.value_ptr.* };
                }
                assert(count == entries.len);
                std.mem.sort(DiffEntry, entries, {}, struct {
                    fn less(_: void, a: DiffEntry, b: DiffEntry) bool {
                        return a.index < b.index;
                    }
                }.less);
                return .{
                    .len = self.base_len,
                    .pruned_chunks = self.base_pruned,
                    .chunk_diffs = entries,
                };
            }

            const Changes = std.AutoHashMapUnmanaged(usize, ChunkDiff);

            fn capture_modified_chunks(
                self: *const Dirty,
                gpa: Allocator,
                changes: *Changes,
            ) Allocator.Error!void {
                var modified = self.modified_bits.keyIterator();
                while (modified.next()) |bit| {
                    const chunk_index = Bits.to_chunk_index(bit.*);
                    const slot = try changes.getOrPut(gpa, chunk_index);
                    if (slot.found_existing) continue;
                    // Modified bits are base bits, so their chunk exists in the base bitmap.
                    slot.value_ptr.* = .{ .modified = self.chunk_from_current(chunk_index).? };
                }
            }

            fn capture_appended_chunks(
                self: *const Dirty,
                gpa: Allocator,
                changes: *Changes,
            ) Allocator.Error!void {
                if (self.appended_bits.items.len == 0) return;
                var chunk_index = Bits.to_chunk_index(self.appended_start());
                const end_chunk = Bits.to_chunk_index(self.projected_len - 1);
                while (chunk_index <= end_chunk) : (chunk_index += 1) {
                    const slot = try changes.getOrPut(gpa, chunk_index);
                    if (slot.found_existing) continue;
                    slot.value_ptr.* = if (self.chunk_from_current(chunk_index)) |old|
                        .{ .modified = old }
                    else
                        .added;
                }
            }

            fn capture_popped_chunks(
                self: *const Dirty,
                gpa: Allocator,
                changes: *Changes,
            ) Allocator.Error!void {
                if (self.projected_len >= self.base_len or self.base_len == 0) return;
                const old_last = Bits.to_chunk_index(self.base_len - 1);
                const new_last = if (self.projected_len > 0)
                    Bits.to_chunk_index(self.projected_len - 1)
                else
                    0;
                // Popping every unpruned bit can leave `new_last` below the pruned chunks.
                var chunk_index = @max(self.base_pruned, new_last);
                while (chunk_index <= old_last) : (chunk_index += 1) {
                    const slot = try changes.getOrPut(gpa, chunk_index);
                    if (slot.found_existing) continue;
                    const old = self.chunk_from_current(chunk_index).?;
                    const chunk_start = @as(u64, chunk_index) * chunk_bits;
                    slot.value_ptr.* = if (self.projected_len > chunk_start)
                        .{ .modified = old }
                    else
                        .{ .removed = old };
                }
            }

            fn chunk_from_current(self: *const Dirty, chunk_index: usize) ?Chunk {
                const current = &self.clean.current;
                if (chunk_index < current.pruned_chunks()) return null;
                if (chunk_index >= current.chunks_len()) return null;
                return current.get_chunk(chunk_index);
            }
        };
    };
}
