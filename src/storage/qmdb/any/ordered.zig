//! Write emission of an ordered `any` batch (commonware's ordered `walk_floor_and_merkleize`
//! and `any/ordered/mod.rs` `Neighbors`).
//!
//! Every ordered update carries the next active key, wrapping from the largest key to the
//! smallest. A batch emits its deletes, then its updates of existing keys, then its creates,
//! each in key order, and then rewrites the predecessor of every key that joins or leaves the
//! key set so the links stay a single cycle. The candidates for each written key's successor
//! (`next`) and each changed key's predecessor (`prev`) come from the updates read for the
//! writes, their translated-key neighbors in the snapshot, and the ancestors' active updates.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const value_mod = @import("../value.zig");
const diff_mod = @import("diff.zig");

/// The ordered emission of database type `D`'s batches.
pub fn Emitter(comptime D: type) type {
    return struct {
        const K = D.Key;
        const V = D.Value;
        const Mutation = D.UnmerkleizedBatch.Mutation;

        /// The current update of a predecessor candidate, taken once it is rewritten.
        const Source = struct { value: V, loc: u64 };
        const Prev = struct { key: K, source: ?Source };
        const Deleted = struct { key: K, loc: u64 };
        const Updated = struct { key: K, value: V, loc: u64 };
        const Created = struct { key: K, value: V, base_old_loc: ?u64 };

        const State = struct {
            next: std.ArrayList(K) = .empty,
            prev: std.ArrayList(Prev) = .empty,
            deleted: std.ArrayList(Deleted) = .empty,
            updated: std.ArrayList(Updated) = .empty,
            created: std.ArrayList(Created) = .empty,

            fn deinit(state: *State, gpa: Allocator) void {
                state.next.deinit(gpa);
                state.prev.deinit(gpa);
                state.deleted.deinit(gpa);
                state.updated.deinit(gpa);
                state.created.deinit(gpa);
                state.* = undefined;
            }
        };

        /// Emits `writes` (the last write of each key, sorted by key) into `walked`.
        pub fn emit(m: anytype, walked: anytype, writes: []const Mutation) !void {
            const gpa = m.gpa;
            var state: State = .{};
            defer state.deinit(gpa);
            try classify(m, &state, writes);
            try add_translated_neighbors(m, &state);
            std.mem.sort(Deleted, state.deleted.items, {}, key_less(Deleted));
            std.mem.sort(Updated, state.updated.items, {}, key_less(Updated));
            const changes_membership = state.created.items.len + state.deleted.items.len > 0;
            if (changes_membership) try add_ancestor_neighbors(m, &state);
            finish(&state);
            const ops_before = walked.ops.items.len;
            try emit_writes(m, walked, &state);
            if (changes_membership) try rewrite_predecessors(m, walked, &state);
            assert(walked.ops.items.len >= ops_before + state.updated.items.len);
        }

        fn key_less(comptime T: type) fn (void, T, T) bool {
            return struct {
                fn less(_: void, a: T, b: T) bool {
                    return diff_mod.order(K, &a.key, &b.key) == .lt;
                }
            }.less;
        }

        /// The active update at `loc`, or null if an ancestor superseded it (commonware's
        /// `read_live`).
        fn live_update(m: anytype, loc: u64) !?D.Update {
            const op = try m.read_op(loc);
            if (op != .update) return error.DataCorrupted; // Candidates hold updates.
            if (m.locate(loc, &op.update.key) == null) return null;
            return op.update;
        }

        fn push_neighbor(gpa: Allocator, state: *State, update: D.Update, loc: u64) !void {
            try state.next.append(gpa, update.next_key);
            const source: Source = .{ .value = update.value, .loc = loc };
            try state.prev.append(gpa, .{ .key = update.key, .source = source });
        }

        /// Reads the written keys' current updates (and their collision siblings), sorting the
        /// writes into deletes, updates, and creates.
        fn classify(m: anytype, state: *State, writes: []const Mutation) !void {
            const gpa = m.gpa;
            const locations = try m.gather_existing_locations(writes);
            defer gpa.free(locations);
            const consumed = try gpa.alloc(bool, writes.len);
            defer gpa.free(consumed);
            @memset(consumed, false);
            for (locations) |loc| {
                const update = try live_update(m, loc) orelse continue;
                try push_neighbor(gpa, state, update, loc);
                const index = find_write(writes, &update.key) orelse continue; // A sibling.
                if (consumed[index]) continue;
                consumed[index] = true;
                if (writes[index].value) |value| {
                    const updated: Updated = .{ .key = update.key, .value = value, .loc = loc };
                    try state.updated.append(gpa, updated);
                } else {
                    try state.deleted.append(gpa, .{ .key = update.key, .loc = loc });
                }
            }
            for (writes, consumed) |write, done| {
                if (done) continue;
                const value = write.value orelse continue; // Deleting an absent key.
                var base_old_loc: ?u64 = null;
                if (diff_mod.resolve(K, V, m.ancestor_entries, &write.key)) |entry| {
                    if (entry.* == .deleted) base_old_loc = entry.base_old_loc();
                }
                try state.next.append(gpa, write.key);
                try state.created.append(gpa, .{
                    .key = write.key,
                    .value = value,
                    .base_old_loc = base_old_loc,
                });
            }
        }

        fn find_write(writes: []const Mutation, key: *const K) ?usize {
            var low: usize = 0;
            var high: usize = writes.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                switch (diff_mod.order(K, &writes[mid].key, key)) {
                    .lt => low = mid + 1,
                    .gt => high = mid,
                    .eq => return mid,
                }
            }
            return null;
        }

        /// Adds the updates under the translated key before each deleted and created key: they
        /// may precede the changed keys, and their successors may follow the created ones.
        fn add_translated_neighbors(m: anytype, state: *State) !void {
            const gpa = m.gpa;
            var locations: std.ArrayList(u64) = .empty;
            defer locations.deinit(gpa);
            const deleted_count = state.deleted.items.len;
            for (0..deleted_count + state.created.items.len) |at| {
                const key = if (at < deleted_count)
                    &state.deleted.items[at].key
                else
                    &state.created.items[at - deleted_count].key;
                const neighbor = m.db.snapshot.prev_translated_key(value_mod.bytes(K, key)) orelse
                    continue;
                var values = neighbor.values;
                while (values.next()) |loc| try locations.append(gpa, loc.*);
            }
            std.mem.sort(u64, locations.items, {}, std.sort.asc(u64));
            var previous: ?u64 = null;
            for (locations.items) |loc| {
                if (previous == loc) continue;
                previous = loc;
                const update = try live_update(m, loc) orelse continue;
                try push_neighbor(gpa, state, update, loc);
            }
        }

        /// Adds the ancestors' active updates of keys this batch leaves alone: the snapshot
        /// lookups above see only the database.
        fn add_ancestor_neighbors(m: anytype, state: *State) !void {
            const gpa = m.gpa;
            for (m.ancestor_entries) |entries| {
                for (entries) |*pair| {
                    const loc = pair.entry.loc() orelse continue;
                    // A nearer ancestor's entry for the key shadows this one.
                    const nearest = diff_mod.resolve(K, V, m.ancestor_entries, &pair.key).?;
                    if (nearest != &pair.entry) continue;
                    if (held(state, &pair.key)) continue;
                    const op = try m.read_op(loc);
                    if (op != .update) return error.DataCorrupted; // Active entries are updates.
                    try state.next.append(gpa, op.update.key);
                    try push_neighbor(gpa, state, op.update, loc);
                }
            }
        }

        /// Whether this batch writes `key` (the lists must be sorted).
        fn held(state: *const State, key: *const K) bool {
            if (find(Updated, state.updated.items, key) != null) return true;
            if (find(Created, state.created.items, key) != null) return true;
            return find(Deleted, state.deleted.items, key) != null;
        }

        fn find(comptime T: type, items: []const T, key: *const K) ?usize {
            var low: usize = 0;
            var high: usize = items.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                switch (diff_mod.order(K, &items[mid].key, key)) {
                    .lt => low = mid + 1,
                    .gt => high = mid,
                    .eq => return mid,
                }
            }
            return null;
        }

        /// Sorts the candidates, keeping the last pushed source per predecessor key and dropping
        /// deleted keys (commonware's `finish_next` and `finish_prev`).
        fn finish(state: *State) void {
            std.mem.sort(K, state.next.items, {}, struct {
                fn less(_: void, a: K, b: K) bool {
                    return diff_mod.order(K, &a, &b) == .lt;
                }
            }.less);
            var count: usize = 0;
            for (state.next.items) |key| {
                if (count > 0 and diff_mod.order(K, &state.next.items[count - 1], &key) == .eq) {
                    continue;
                }
                if (find(Deleted, state.deleted.items, &key) != null) continue;
                state.next.items[count] = key;
                count += 1;
            }
            state.next.shrinkRetainingCapacity(count);
            // Stable: a key's later pushes carry fresher state, so the last one wins.
            std.mem.sort(Prev, state.prev.items, {}, key_less(Prev));
            count = 0;
            for (state.prev.items, 0..) |prev, at| {
                const last = at + 1 == state.prev.items.len or
                    diff_mod.order(K, &prev.key, &state.prev.items[at + 1].key) != .eq;
                if (!last) continue;
                if (find(Deleted, state.deleted.items, &prev.key) != null) continue;
                state.prev.items[count] = prev;
                count += 1;
            }
            state.prev.shrinkRetainingCapacity(count);
        }

        /// The smallest candidate above `key`, wrapping to the smallest.
        fn next_key(state: *const State, key: *const K) K {
            const next = state.next.items;
            assert(next.len > 0); // A written key's successor is always a candidate.
            var low: usize = 0;
            var high: usize = next.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (diff_mod.order(K, &next[mid], key) == .gt) high = mid else low = mid + 1;
            }
            return if (low < next.len) next[low] else next[0];
        }

        /// The key's location in the database snapshot: its nearest ancestor entry's base, else
        /// `loc` itself.
        fn base_of(m: anytype, key: *const K, loc: u64) ?u64 {
            const entry = diff_mod.resolve(K, V, m.ancestor_entries, key) orelse return loc;
            return entry.base_old_loc();
        }

        fn push(m: anytype, walked: anytype, update: D.Update, base: ?u64) !void {
            if (base) |loc| try walked.superseded.append(m.gpa, loc);
            try walked.push_update(m.gpa, update, base);
        }

        /// Emits the deletes, the updates, and the creates, each in key order.
        fn emit_writes(m: anytype, walked: anytype, state: *const State) !void {
            const gpa = m.gpa;
            for (state.deleted.items) |deleted| {
                const base = base_of(m, &deleted.key, deleted.loc);
                if (base) |loc| try walked.superseded.append(gpa, loc);
                try walked.push_delete(gpa, deleted.key, base);
            }
            for (state.updated.items) |updated| {
                const next = next_key(state, &updated.key);
                const update: D.Update = .{
                    .key = updated.key,
                    .value = updated.value,
                    .next_key = next,
                };
                try push(m, walked, update, base_of(m, &updated.key, updated.loc));
            }
            for (state.created.items) |created| {
                const next = next_key(state, &created.key);
                const update: D.Update = .{
                    .key = created.key,
                    .value = created.value,
                    .next_key = next,
                };
                try push(m, walked, update, created.base_old_loc);
                walked.active_keys_delta += 1;
            }
        }

        /// Rewrites the predecessor of each created, then each deleted, key with its current
        /// value and its successor in the final key set, once per predecessor.
        fn rewrite_predecessors(m: anytype, walked: anytype, state: *State) !void {
            if (state.prev.items.len == 0) return;
            const deleted_count = state.deleted.items.len;
            for (0..state.created.items.len + deleted_count) |at| {
                const key = if (at < state.created.items.len)
                    &state.created.items[at].key
                else
                    &state.deleted.items[at - state.created.items.len].key;
                const prev = claim(state, key);
                const source = prev.source orelse continue; // Rewritten already, or no source.
                prev.source = null;
                // An updated key's own operation carries its link.
                if (find(Updated, state.updated.items, &prev.key) != null) continue;
                const next = next_key(state, &prev.key);
                const update: D.Update = .{
                    .key = prev.key,
                    .value = source.value,
                    .next_key = next,
                };
                try push(m, walked, update, base_of(m, &prev.key, source.loc));
            }
        }

        /// The predecessor candidate of `key`: the largest below it, wrapping to the largest.
        fn claim(state: *State, key: *const K) *Prev {
            const prev = state.prev.items;
            assert(prev.len > 0);
            var low: usize = 0;
            var high: usize = prev.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (diff_mod.order(K, &prev[mid].key, key) == .lt) low = mid + 1 else high = mid;
            }
            return if (low > 0) &prev[low - 1] else &prev[prev.len - 1];
        }
    };
}

/// Whether `key` lies in the cyclic span `[start, end)`: the whole key space when `start` equals
/// `end` (a single key), wrapping past the largest key when `start` is above `end`.
pub fn in_span(comptime K: type, start: *const K, end: *const K, key: *const K) bool {
    const from_start = diff_mod.order(K, key, start) != .lt;
    const before_end = diff_mod.order(K, key, end) == .lt;
    if (diff_mod.order(K, start, end) == .lt) return from_start and before_end;
    return from_start or before_end;
}
