//! A mock application that stores the finalized blocks marshal reports (commonware
//! `marshal/mocks/application.rs`).
//!
//! zigware differences: commonware's `Application` is a `Clone` of `Arc<Mutex<..>>` fields.
//! Here it is a handle to one heap state with `clone` and `deinit`, so the actor owns one
//! handle and the test inspects another. Snapshots (`blocks`, `pending_ack_heights`) are
//! owned copies the caller frees; `contains`, `block_count`, and `block` read the state
//! without copying it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const utils = @import("utils");
const types = @import("../../types.zig");
const update = @import("../update.zig");

const Height = types.Height;
const Exact = utils.acknowledgement.Exact;

/// A shared application over blocks `B` that records every finalized block and the tip,
/// and acknowledges blocks at once (`init`) or queues them for the test (`manual_ack`).
pub fn Application(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;
        pub const Activity = update.Update(B, Exact);
        pub const Tip = struct { height: Height, digest: B.Digest };
        /// A finalized block at its height.
        pub const Entry = struct { height: Height, block: broadcast.Digested(B) };

        state: *State,

        const Pending = struct { height: Height, ack: Exact };

        const State = struct {
            gpa: Allocator,
            io: Io,
            mutex: Io.Mutex = .init,
            /// Broadcast when a block is queued for a manual acknowledgement.
            queued: Io.Condition = .init,
            /// Finalized blocks, sorted by height, one per height.
            blocks: std.ArrayList(Entry) = .empty,
            tip: ?Tip = null,
            /// Unacknowledged blocks in arrival order (manual acknowledgement only).
            pending: std.ArrayList(Pending) = .empty,
            auto_ack: bool,
            /// Live handles; the last `deinit` frees the state.
            references: u32 = 1,

            fn lock(state: *State) void {
                state.mutex.lockUncancelable(state.io);
            }

            fn unlock(state: *State) void {
                state.mutex.unlock(state.io);
            }

            /// The index of `height` in `blocks`, or where it would be inserted.
            fn search(state: *const State, height: Height) struct { index: usize, found: bool } {
                var low: usize = 0;
                var high: usize = state.blocks.items.len;
                while (low < high) {
                    const middle = low + (high - low) / 2;
                    const at = state.blocks.items[middle].height.get();
                    if (at == height.get()) return .{ .index = middle, .found = true };
                    if (at < height.get()) low = middle + 1 else high = middle;
                }
                assert(low <= state.blocks.items.len);
                return .{ .index = low, .found = false };
            }
        };

        /// An application that acknowledges every block as it arrives.
        pub fn init(gpa: Allocator, io: Io) Allocator.Error!Self {
            return create(gpa, io, true);
        }

        /// An application that queues acknowledgements for the test to release.
        pub fn manual_ack(gpa: Allocator, io: Io) Allocator.Error!Self {
            return create(gpa, io, false);
        }

        fn create(gpa: Allocator, io: Io, auto_ack: bool) Allocator.Error!Self {
            const state = try gpa.create(State);
            state.* = .{ .gpa = gpa, .io = io, .auto_ack = auto_ack };
            assert(state.references == 1);
            return .{ .state = state };
        }

        /// Another handle to the same application.
        pub fn clone(self: Self) Self {
            const state = self.state;
            state.lock();
            defer state.unlock();
            assert(state.references > 0);
            state.references += 1;
            return .{ .state = state };
        }

        /// Drops this handle. The last one frees the blocks and drops the pending
        /// acknowledgements unacknowledged, which stops a marshal waiting on them.
        pub fn deinit(self: *Self) void {
            const state = self.state;
            self.* = undefined;
            state.lock();
            assert(state.references > 0);
            state.references -= 1;
            const last = state.references == 0;
            state.unlock();
            if (!last) return;
            for (state.blocks.items) |*entry| entry.block.deinit();
            for (state.pending.items) |*pending| pending.ack.deinit();
            state.blocks.deinit(state.gpa);
            state.pending.deinit(state.gpa);
            state.gpa.destroy(state);
        }

        /// Records a finalized block or tip (commonware `Reporter::report`).
        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            const state = self.state;
            switch (activity) {
                .tip => |reported| {
                    state.lock();
                    defer state.unlock();
                    state.tip = .{ .height = reported.height, .digest = reported.digest };
                },
                .block => |value| {
                    var ack = value.ack;
                    const height = value.block.inner().height();
                    state.lock();
                    defer state.unlock();
                    insert_block(state, height, value.block);
                    if (state.auto_ack) {
                        ack.acknowledge();
                    } else {
                        state.pending.append(state.gpa, .{ .height = height, .ack = ack }) catch
                            @panic("mock application: out of memory");
                        state.queued.broadcast(state.io);
                    }
                },
            }
            return .ok;
        }

        /// Stores `block` at `height`, replacing an earlier block there (lock held).
        fn insert_block(state: *State, height: Height, value: broadcast.Digested(B)) void {
            const at = state.search(height);
            if (at.found) {
                state.blocks.items[at.index].block.deinit();
                state.blocks.items[at.index].block = value;
                return;
            }
            state.blocks.insert(state.gpa, at.index, .{ .height = height, .block = value }) catch
                @panic("mock application: out of memory");
            assert(state.blocks.items[at.index].height.get() == height.get());
        }

        /// The finalized blocks by height, as shared handles the caller frees with
        /// `free_blocks`.
        pub fn blocks(self: Self, gpa: Allocator) Allocator.Error![]Entry {
            const state = self.state;
            state.lock();
            defer state.unlock();
            const copy = try gpa.alloc(Entry, state.blocks.items.len);
            for (copy, state.blocks.items) |*to, from| {
                to.* = .{ .height = from.height, .block = from.block.clone() };
            }
            return copy;
        }

        /// Releases a `blocks` snapshot.
        pub fn free_blocks(gpa: Allocator, entries: []Entry) void {
            for (entries) |*entry| entry.block.deinit();
            gpa.free(entries);
        }

        /// How many finalized blocks the application holds.
        pub fn block_count(self: Self) usize {
            const state = self.state;
            state.lock();
            defer state.unlock();
            return state.blocks.items.len;
        }

        /// Whether the application holds a finalized block at `height`.
        pub fn contains(self: Self, height: Height) bool {
            const state = self.state;
            state.lock();
            defer state.unlock();
            return state.search(height).found;
        }

        /// The finalized block at `height`, as a handle the caller frees.
        pub fn block(self: Self, height: Height) ?broadcast.Digested(B) {
            const state = self.state;
            state.lock();
            defer state.unlock();
            const at = state.search(height);
            if (!at.found) return null;
            return state.blocks.items[at.index].block.clone();
        }

        /// The latest reported tip.
        pub fn tip(self: Self) ?Tip {
            const state = self.state;
            state.lock();
            defer state.unlock();
            return state.tip;
        }

        /// The heights of unacknowledged blocks in arrival order; the caller frees them.
        pub fn pending_ack_heights(self: Self, gpa: Allocator) Allocator.Error![]Height {
            const state = self.state;
            state.lock();
            defer state.unlock();
            const heights = try gpa.alloc(Height, state.pending.items.len);
            for (heights, state.pending.items) |*height, pending| height.* = pending.height;
            return heights;
        }

        /// Acknowledges the oldest pending block and returns its height.
        pub fn acknowledge_next(self: Self) ?Height {
            const state = self.state;
            state.lock();
            if (state.pending.items.len == 0) {
                state.unlock();
                return null;
            }
            var pending = state.pending.orderedRemove(0);
            state.unlock();
            pending.ack.acknowledge();
            return pending.height;
        }

        /// Waits for the next block to be queued, acknowledges it, and returns its height.
        pub fn acknowledged(self: Self) Io.Cancelable!Height {
            const state = self.state;
            assert(!state.auto_ack);
            state.lock();
            while (state.pending.items.len == 0) {
                state.queued.wait(state.io, &state.mutex) catch |err| {
                    state.unlock();
                    return err;
                };
            }
            var pending = state.pending.orderedRemove(0);
            state.unlock();
            pending.ack.acknowledge();
            return pending.height;
        }
    };
}

test {
    _ = @import("application_test.zig");
}
