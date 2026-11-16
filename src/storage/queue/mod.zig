//! A durable, at-least-once delivery queue backed by a contiguous variable journal (commonware's
//! `storage/src/queue`).
//!
//! Items are durably stored in a journal and survive crashes. The reader side delivers committed
//! items in FIFO order and must acknowledge each one after processing; items can be acknowledged
//! out of order. Acknowledgements are in memory only: the durable equivalent is the journal's
//! pruning boundary, which `sync` advances to the whole sections below the ack floor. On restart
//! every non-pruned item is re-delivered, acknowledged or not, so processing must be idempotent.
//!
//! # Operations
//!
//! - `append` / `commit`: write items, then persist and publish them to the reader. Appended items
//!   are lost on restart unless committed.
//! - `enqueue`: append and commit in one step.
//! - `sync`: commit, then prune completed sections below the ack floor.
//! - `try_recv`: the next unacknowledged committed item.
//! - `ack` / `ack_up_to`: mark items processed.
//!
//! # Ownership
//!
//! commonware splits the queue into a writer and a `Reader` that may run in separate tasks and
//! share snapshots over a watch channel. Nothing here runs concurrently with the journal, so one
//! `Queue` holds both sides and the reader reads the live journal up to the published size.
//! Received items are owned by the caller; free them with `codec.free`. A failed storage
//! mutation leaves the queue failed; only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const Storage = runtime.storage.Storage;
const variable = @import("../journal/contiguous/variable.zig");
const cursor_mod = @import("cursor.zig");

pub const cursor = cursor_mod;
pub const Cursor = cursor_mod.Cursor;

pub const Error = variable.Error || error{PositionOutOfRange};

/// Configuration of a queue: its journal's configuration (`partition`, `items_per_section`,
/// `compression`, `codec_config`, `cache_ref`, `write_buffer`, `replay_buffer`).
pub fn Config(comptime V: type) type {
    return variable.Config(V);
}

/// Positions `[start, end)` returned by `enqueue_bulk`.
pub const Range = struct { start: u64, end: u64 };

pub fn Queue(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Journal = variable.Journal(V);

        /// An item delivered by `try_recv`; the caller owns `item`.
        pub const Received = struct { position: u64, item: V };

        gpa: Allocator,
        journal: Journal,
        cursor: Cursor,
        /// Items visible to the reader: the size at the last commit or sync.
        published: u64,
        failed: bool = false,
        /// Metrics: total appended items (`tip`), the next item to dequeue (`next`), and the
        /// ack floor (`floor`, read from the cursor).
        tip: u64,
        next: u64,

        /// Open the queue. On restart the reader begins at the journal's pruning boundary.
        pub fn init(gpa: Allocator, storage: Storage, cfg: Config(V)) Error!Self {
            const journal = try Journal.init(gpa, storage, cfg);
            const bounds = journal.get_bounds();
            assert(bounds.start <= bounds.end);
            return .{
                .gpa = gpa,
                .journal = journal,
                .cursor = .init(bounds.start),
                .published = bounds.end,
                .tip = bounds.end,
                .next = bounds.start,
            };
        }

        /// Close the queue, dropping uncommitted items and acknowledgements.
        pub fn deinit(self: *Self) void {
            self.cursor.deinit(self.gpa);
            self.journal.deinit();
            self.* = undefined;
        }

        /// Remove all data from storage, freeing the queue.
        pub fn destroy(self: *Self) Error!void {
            assert(!self.failed);
            self.cursor.deinit(self.gpa);
            defer self.* = undefined;
            try self.journal.destroy();
        }

        /// The number of items appended.
        pub fn size(self: *const Self) u64 {
            return self.journal.size();
        }

        /// The ack floor: every position below it is acknowledged.
        pub fn floor(self: *const Self) u64 {
            return self.cursor.ack_floor;
        }

        /// Append an item without committing, returning its position. The reader receives it
        /// after the next `commit` or `sync`.
        pub fn append(self: *Self, item: V) Error!u64 {
            assert(!self.failed);
            errdefer self.failed = true;
            const position = try self.journal.append(item);
            self.tip = position + 1;
            assert(self.tip == self.journal.size());
            return position;
        }

        /// Append and commit an item, returning its position.
        pub fn enqueue(self: *Self, item: V) Error!u64 {
            const position = try self.append(item);
            try self.commit();
            return position;
        }

        /// Append `items` with a single commit, returning their positions.
        pub fn enqueue_bulk(self: *Self, items: []const V) Error!Range {
            const start = self.journal.size();
            for (items) |item| _ = try self.append(item);
            const end = self.journal.size();
            assert(end - start == items.len);
            // Only a nonempty batch needs a commit.
            if (end > start) try self.commit();
            return .{ .start = start, .end = end };
        }

        /// Durably persist appended items and publish them to the reader. Does not persist
        /// acknowledgements; `sync` also prunes acknowledged sections.
        pub fn commit(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.journal.commit();
            self.published = self.journal.size();
        }

        /// Durably persist the queue so no recovery is needed on startup, prune whole sections
        /// below the ack floor, and publish.
        pub fn sync(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            // Make appended items durable before pruning their predecessors.
            try self.journal.sync();
            _ = try self.journal.prune(self.cursor.ack_floor);
            assert(self.journal.pruning_boundary() <= self.cursor.ack_floor);
            self.published = self.journal.size();
        }

        /// The next unacknowledged published item, or null when none is waiting.
        pub fn try_recv(self: *Self) Error!?Received {
            const position = self.cursor.next_position(self.published);
            self.next = self.cursor.read_pos;
            const next_position = position orelse return null;
            // Advance delivery only after the item has been read successfully.
            const item = try self.journal.read(next_position);
            self.cursor.delivered(next_position);
            self.next = self.cursor.read_pos;
            return .{ .position = next_position, .item = item };
        }

        /// Whether `position` has been acknowledged.
        pub fn is_acked(self: *const Self, position: u64) bool {
            return self.cursor.is_acked(position);
        }

        /// Mark the item at `position` as processed (in memory only). Fails with
        /// `PositionOutOfRange` if it has not been published.
        pub fn ack(self: *Self, position: u64) Error!void {
            try self.cursor.ack(self.gpa, position, self.published);
        }

        /// Acknowledge every item in `[ack_floor, up_to)`. Fails with `PositionOutOfRange` if
        /// `up_to` exceeds the published items.
        pub fn ack_up_to(self: *Self, up_to: u64) Error!void {
            try self.cursor.ack_up_to(self.gpa, up_to, self.published);
        }

        /// The position of the next item `try_recv` checks.
        pub fn read_position(self: *const Self) u64 {
            return self.cursor.read_pos;
        }

        /// Whether every published item has been acknowledged.
        pub fn is_empty(self: *const Self) bool {
            return self.cursor.is_empty(self.published);
        }

        /// Reset the read position to the ack floor so every unacknowledged item is
        /// re-delivered.
        pub fn reset(self: *Self) void {
            self.cursor.reset();
            self.next = self.cursor.read_pos;
        }

        /// Published items not yet read.
        pub fn pending(self: *const Self) u64 {
            return self.published -| self.cursor.read_pos;
        }
    };
}

test {
    _ = @import("cursor.zig");
    _ = @import("queue_test.zig");
}
