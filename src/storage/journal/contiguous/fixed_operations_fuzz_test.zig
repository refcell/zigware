//! The `journal_fixed_operations` fuzz target (commonware `storage/fuzz`): random appends,
//! batched and nested appends, reads, batch reads, replays, syncs, prunes, restarts, bounded
//! reopens, `init_at_size` near `u64::MAX`, and destroy on a fixed journal of SHA-256 digests
//! (three per blob, one 57-byte cache page).
//!
//! Beyond commonware's checks (sizes, pruning boundary, batch reads and synchronous reads
//! against single reads), every item read or replayed must be the digest last appended at its
//! position. commonware drops the journal where Zig calls `deinit`, which also discards
//! unsynced items; both reopen to the recovered size.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const contiguous = @import("mod.zig");
const fixed = @import("fixed.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Journal = fixed.Journal(D);
const Draws = codec.fuzz.Draws;

const operations_max = 50;
const append_many_max = 20;
const read_many_max = 16;
const buffer_max = 2048;

const Operation = enum {
    append,
    read,
    size,
    sync,
    reopen_at_most,
    bounds,
    prune,
    replay,
    restart,
    destroy,
    read_many,
    append_many,
    append_nested,
    reopen_matching,
    multiple_sync,
    try_read_sync,
    pruning_boundary,
    init_at_size,
};

fn digest(value: u64) D {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

/// commonware's `boundary_size`: biased toward `u64::MAX`, where size arithmetic overflows.
fn boundary_size(draws: Draws) u64 {
    const max = std.math.maxInt(u64);
    return switch (draws.index(5)) {
        0 => max,
        1 => max - 1,
        2 => max - draws.range_at_most(u64, 0, 64),
        3 => draws.range_at_most(u64, 0, 256),
        else => draws.value(u64),
    };
}

const State = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    journal: ?Journal = null,
    /// The digest last appended at each position.
    model: std.AutoHashMapUnmanaged(u64, D) = .empty,
    next_value: u64 = 0,
    size: u64 = 0,
    oldest: u64 = 0,

    fn cfg(self: *State) fixed.Config {
        return .{
            .partition = "fixed-journal-operations-fuzz-test",
            .items_per_blob = 3,
            .cache_ref = &self.cache_ref,
            .write_buffer = buffer_max,
            .replay_buffer = buffer_max,
        };
    }

    fn deinit(self: *State) void {
        if (self.journal) |*journal| journal.deinit();
        self.model.deinit(gpa);
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn j(self: *State) *Journal {
        return &self.journal.?;
    }

    /// Closes the journal (discarding unsynced items) and reopens it with `max_size`.
    fn reopen(self: *State, max_size: ?u64) !void {
        self.j().deinit();
        self.journal = null;
        const storage = self.storage.interface();
        self.journal = if (max_size) |max|
            try Journal.init_at_most(gpa, storage, self.cfg(), max)
        else
            try Journal.init(gpa, storage, self.cfg());
        self.observe();
    }

    fn observe(self: *State) void {
        const bounds = self.j().get_bounds();
        self.size = bounds.end;
        self.oldest = bounds.start;
        assert(self.oldest <= self.size);
    }

    fn expect_item(self: *const State, position: u64, item: D) !void {
        const expected = self.model.get(position) orelse return error.TestUnexpectedResult;
        try testing.expect(expected.eql(item));
    }

    /// Appends `digests` as one item, a flat batch, or a nested batch.
    fn append(self: *State, nested: []const []const D) !void {
        var count: u64 = 0;
        for (nested) |items| count += items.len;
        const result = if (nested.len == 1 and count == 1)
            self.j().append(nested[0][0])
        else
            self.j().append_many_nested(nested);
        const last = result catch |err| switch (err) {
            error.EmptyAppend, error.SizeOverflow => {
                if (err == error.EmptyAppend) assert(count == 0);
                return self.reopen(null);
            },
            else => return err,
        };
        try testing.expectEqual(self.size + count - 1, last);
        for (nested) |items| {
            for (items) |item| {
                try self.model.put(gpa, self.size, item);
                self.size += 1;
            }
        }
    }

    fn append_counted(self: *State, count_a: usize, count_b: usize, nested: bool) !void {
        var items: [2 * append_many_max]D = undefined;
        for (items[0 .. count_a + count_b]) |*item| {
            item.* = digest(self.next_value);
            self.next_value += 1;
        }
        const a = items[0..count_a];
        const b = items[count_a..][0..count_b];
        if (nested) return self.append(&.{ a, b });
        assert(count_b == 0);
        // A flat batch, as commonware's `Many::Flat`; even one item goes through append_many.
        const last = self.j().append_many(a) catch |err| switch (err) {
            error.EmptyAppend, error.SizeOverflow => return self.reopen(null),
            else => return err,
        };
        try testing.expectEqual(self.size + count_a - 1, last);
        for (a) |item| {
            try self.model.put(gpa, self.size, item);
            self.size += 1;
        }
    }

    /// A drawn position: inside the bounds half of the time, else any `u64`.
    fn draw_position(self: *State, draws: Draws) u64 {
        const raw = draws.value(u64);
        const len = self.size - self.oldest;
        if (len > 0 and draws.value(bool)) return self.oldest + raw % len;
        return raw;
    }

    fn contains(self: *const State, position: u64) bool {
        return position >= self.oldest and position < self.size;
    }

    fn read(self: *State, position: u64) !void {
        if (!self.contains(position)) return;
        try self.expect_item(position, try self.j().read(position));
        if (self.j().try_read_sync(position)) |item| try self.expect_item(position, item);
    }

    fn read_many(self: *State, draws: Draws) !void {
        const len = self.size - self.oldest;
        const count = draws.range_at_most(usize, 0, read_many_max);
        var positions: [read_many_max]u64 = undefined;
        for (positions[0..count]) |*p| p.* = draws.value(u64);
        if (len == 0 or count == 0) return;
        for (positions[0..count]) |*p| p.* = self.oldest + p.* % len;
        std.mem.sort(u64, positions[0..count], {}, std.sort.asc(u64));
        var unique: usize = 0;
        for (positions[0..count]) |p| {
            if (unique > 0 and positions[unique - 1] == p) continue;
            positions[unique] = p;
            unique += 1;
        }
        var out: [read_many_max]D = undefined;
        try self.j().read_many(positions[0..unique], out[0..unique]);
        for (positions[0..unique], out[0..unique]) |p, item| {
            try testing.expect(item.eql(try self.j().read(p)));
            try self.expect_item(p, item);
        }
    }

    /// Replays from a drawn start, checking up to three batches.
    fn replay(self: *State, draws: Draws) !void {
        const buffer = draws.range_at_most(usize, 1, buffer_max);
        const start = self.oldest + draws.value(u64) % (self.size - self.oldest + 1);
        var stream = try self.j().replay(.{ .start = start, .end = self.size }, buffer);
        defer stream.deinit();
        var expected = start;
        for (0..3) |_| {
            const batch = try stream.next() orelse break;
            try testing.expectEqual(expected, batch.start);
            for (batch.items, batch.start..) |item, p| try self.expect_item(p, item);
            expected += batch.items.len;
        }
        assert(expected <= self.size);
    }

    /// Syncs and reopens at the last position holding `digest(keep_value)` (commonware's
    /// `ReopenMatching`), or at the pruning boundary when none does.
    fn reopen_matching(self: *State, keep_value: u64) !void {
        if (self.size == self.oldest) return;
        const target = digest(keep_value);
        var new_size = self.oldest;
        var p = self.size;
        while (p > self.oldest) {
            p -= 1;
            if ((try self.j().read(p)).eql(target)) {
                new_size = p + 1;
                break;
            }
        }
        try self.j().sync();
        try self.reopen(new_size);
        try testing.expectEqual(new_size, self.size);
    }

    fn init_at_size(self: *State, size_new: u64) !void {
        self.j().deinit();
        self.journal = null;
        const storage = self.storage.interface();
        if (Journal.init_at_size(gpa, storage, self.cfg(), size_new)) |journal| {
            self.journal = journal;
            self.model.clearRetainingCapacity();
            try testing.expectEqual(size_new, journal.size());
        } else |err| {
            // `u64::MAX` is rejected before any reset is staged; the old state survives.
            if (err != error.SizeOverflow) return err;
            try testing.expectEqual(std.math.maxInt(u64), size_new);
            self.journal = try Journal.init(gpa, storage, self.cfg());
        }
        self.observe();
    }

    /// Runs one operation; returns false once the journal is destroyed.
    fn run(self: *State, operation: Operation, draws: Draws) !bool {
        switch (operation) {
            .append => {
                const item = digest(draws.value(u64));
                try self.append(&.{&.{item}});
            },
            .read => try self.read(self.draw_position(draws)),
            .try_read_sync => try self.read(self.draw_position(draws)),
            .read_many => try self.read_many(draws),
            .size => try testing.expectEqual(self.size, self.j().size()),
            .bounds => try testing.expectEqual(
                contiguous.Bounds{ .start = self.oldest, .end = self.size },
                self.j().get_bounds(),
            ),
            .pruning_boundary => try testing.expectEqual(self.oldest, self.j().pruning_boundary()),
            .sync => try self.j().sync(),
            .multiple_sync => for (0..3) |_| try self.j().sync(),
            .replay => try self.replay(draws),
            .restart => try self.reopen(null),
            .destroy => {
                var journal = self.journal.?;
                self.journal = null;
                try journal.destroy();
                return false;
            },
            else => try self.run_resizing(operation, draws),
        }
        return true;
    }

    fn run_resizing(self: *State, operation: Operation, draws: Draws) !void {
        switch (operation) {
            .append_many => try self.append_counted(draws.index(append_many_max + 1), 0, false),
            .append_nested => {
                const count_a = draws.index(append_many_max + 1);
                try self.append_counted(count_a, draws.index(append_many_max + 1), true);
            },
            .reopen_at_most => {
                const size_new = draws.value(u64) % (self.size +| 2);
                if (size_new > self.size or size_new < self.oldest) return;
                try self.j().sync();
                try self.reopen(size_new);
                try testing.expectEqual(size_new, self.size);
            },
            .prune => {
                const min = draws.value(u64) % (self.size +| 2);
                if (min > self.size) return;
                _ = try self.j().prune(min);
                self.observe();
            },
            .reopen_matching => try self.reopen_matching(draws.value(u64) % (self.next_value + 1)),
            .init_at_size => try self.init_at_size(boundary_size(draws)),
            else => unreachable, // Proof: `run` handles every other operation.
        }
    }
};

fn fuzz_operations(_: void, smith: *std.testing.Smith) anyerror!void {
    const draws: Draws = .init(smith);
    var state: State = .{
        .storage = .init(gpa),
        .cache_ref = try .init(gpa, 57, 1),
    };
    defer state.deinit();
    state.journal = try Journal.init(gpa, state.storage.interface(), state.cfg());
    const steps = draws.range_at_most(usize, 1, operations_max);
    for (0..steps) |_| {
        if (!try state.run(draws.value(Operation), draws)) return;
        try testing.expectEqual(state.size, state.j().size());
        try testing.expectEqual(state.oldest, state.j().get_bounds().start);
    }
}

// Seeded inputs in `zig build test`, then `std.testing.fuzz` under `--fuzz`.
test "fuzz journal fixed operations (seeded)" {
    try codec.fuzz.run({}, fuzz_operations, 0x6a6f75726e616c66, 100);
}
