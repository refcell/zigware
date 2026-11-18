//! The `qmdb_current_mmb_prune_grow` fuzz target (commonware `storage/fuzz`): prune/grow
//! divergence of an MMB `current` database. Commits of one hot key at a time drive the floor
//! until pruning removes bitmap chunks, then a fixed post-prune growth window and the drawn
//! updates, bursts, deletes, commits, and reopens run against a pruned database and an
//! unpruned reference fed the same writes. After every commit both must agree on the size,
//! the ops root, and the canonical root; a reopen of the pruned database must keep its roots,
//! bounds, and pruned bits; and at the end every key must match the reference and the model.
//!
//! Each database has its own storage (commonware gives them separate partitions) on
//! `current`'s test harness sizes.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const index = @import("../../index/mod.zig");
const translator = @import("../../translator.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const value = @import("../value.zig");
const any = @import("../any/mod.zig");
const current = @import("mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
/// A tiny key space forces key updates, which raise the floor.
const Key = utils.sequence.FixedBytes(1);

const max_operations = 100;
const max_actual_writes = 64;
const logical_key_space: u8 = 8;
const post_prune_window_steps: u8 = 127;
/// Past one 256-operation bitmap chunk, with headroom, before pruning must have begun.
const bootstrap_commits: u16 = 320;

const Db = Db: {
    const E = value.Fixed(Digest);
    const Journal = fixed.Journal(any.operation.Unordered(merkle.mmb.Family, Key, E));
    const U = any.operation.update.Unordered(Key, E);
    const I = index.unordered.Index(translator.TwoCap, u64);
    break :Db current.Db(merkle.mmb.Family, U, Journal, I, support.Sha256, 32);
};

/// The live value of each logical key, or null.
const State = [logical_key_space]?[32]u8;

const Operation = union(enum) {
    update: struct { key: u8, value: [32]u8 },
    update_burst: struct { key: u8, value: [32]u8, count: u8 },
    delete: u8,
    delete_burst: struct { key: u8, count: u8 },
    commit,
    close_reopen,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        const tag = reader.below(7);
        const key: u8 = @intCast(reader.below(logical_key_space));
        return switch (tag) {
            0 => .{ .update = .{ .key = key, .value = draw_value(reader) } },
            1 => .{ .update_burst = .{
                .key = key,
                .value = draw_value(reader),
                .count = @intCast(1 + reader.below(8)),
            } },
            2 => .{ .delete = key },
            3 => .{ .delete_burst = .{ .key = key, .count = @intCast(1 + reader.below(8)) } },
            // Commonware's `Root` commits too.
            4, 5 => .commit,
            6 => .close_reopen,
            else => unreachable, // Proof: `below(7)` is in 0..7.
        };
    }
};

fn draw_value(reader: *fuzz_bytes.Reader) [32]u8 {
    var bytes: [32]u8 = undefined;
    for (&bytes) |*b| b.* = reader.int(u8);
    return bytes;
}

fn burst_key(key: u8, offset: u8) u8 {
    const result: u8 = @intCast((@as(u16, key) + offset) % logical_key_space);
    assert(result < logical_key_space);
    return result;
}

fn burst_value(bytes: [32]u8, offset: u8) [32]u8 {
    var result = bytes;
    result[31] +%= offset;
    return result;
}

const Write = struct { key: u8, value: ?[32]u8 };

const Run = struct {
    pruned_harness: support.Harness,
    reference_harness: support.Harness,
    pruned: Db,
    reference: Db,
    /// The state after the queued writes.
    expected: State = @splat(null),
    /// The state after the last commit.
    committed: State = @splat(null),
    pending: std.ArrayList(Write) = .empty,
    issued_writes: usize = 0,

    fn init(self: *Run) !void {
        self.pruned_harness = try .init(gpa);
        errdefer self.pruned_harness.deinit();
        self.reference_harness = try .init(gpa);
        errdefer self.reference_harness.deinit();
        self.pruned = try self.pruned_harness.open(Db, null);
        errdefer self.pruned.deinit();
        self.reference = try self.reference_harness.open(Db, null);
        self.expected = @splat(null);
        self.committed = @splat(null);
        self.pending = .empty;
        self.issued_writes = 0;
        assert(self.pruned.root().eql(self.reference.root()));
    }

    fn deinit(self: *Run) void {
        self.pending.deinit(gpa);
        self.reference.deinit();
        self.pruned.deinit();
        self.reference_harness.deinit();
        self.pruned_harness.deinit();
    }

    fn pruned_bits(self: *const Run) u64 {
        const bits = self.pruned.any.bitmap.pruned_chunks() * Db.chunk_bytes * 8;
        assert(bits <= self.pruned.bounds().end);
        return bits;
    }

    fn queue(self: *Run, key: u8, bytes: ?[32]u8) !void {
        assert(key < logical_key_space);
        try self.pending.append(gpa, .{ .key = key, .value = bytes });
        self.expected[key] = bytes;
    }

    fn expect_matches_reference(self: *Run) !void {
        try testing.expectEqual(self.reference.bounds().end, self.pruned.bounds().end);
        try testing.expect(self.pruned.ops_root().eql(self.reference.ops_root()));
        try testing.expect(self.pruned.root().eql(self.reference.root()));
    }

    fn apply(db: *Db, writes: []const Write) !void {
        var batch = try db.new_batch();
        const merkleized = merkleized: {
            errdefer batch.deinit();
            for (writes) |w| {
                const v: ?Digest = if (w.value) |bytes| .{ .bytes = bytes } else null;
                try batch.write(.init(.{w.key}), v);
            }
            break :merkleized try batch.merkleize(db);
        };
        defer merkleized.release();
        try db.apply_batch(merkleized);
        try db.commit();
        assert(db.root().eql(merkleized.root()));
    }

    /// Commits the queued writes to both databases, then prunes the pruned one to its sync
    /// boundary; both must agree after each step.
    fn commit_and_prune(self: *Run) !void {
        if (self.pending.items.len > 0) {
            try apply(&self.pruned, self.pending.items);
            try apply(&self.reference, self.pending.items);
            self.pending.clearRetainingCapacity();
            self.committed = self.expected;
        }
        try self.expect_matches_reference();
        try self.pruned.prune(self.pruned.sync_boundary());
        try self.expect_matches_reference();
        assert(self.pending.items.len == 0);
    }

    fn reopen(self: *Run) !void {
        const root = self.pruned.root();
        const ops_root = self.pruned.ops_root();
        const bounds = self.pruned.bounds();
        const bits = self.pruned_bits();
        self.pruned.deinit();
        self.pruned = try self.pruned_harness.open(Db, null);
        try testing.expect(self.pruned.root().eql(root));
        try testing.expect(self.pruned.ops_root().eql(ops_root));
        try testing.expectEqual(bounds, self.pruned.bounds());
        try testing.expectEqual(bits, self.pruned_bits());
        try self.expect_matches_reference();
    }

    /// Commits one hot-key write at a time until pruning removes bitmap chunks.
    fn bootstrap(self: *Run) !void {
        for (0..bootstrap_commits) |step| {
            const key: u8 = @intCast(step % logical_key_space);
            var bytes: [32]u8 = @splat(0);
            bytes[0] = 0xb0;
            bytes[1] = @truncate(step);
            bytes[31] = key;
            try self.queue(key, bytes);
            try self.commit_and_prune();
            if (self.pruned_bits() > 0) return;
        }
        return error.BootstrapDidNotPrune;
    }

    /// One write per commit, deleting live keys on odd steps, with a reopen midway.
    fn post_prune_window(self: *Run) !void {
        for (0..post_prune_window_steps) |step_index| {
            const step: u8 = @intCast(step_index);
            const key = step % logical_key_space;
            if (self.expected[key] != null and step % 2 == 1) {
                try self.queue(key, null);
            } else {
                var bytes: [32]u8 = @splat(0);
                bytes[0] = step;
                bytes[31] = key;
                try self.queue(key, bytes);
            }
            try self.commit_and_prune();
            if (step == post_prune_window_steps / 2) try self.reopen();
        }
        assert(self.pending.items.len == 0);
    }

    /// The first key from `preferred` onward (wrapping) that is live after the queued writes.
    fn find_live_key(self: *const Run, preferred: u8) ?u8 {
        for (0..logical_key_space) |offset| {
            const candidate = burst_key(preferred, @intCast(offset));
            if (self.expected[candidate] != null) return candidate;
        }
        return null;
    }

    fn apply_operation(self: *Run, operation: Operation, window_ran: *bool) !void {
        switch (operation) {
            .update => |u| if (self.issued_writes < max_actual_writes) {
                try self.queue(u.key, u.value);
                self.issued_writes += 1;
            },
            .update_burst => |u| for (0..u.count) |offset| {
                if (self.issued_writes >= max_actual_writes) break;
                const o: u8 = @intCast(offset);
                try self.queue(burst_key(u.key, o), burst_value(u.value, o));
                self.issued_writes += 1;
            },
            .delete => |k| if (self.issued_writes < max_actual_writes) {
                if (self.find_live_key(k)) |live| {
                    try self.queue(live, null);
                    self.issued_writes += 1;
                }
            },
            .delete_burst => |d| for (0..d.count) |offset| {
                if (self.issued_writes >= max_actual_writes) break;
                const live = self.find_live_key(burst_key(d.key, @intCast(offset))) orelse break;
                try self.queue(live, null);
                self.issued_writes += 1;
            },
            .commit => {
                try self.commit_and_prune();
                if (self.pruned_bits() > 0 and !window_ran.*) {
                    window_ran.* = true;
                    try self.post_prune_window();
                }
            },
            .close_reopen => {
                try self.commit_and_prune();
                try self.reopen();
            },
        }
    }

    fn expect_final(self: *Run) !void {
        try self.commit_and_prune();
        for (0..logical_key_space) |k| {
            const key: Key = .init(.{@intCast(k)});
            const got = try self.pruned.get(&key);
            const reference = try self.reference.get(&key);
            try testing.expectEqual(got == null, reference == null);
            try testing.expectEqual(self.committed[k] == null, got == null);
            if (got) |g| {
                try testing.expect(g.eql(reference.?));
                try testing.expectEqualSlices(u8, &self.committed[k].?, &g.bytes);
            }
        }
    }
};

fn run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var state: Run = undefined;
    try state.init();
    defer state.deinit();
    try state.bootstrap();
    var window_ran = false;
    const count = 1 + reader.below(max_operations);
    for (0..count) |_| try state.apply_operation(Operation.decode(&reader), &window_ran);
    try state.expect_final();
}

const input_max = 1024;

test "fuzz qmdb_current_mmb_prune_grow (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x70677277, 2, run);
}

test "fuzz qmdb_current_mmb_prune_grow" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run), .{});
}
