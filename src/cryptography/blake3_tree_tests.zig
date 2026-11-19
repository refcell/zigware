//! Tests of `Blake3.hash_across` splitting a message along the BLAKE3 tree (commonware
//! `blake3::tests::{test_hash_long_messages, test_hash_splits_long_messages}`).

const std = @import("std");
const parallel = @import("parallel");
const blake3 = @import("blake3.zig");
const tree = @import("blake3_tree.zig");

const testing = std.testing;
const gpa = testing.allocator;
const Blake3 = blake3.Blake3;
const Digest = blake3.Digest;
const Explorer = parallel.mocks.Explorer;
const chunk_len = tree.chunk_len;
const subtree_len = tree.subtree_len_min;
const split_len = tree.split_len_min;

const total_len = (1 << 20) + 5000;

/// Messages around multiples of the minimum subtree and around the split length.
const lengths = [_]usize{
    0,                                   1,                           chunk_len,
    chunk_len + 1,                       3 * chunk_len + 7,           subtree_len - 1,
    subtree_len,                         subtree_len + 1,             subtree_len + chunk_len,
    2 * subtree_len - 1,                 2 * subtree_len,             2 * subtree_len + 1,
    2 * subtree_len + 3 * chunk_len + 7, 3 * subtree_len + 17,        split_len - 1,
    split_len,                           split_len + subtree_len + 1, 3 * split_len + 17,
    total_len,
};

fn random_data() ![]u8 {
    const data = try gpa.alloc(u8, total_len);
    var random = std.Random.DefaultPrng.init(0);
    random.random().bytes(data);
    return data;
}

fn reference(message: []const u8) Digest {
    var out: Digest = undefined;
    blake3.Core.hash(message, &out.bytes, .{});
    return out;
}

/// The message given whole, cut inside chunks and subtrees, padded with empty parts, and
/// paged into 1000-byte parts.
const Splits = struct {
    whole: [1][]const u8,
    three: [3][]const u8,
    padded: [3][]const u8,
    pages: []const []const u8,

    fn init(message: []const u8, pages: [][]const u8) Splits {
        const a = message.len / 3;
        const b = a + @min(subtree_len, message.len - a);
        var count: usize = 0;
        var offset: usize = 0;
        while (offset < message.len) : (count += 1) {
            const end = @min(message.len, offset + 1000);
            pages[count] = message[offset..end];
            offset = end;
        }
        return .{
            .whole = .{message},
            .three = .{ message[0..a], message[a..b], message[b..] },
            .padded = .{ "", message, "" },
            .pages = pages[0..count],
        };
    }

    fn all(splits: *const Splits) [4][]const []const u8 {
        return .{ &splits.whole, &splits.three, &splits.padded, splits.pages };
    }
};

const Across = struct {
    parts: []const []const u8,

    pub fn run(op: Across, explorer: Explorer) Digest {
        return Blake3.hash_across(op.parts, explorer);
    }

    pub fn eql(_: Across, a: Digest, b: Digest) bool {
        return a.eql(b);
    }
};

test "blake3 long messages hash to the reference digest whole, in parts, and across workers" {
    const data = try random_data();
    defer gpa.free(data);
    const pages = try gpa.alloc([]const u8, total_len / 1000 + 1);
    defer gpa.free(pages);
    for (lengths) |len| {
        const message = data[0..len];
        const expected = reference(message);
        const splits: Splits = .init(message, pages);
        for (splits.all()) |split| {
            try testing.expect(Blake3.hash(split).eql(expected));
            const across = try parallel.mocks.explore(gpa, testing.io, Across{ .parts = split });
            try testing.expect(across.eql(expected));
            if (len > chunk_len) {
                const serial = tree.hash_subtrees(split, len, parallel.sequential);
                try testing.expectEqualSlices(u8, &expected.bytes, &serial);
            }
        }
    }
}

test "blake3 a large message hashes alike at every concurrency level" {
    const data = try random_data();
    defer gpa.free(data);
    const message = data[0 .. (1 << 20) + 4097];
    const expected = reference(message);
    for ([_]u32{ 0, 1, 2, 3, 4, 8 }) |workers| {
        for ([_]usize{ 2, 8, 32 }) |planned| {
            const strategy = try parallel.mocks.pooled(gpa, testing.io, workers, planned);
            defer strategy.pool.destroy();
            try testing.expect(Blake3.hash_across(&.{message}, strategy).eql(expected));
            const pair = Blake3.hash_pair(&.{message}, &.{message[0..split_len]}, strategy);
            try testing.expect(pair[0].eql(expected));
            try testing.expect(pair[1].eql(reference(message[0..split_len])));
        }
    }
}

/// A strategy that runs every call in parallel on the calling thread and counts the
/// `map_into` rounds it is handed (commonware's job-counting worker).
const Counting = struct {
    rounds: *usize,

    pub fn parallelism(_: Counting) usize {
        return 2;
    }

    pub fn run(_: Counting, len: usize, op: anytype) @TypeOf(op.parallel()) {
        std.debug.assert(len > 0);
        return op.parallel();
    }

    pub fn map_into(counting: Counting, items: anytype, out: anytype, op: anytype) void {
        counting.rounds.* += 1;
        parallel.sequential.map_into(items, out, op);
    }

    const S = parallel.Sequential;
    pub const split = S.split;
    pub const execute = S.execute;
    pub const scratch = S.scratch;
    pub const try_run = S.try_run;
    pub const run_batches = S.run_batches;
    pub const try_run_batches = S.try_run_batches;
    pub const fold = S.fold;
    pub const fold_init = S.fold_init;
    pub const try_fold = S.try_fold;
    pub const map_init_into = S.map_init_into;
    pub const try_map_into = S.try_map_into;
    pub const map_collect = S.map_collect;
    pub const map_init_collect = S.map_init_collect;
    pub const try_map_collect = S.try_map_collect;
    pub const map_partition_collect = S.map_partition_collect;
    pub const join = S.join;
    pub const sort_by = S.sort_by;
    pub const sort_unstable_by = S.sort_unstable_by;
};

test "blake3 a message of at least the split length hashes across the strategy" {
    const data = try random_data();
    defer gpa.free(data);
    const cases = [_]struct { usize, usize }{
        .{ split_len - 1, 0 }, .{ split_len, 1 }, .{ 2 * split_len, 1 },
    };
    for (cases) |case| {
        var rounds: usize = 0;
        const message = data[0..case[0]];
        const digest = Blake3.hash_across(&.{message}, Counting{ .rounds = &rounds });
        try testing.expect(digest.eql(reference(message)));
        try testing.expectEqual(case[1], rounds);
    }
}

test "blake3 subtrees are commonware's task bound rounded down to a power of two" {
    try testing.expectEqual(16 * chunk_len, tree.subtree_len_for(split_len));
    try testing.expectEqual(16 * chunk_len, tree.subtree_len_for(2 * split_len - 1));
    try testing.expectEqual(32 * chunk_len, tree.subtree_len_for(2 * split_len));
    try testing.expectEqual(64 * chunk_len, tree.subtree_len_for(1 << 30));
}
