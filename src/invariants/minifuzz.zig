//! Simple fuzzing harness for in-module tests (port of commonware's `minifuzz`).
//!
//! ```zig
//! try minifuzz.run(testing.allocator, {}, struct {
//!     fn body(_: void, u: *minifuzz.Unstructured) !void {
//!         const x = try u.arbitrary(u32);
//!         const y = try u.arbitrary(u32);
//!         try testing.expect(x +% y >= x or x > 1000);
//!     }
//! }.body);
//! ```
//!
//! The body draws its input from an `Unstructured` and reports a property violation by
//! returning an error (Zig cannot catch panics, so use `std.testing.expect*`, not
//! `assert`). Returning `error.NotEnoughData` asks for a longer input and
//! `error.IncorrectFormat` rejects the input; neither counts as a try. Any other error is a
//! failure: `run` prints `failure (MINIFUZZ_BRANCH = 0x...)` and returns the error.
//! Replay that exact failure with `Builder.with_reproduce("0x...")`, or for every minifuzz
//! test at once with `zig build test -Dminifuzz-branch=0x...` (commonware reads the
//! `MINIFUZZ_BRANCH` environment variable instead; library code here never reads it).
//!
//! Like an external fuzzer, minifuzz turns random bytes into inputs, so tests read like
//! property tests: consider the invariants the code must satisfy, not single examples.
//! It uses no coverage feedback, but it grows, mutates, and trims its input buffer with
//! the same strategies and the same ChaCha8 stream as commonware, so a branch token names
//! the same byte sequences in both.
//!
//! After commonware's search passes, minifuzz runs a long-input phase: as many cases as the
//! search had tries (`long_cases_min` to `long_cases_max`), each a fresh ChaCha8 buffer of
//! 128, 512, or 2048 bytes in turn. Each branch of the search starts again from 8 bytes and
//! branch `k` yields `k + 1` samples, so a search of a few dozen tries never sees more than
//! about 30 bytes, and a body whose generator pads with zeros (like `arbitrary`) never asks
//! for more: such a body would reach only its first action or two. A long case prints a
//! token like any failure (its `size` has `long_input_bit` set), so it replays the same way.
//! This phase is zigware's addition; the search before it is byte-for-byte commonware's.
//!
//! Deviations from commonware, all forced by Zig: the default search bound is a case count
//! (`default_search_limit` times `-Dfuzz-soak`; a soaked test build with
//! `-Dfuzz-soak-budget-s` stops a target after its unsoaked cases once that many seconds
//! passed) rather than ten seconds, since time needs an
//! `std.Io` (`with_search_time` takes one); the default seed is `-Dfuzz-seed` rather than
//! an OS random seed; and `run` stays silent when it finds nothing (`search` returns the
//! final branch).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ChaCha8 = std.crypto.stream.chacha.ChaCha8With64BitNonce;
const builtin = @import("builtin");
const build_options = @import("build_options");
const formatting = @import("formatting");
const unstructured = @import("unstructured.zig");

pub const Unstructured = unstructured.Unstructured;
pub const Error = unstructured.Error;

/// The name commonware prints in front of a failing branch token.
pub const env_var = "MINIFUZZ_BRANCH";

/// Cases run by a default `Builder`, before scaling by `-Dfuzz-soak`.
pub const default_search_limit: u64 = 10_000;

/// `Branch.size` with this bit names long-input case `size & ~long_input_bit` (commonware's
/// sizes count samples and never get near it).
pub const long_input_bit: u32 = 1 << 31;
/// Bounds on the long-input cases after a search, which runs as many as it had tries.
pub const long_cases_min: u64 = 1;
pub const long_cases_max: u64 = 256;
/// The lengths of the long-input cases, in turn.
const long_input_lens = [_]usize{ 128, 512, 2048 };
/// Mixed into a long-input case's ChaCha8 seed ("long").
const long_input_salt: u64 = 0x6c6f_6e67;

/// A point in the search: the seed, a thread (the current ChaCha8 stream), and a size (how
/// many samples the stream yields before the search moves to the next thread).
pub const Branch = struct {
    seed: u32,
    thread: u32,
    size: u32,

    pub fn init(seed: u64) Branch {
        return .{ .seed = @truncate(seed >> 32), .thread = @truncate(seed), .size = 0 };
    }

    /// Parses a `0x` + 24 hex digit token; null if it is not one.
    pub fn parse(token: []const u8) ?Branch {
        var memory: [64]u8 = undefined;
        var fixed: std.heap.FixedBufferAllocator = .init(&memory);
        const decoded = formatting.from_hex(fixed.allocator(), token) catch return null;
        const bytes = decoded orelse return null;
        if (bytes.len != 12) return null;
        return .{
            .seed = std.mem.readInt(u32, bytes[0..4], .big),
            .thread = std.mem.readInt(u32, bytes[4..8], .big),
            .size = std.mem.readInt(u32, bytes[8..12], .big),
        };
    }

    pub fn next(self: Branch) Branch {
        return .{ .seed = self.seed, .thread = self.thread +% 1, .size = self.size +| 1 };
    }

    /// Long-input case `index` of a search that started at `start`.
    pub fn long(start: Branch, index: u32) Branch {
        assert(index < long_input_bit);
        return .{ .seed = start.seed, .thread = start.thread, .size = long_input_bit | index };
    }

    pub fn is_long(self: Branch) bool {
        return self.size & long_input_bit != 0;
    }

    /// The input length of a long-input case.
    fn long_len(self: Branch) usize {
        assert(self.is_long());
        const index = self.size & ~long_input_bit;
        return long_input_lens[index % long_input_lens.len];
    }

    pub fn rng_seed(self: Branch) u64 {
        return @as(u64, self.seed) << 32 | self.thread;
    }

    pub fn format(self: Branch, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print("0x{x:0>8}{x:0>8}{x:0>8}", .{ self.seed, self.thread, self.size });
    }
};

/// rand_chacha 0.10's `ChaCha8Rng::seed_from_u64`: a word stream over the ChaCha8
/// keystream (64-bit counter, zero nonce). `fill_bytes` discards the rest of a partly used
/// word, as `BlockRng` does.
const Rng = struct {
    key: [32]u8,
    block_index: u64 = 0,
    block: [64]u8 = undefined,
    /// Byte offset into `block`, always word-aligned; 64 means the block is used up.
    offset: usize = 64,

    fn init(seed: u64) Rng {
        // rand_core's seed_from_u64: PCG32 outputs fill the key.
        var state = seed;
        var key: [32]u8 = undefined;
        for (0..8) |index| {
            state = state *% 0x5851_f42d_4c95_7f2d +% 0xa176_54e4_6fbe_17f3;
            const xorshifted: u32 = @truncate(((state >> 18) ^ state) >> 27);
            const rotation: u5 = @intCast(state >> 59);
            const word = std.math.rotr(u32, xorshifted, rotation);
            std.mem.writeInt(u32, key[index * 4 ..][0..4], word, .little);
        }
        assert(state != seed);
        return .{ .key = key };
    }

    fn refill(self: *Rng) void {
        assert(self.offset == 64);
        ChaCha8.stream(&self.block, self.block_index, self.key, @splat(0));
        self.block_index += 1;
        self.offset = 0;
    }

    fn next_u32(self: *Rng) u32 {
        if (self.offset == 64) self.refill();
        assert(self.offset % 4 == 0);
        const word = std.mem.readInt(u32, self.block[self.offset..][0..4], .little);
        self.offset += 4;
        return word;
    }

    fn fill_bytes(self: *Rng, out: []u8) void {
        var written: usize = 0;
        while (written < out.len) {
            if (self.offset == 64) self.refill();
            const count = @min(out.len - written, 64 - self.offset);
            @memcpy(out[written..][0..count], self.block[self.offset..][0..count]);
            written += count;
            self.offset += count;
        }
        self.offset = std.mem.alignForward(usize, self.offset, 4);
        assert(written == out.len);
        assert(self.offset <= 64);
    }
};

const divisor: usize = 1000;
const add_bytes_coefficients = [3]usize{ 100, 1000, 8000 };
const modify_prefix_numerator: usize = 100;
const modify_prefix_min_bytes: usize = 8;
const copy_portion_numerator: usize = 50;
const strategy_weights = [6]u32{ 200, 20, 10, 50, 10, 200 };
/// Unforced growth stops at 8 KiB.
const buffer_size_max: usize = 1 << 13;

/// Produces the inputs of one branch: grows, mutates, and trims a byte buffer.
const Sampler = struct {
    rng: Rng,
    buffer: std.ArrayList(u8),
    count: i64,
    last_bytes_used: usize = 0,

    fn init(gpa: Allocator, branch: Branch) Allocator.Error!Sampler {
        const buffer: std.ArrayList(u8) = try .initCapacity(gpa, 1 << 16);
        assert(buffer.items.len == 0);
        return .{ .rng = .init(branch.rng_seed()), .buffer = buffer, .count = branch.size };
    }

    fn deinit(self: *Sampler, gpa: Allocator) void {
        self.buffer.deinit(gpa);
        self.* = undefined;
    }

    /// Restarts on `branch`, keeping the buffer's memory.
    fn switch_to(self: *Sampler, branch: Branch) void {
        self.buffer.clearRetainingCapacity();
        self.rng = .init(branch.rng_seed());
        self.count = branch.size;
        self.last_bytes_used = 0;
        assert(self.buffer.items.len == 0);
    }

    fn add_bytes(self: *Sampler, gpa: Allocator, force: bool) Allocator.Error!void {
        const size = self.buffer.items.len;
        if (!force and size >= buffer_size_max) return;
        const c = add_bytes_coefficients;
        const growth = (c[0] *| size *| size +| c[1] *| size +| c[2]) / divisor;
        const size_new = if (force) size + growth else @min(size + growth, buffer_size_max);
        assert(size_new >= size);
        try self.buffer.resize(gpa, size_new);
        self.rng.fill_bytes(self.buffer.items[size..]);
    }

    fn modify_prefix(self: *Sampler) void {
        const items = self.buffer.items;
        if (items.len == 0) return;
        const by_proportion = items.len * modify_prefix_numerator / divisor;
        const prefix_len = @min(@max(by_proportion, modify_prefix_min_bytes), items.len);
        assert(prefix_len > 0);
        self.rng.fill_bytes(items[0..prefix_len]);
    }

    fn copy_portion(self: *Sampler) void {
        const items = self.buffer.items;
        if (items.len < 2) return;
        const by_proportion = @max(items.len * copy_portion_numerator / divisor, 1);
        const portion = @min(by_proportion, items.len / 2);
        const source = self.rng.next_u32() % (items.len - portion + 1);
        const target = self.rng.next_u32() % (items.len - portion + 1);
        assert(source + portion <= items.len and target + portion <= items.len);
        @memmove(items[target..][0..portion], items[source..][0..portion]);
    }

    /// A random non-empty run past the first `modify_prefix_min_bytes`, or null.
    fn pick_tail_run(self: *Sampler) ?[]u8 {
        const items = self.buffer.items;
        const prefix_len = @min(modify_prefix_min_bytes, items.len);
        if (prefix_len >= items.len) return null;
        const start = prefix_len + self.rng.next_u32() % (items.len - prefix_len);
        const len = @max(self.rng.next_u32() % (items.len - start), 1);
        assert(start + len <= items.len);
        return items[start..][0..len];
    }

    fn clear_non_prefix(self: *Sampler) void {
        const span = self.pick_tail_run() orelse return;
        @memset(span, 0);
    }

    fn arithmetic_non_prefix(self: *Sampler) void {
        const span = self.pick_tail_run() orelse return;
        const delta: u8 = @truncate(self.rng.next_u32());
        for (span) |*byte| byte.* +%= delta;
    }

    fn pick_strategy(self: *Sampler) u32 {
        var weights = strategy_weights;
        // Plenty of unused bytes: grow less (add_bytes is indices 4 and 5).
        const unused = self.buffer.items.len -| self.last_bytes_used;
        if (unused > 64) {
            weights[4] = 0;
            weights[5] = 0;
        } else if (unused > 16) {
            weights[4] /= 4;
            weights[5] /= 4;
        }
        // A small buffer favors modify_prefix.
        if (self.buffer.items.len <= 16) weights[0] *|= 2;
        var total: u32 = 0;
        for (weights) |weight| total += weight;
        assert(total > 0); // Proof: weights 1 to 3 are never reduced.
        var choice = self.rng.next_u32() % total;
        for (weights, 0..) |weight, index| {
            if (choice < weight) return @intCast(index);
            choice -= weight;
        }
        unreachable; // Proof: choice < total, the sum of the weights.
    }

    /// The next input of this branch, or null once the branch is exhausted.
    fn next(self: *Sampler, gpa: Allocator) Allocator.Error!?[]const u8 {
        if (self.count < 0) return null;
        self.count -= 1;
        if (self.buffer.items.len == 0) {
            try self.add_bytes(gpa, false);
        } else switch (self.pick_strategy()) {
            0 => self.modify_prefix(),
            1 => self.copy_portion(),
            2 => self.clear_non_prefix(),
            3 => self.arithmetic_non_prefix(),
            else => try self.add_bytes(gpa, false),
        }
        assert(self.buffer.items.len > 0);
        return self.buffer.items;
    }
};

/// How a search ended.
pub const Outcome = union(enum) {
    /// No failure within the search bound; the branch the search stopped on.
    passed: Branch,
    failed: Failure,
};

pub const Failure = struct {
    /// Replays this failure through `Builder.with_reproduce`.
    branch: Branch,
    /// The error the body returned.
    err: anyerror,
    /// The body failed while drawing its input (`EmptyChoose`), not on a property.
    sampling: bool,
};

const SearchBound = union(enum) {
    limit: u64,
    time: struct { io: Io, duration: Io.Duration },
};

/// Configures and runs a fuzz test.
pub const Builder = struct {
    search_bound: SearchBound = .{ .limit = default_search_limit * build_options.fuzz_soak },
    min_iterations: u64 = 100,
    seed: ?u64 = null,
    reproduce: ?Branch = null,

    /// Sets the RNG seed for deterministic fuzzing.
    pub fn with_seed(self: Builder, seed: u64) Builder {
        var builder = self;
        builder.seed = seed;
        return builder;
    }

    /// Limits the fuzzer to a fixed number of test cases (and lowers `min_iterations` to it).
    pub fn with_search_limit(self: Builder, search_limit: u64) Builder {
        var builder = self;
        builder.search_bound = .{ .limit = search_limit };
        builder.min_iterations = @min(self.min_iterations, search_limit);
        return builder;
    }

    /// Limits the fuzzer to a duration, measured on `io`'s awake clock.
    pub fn with_search_time(self: Builder, io: Io, duration: Io.Duration) Builder {
        assert(duration.nanoseconds >= 0);
        var builder = self;
        builder.search_bound = .{ .time = .{ .io = io, .duration = duration } };
        return builder;
    }

    /// Sets the minimum number of tries, even past the search time.
    pub fn with_min_iterations(self: Builder, min_iterations: u64) Builder {
        var builder = self;
        builder.min_iterations = min_iterations;
        return builder;
    }

    /// Replays a failure from its token (the `MINIFUZZ_BRANCH = 0x...` output).
    pub fn with_reproduce(self: Builder, token: []const u8) Builder {
        var builder = self;
        builder.reproduce = Branch.parse(token) orelse
            @panic("invalid MINIFUZZ_BRANCH hex format (expected 24 hex chars)");
        return builder;
    }

    /// The first branch: the reproduce token, the seed, `-Dminifuzz-branch`, then
    /// `-Dfuzz-seed`.
    fn start(self: Builder) Branch {
        if (self.reproduce) |branch| return branch;
        if (self.seed) |seed| return .init(seed);
        return Branch.parse(build_options.minifuzz_branch) orelse
            .init(build_options.fuzz_seed);
    }

    /// Runs the fuzz test. On a failure prints the branch token and returns the body's
    /// error. `body` is `fn (@TypeOf(context), *Unstructured) !void`.
    pub fn run(self: Builder, gpa: Allocator, context: anytype, body: anytype) anyerror!void {
        switch (try self.search(gpa, context, body)) {
            .passed => {},
            .failed => |failure| {
                std.debug.print("failure ({s} = {f}){s}: {t}\n", .{
                    env_var,
                    failure.branch,
                    if (failure.sampling) " (while sampling)" else "",
                    failure.err,
                });
                return failure.err;
            },
        }
    }

    /// Like `run`, but returns how the search ended instead of printing.
    pub fn search(self: Builder, gpa: Allocator, context: anytype, body: anytype) !Outcome {
        const first = self.start();
        if (first.is_long()) {
            // Replaying a long-input case: run just that case.
            const failure = try search_long(gpa, context, body, first, 1, null);
            return if (failure) |found| .{ .failed = found } else .{ .passed = first };
        }
        var search_state: Search = .init(self);
        assert(std.meta.eql(search_state.branch, first));
        const outcome = try search_samples(gpa, context, body, &search_state);
        if (outcome == .failed) return outcome;
        const cases = std.math.clamp(search_state.tries, long_cases_min, long_cases_max);
        const failure = try search_long(gpa, context, body, .long(first, 0), cases, &search_state);
        return if (failure) |found| .{ .failed = found } else outcome;
    }
};

/// commonware's search: samples from each branch in turn until the search bound.
fn search_samples(
    gpa: Allocator,
    context: anytype,
    body: anytype,
    search_state: *Search,
) !Outcome {
    assert(search_state.tries == 0);
    var sampler: Sampler = try .init(gpa, search_state.branch);
    defer sampler.deinit(gpa);
    // Bounded by the search limit or deadline once `min_iterations` tries pass.
    while (true) {
        while (try sampler.next(gpa)) |sample| {
            if (search_state.done()) return .{ .passed = search_state.branch };
            var u: Unstructured = .init(sample);
            const started = search_state.now();
            const result = body(context, &u);
            search_state.record_case(started);
            const used = sample.len - u.len();
            if (result) |_| {
                sampler.last_bytes_used = used;
                search_state.tries += 1;
            } else |err| {
                const any: anyerror = err;
                if (any == error.NotEnoughData) {
                    try sampler.add_bytes(gpa, true);
                } else if (any == error.IncorrectFormat) {
                    sampler.last_bytes_used = used;
                } else return .{ .failed = .{
                    .branch = search_state.branch,
                    .err = any,
                    .sampling = any == error.EmptyChoose,
                } };
            }
        }
        search_state.branch = search_state.branch.next();
        sampler.switch_to(search_state.branch);
    }
}

/// Runs `cases` long-input cases from `first`, each a fresh ChaCha8 buffer; returns the
/// first failure. Inputs that run short or are rejected are skipped. A soaked search stops
/// after its unsoaked share of cases once its soak budget is spent.
fn search_long(
    gpa: Allocator,
    context: anytype,
    body: anytype,
    first: Branch,
    cases: u64,
    search_state: ?*const Search,
) !?Failure {
    assert(first.is_long());
    assert(cases >= 1 and cases <= long_cases_max);
    const cases_unsoaked = if (search_state) |state| state.long_cases_unsoaked() else cases;
    const buffer = try gpa.alloc(u8, std.mem.max(usize, &long_input_lens));
    defer gpa.free(buffer);
    var branch = first;
    for (0..cases) |case| {
        if (case >= cases_unsoaked and search_state.?.budget_spent()) break;
        if (case > 0) branch = .long(first, (branch.size & ~long_input_bit) + 1);
        const input = buffer[0..branch.long_len()];
        // Mixed so the stream differs from the search branch with the same seed.
        var rng: Rng = .init((branch.rng_seed() ^ long_input_salt) +% branch.size);
        rng.fill_bytes(input);
        var u: Unstructured = .init(input);
        body(context, &u) catch |err| {
            const any: anyerror = err;
            if (any == error.NotEnoughData or any == error.IncorrectFormat) continue;
            return .{ .branch = branch, .err = any, .sampling = any == error.EmptyChoose };
        };
    }
    assert(branch.is_long());
    return null;
}

/// The progress of one `Builder.search`.
const Search = struct {
    builder: Builder,
    branch: Branch,
    tries: u64 = 0,
    deadline_ns: i96 = 0,
    /// The longest case so far: the search stops before a case unlikely to finish in time.
    longest_case_ns: i96 = 0,
    /// When the search started, on the test clock, if a soak budget applies.
    soak_started_ns: i96 = 0,

    fn init(builder: Builder) Search {
        var search: Search = .{ .builder = builder, .branch = builder.start() };
        if (soak_budgeted) search.soak_started_ns = soak_now();
        switch (builder.search_bound) {
            .limit => {},
            .time => |time| {
                search.deadline_ns = search.now() + time.duration.nanoseconds;
            },
        }
        assert(search.tries == 0);
        return search;
    }

    /// Nanoseconds on the awake clock, or zero when the search has no time bound.
    fn now(self: *const Search) i96 {
        return switch (self.builder.search_bound) {
            .limit => 0,
            .time => |time| Io.Clock.awake.now(time.io).nanoseconds,
        };
    }

    fn record_case(self: *Search, started_ns: i96) void {
        const elapsed_ns = self.now() - started_ns;
        assert(elapsed_ns >= 0);
        self.longest_case_ns = @max(self.longest_case_ns, elapsed_ns);
    }

    fn done(self: *const Search) bool {
        // Before `min_iterations`: `with_search_limit` sets it to the whole soaked limit.
        if (self.soak_spent()) return true;
        if (self.tries < self.builder.min_iterations) return false;
        return switch (self.builder.search_bound) {
            .limit => |limit| self.tries >= limit,
            .time => self.now() + self.longest_case_ns >= self.deadline_ns,
        };
    }

    /// The cases an unsoaked build of a case-bounded search runs: the share a soaked search
    /// always runs before its budget can stop it.
    fn tries_unsoaked(self: *const Search) u64 {
        const limit = self.builder.search_bound.limit;
        assert(limit > 0);
        return @max(1, limit / build_options.fuzz_soak);
    }

    /// The long-input cases an unsoaked build runs (as `search` counts them).
    fn long_cases_unsoaked(self: *const Search) u64 {
        if (!soak_budgeted or self.builder.search_bound != .limit) return long_cases_max;
        return std.math.clamp(self.tries_unsoaked(), long_cases_min, long_cases_max);
    }

    /// Whether a soaked, case-bounded search ran its unsoaked share of cases and then used
    /// up `-Dfuzz-soak-budget-s`, so one slow target cannot take the whole soak job.
    fn soak_spent(self: *const Search) bool {
        if (!soak_budgeted or self.builder.search_bound != .limit) return false;
        if (self.tries < self.tries_unsoaked()) return false;
        return self.budget_spent();
    }

    /// Whether `-Dfuzz-soak-budget-s` passed since the search started.
    fn budget_spent(self: *const Search) bool {
        if (!soak_budgeted) return false;
        const budget_ns: i96 = @as(i96, build_options.fuzz_soak_budget_s) * std.time.ns_per_s;
        const spent_ns = soak_now() - self.soak_started_ns;
        assert(spent_ns >= 0);
        return spent_ns >= budget_ns;
    }
};

/// A soak budget applies to tests of a soaked build with `-Dfuzz-soak-budget-s`.
const soak_budgeted = builtin.is_test and build_options.fuzz_soak > 1 and
    build_options.fuzz_soak_budget_s > 0;

/// The test clock: only soaked test builds read it, to bound a search's wall time.
fn soak_now() i96 {
    comptime assert(soak_budgeted);
    return Io.Clock.awake.now(std.testing.io).nanoseconds;
}

/// Runs a fuzz test with the default `Builder`.
pub fn run(gpa: Allocator, context: anytype, body: anytype) anyerror!void {
    return Builder.run(.{}, gpa, context, body);
}

const testing = std.testing;

fn fnv1a(bytes: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (bytes) |byte| hash = (hash ^ byte) *% 0x100000001b3;
    return hash;
}

test "Rng matches rand_chacha ChaCha8Rng::seed_from_u64" {
    // Expected values from rand_chacha 0.10.0 / rand_core 0.10.1.
    var rng: Rng = .init(42);
    var bytes: [7]u8 = undefined;
    rng.fill_bytes(&bytes);
    try testing.expectEqualSlices(u8, &.{ 161, 91, 93, 57, 181, 191, 144 }, &bytes);
    try testing.expectEqual(@as(u32, 628724104), rng.next_u32());
    const low = rng.next_u32();
    const high = rng.next_u32();
    try testing.expectEqual(@as(u64, 14246666336075071430), @as(u64, high) << 32 | low);
}

test "Sampler matches commonware's sample stream" {
    // Expected values from commonware's Sampler, driven the same way: forced growth after
    // samples 3 and 30, otherwise `set_bytes_used(len * (i % 3) / 2)`; FNV-1a of each sample.
    const branch: Branch = .{ .seed = 0x01234567, .thread = 0x89abcdef, .size = 60 };
    var sampler: Sampler = try .init(testing.allocator, branch);
    defer sampler.deinit(testing.allocator);
    var hashes: [61][8]u8 = undefined;
    var count: usize = 0;
    while (try sampler.next(testing.allocator)) |sample| : (count += 1) {
        std.mem.writeInt(u64, &hashes[count], fnv1a(sample), .little);
        if (count == 3 or count == 30) {
            try sampler.add_bytes(testing.allocator, true);
        } else {
            sampler.last_bytes_used = sample.len * (count % 3) / 2;
        }
    }
    try testing.expectEqual(@as(usize, 61), count);
    const last = std.mem.readInt(u64, &hashes[60], .little);
    try testing.expectEqual(@as(u64, 0xef5e5cc419388551), last);
    try testing.expectEqual(@as(u64, 0x79427f26a746cf17), fnv1a(std.mem.asBytes(&hashes)));
}
