//! The operations of the `Strategy` interface, written once over the primitives every
//! strategy provides (see `root.zig`):
//!
//! - `parallelism()`: the parallelism the strategy plans with (1 for `Sequential`);
//! - `split(len)`: the number of chunks a fold or map over `len` items runs as (1 = serial);
//! - `execute(count, context, body)`: calls `body(context, index)` for `index` in `0..count`,
//!   possibly in parallel, and returns once every call has returned;
//! - `scratch()`: an allocator for parallel sort buffers, or null to sort serially.
//!
//! A strategy declares each operation as `pub const fold = strategy.fold;` and so on, so
//! `s.fold(items, op)` works on any strategy value.

const std = @import("std");
const assert = std.debug.assert;
const ops = @import("ops.zig");

const Range = ops.Range;
const Return = ops.Return;
const max_chunks = ops.max_chunks;

/// Runs `op.serial()` or `op.parallel()`, which must return the same type. A strategy without
/// parallelism always runs the serial body.
fn run_on(strategy: anytype, len: usize, op: anytype) Return(@TypeOf(op), "serial") {
    const Op = @TypeOf(op);
    comptime assert(Return(Op, "serial") == Return(Op, "parallel"));
    assert(strategy.parallelism() >= 1);
    _ = len;
    if (strategy.parallelism() > 1) return op.parallel();
    return op.serial();
}

/// What a call's work runs on, for an adaptive strategy's timing: the caller's own thread
/// (`run`'s bodies, whose busy time is their wall time), or jobs the strategy places on its
/// pool, whose busy time is metered.
pub const Body = enum { caller, placed };

/// The strategy one call runs on. A strategy declaring `adapt` (a `Rayon` with a policy)
/// chooses serial or parallel for the call site and times the call; others run unchanged.
pub fn Adapted(comptime S: type) type {
    const B = ops.Base(S);
    if (@hasDecl(B, "adapt")) return B.Adaptation;
    return struct {
        strategy: S,

        pub fn get(adapted: *@This()) S {
            return adapted.strategy;
        }

        pub fn finish(_: *@This(), result: anytype) @TypeOf(result) {
            return result;
        }
    };
}

/// Adapts `strategy` for a call from `site` over `len` items and `work` estimated units.
pub fn adapt(
    strategy: anytype,
    site: usize,
    len: usize,
    work: usize,
    body: Body,
) Adapted(@TypeOf(strategy)) {
    // `run`'s bodies run on the caller, and their work is their length.
    assert(body == .placed or work == len);
    if (comptime @hasDecl(ops.Base(@TypeOf(strategy)), "adapt")) {
        return strategy.adapt(site, len, work, body);
    }
    return .{ .strategy = strategy };
}

// The operations. Each adapts once, at its outermost call, keyed by its caller's address, and
// runs the matching `*_on` body on the adapted strategy.

/// Runs `op.serial()` or `op.parallel()`, which must return the same type. A strategy without
/// parallelism always runs the serial body; an adaptive one picks per call site. `try_run` is
/// the same for bodies that return error unions: an adaptive strategy records only successes.
pub fn run(strategy: anytype, len: usize, op: anytype) Return(@TypeOf(op), "serial") {
    var call = adapt(strategy, @returnAddress(), len, len, .caller);
    return call.finish(run_on(call.get(), len, op));
}

pub const try_run = run;

/// Reduces `items` to one value: each chunk folds its items into `op.identity()` with
/// `op.fold(acc, item)`, and the chunk results combine in order with `op.reduce(a, b)`.
pub fn fold(strategy: anytype, items: anytype, op: anytype) Return(@TypeOf(op), "identity") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(fold_on(call.get(), items, op));
}

/// Like `fold`, with one `op.init()` state per chunk passed to `op.fold(acc, &state, item)`.
pub fn fold_init(strategy: anytype, items: anytype, op: anytype) Return(@TypeOf(op), "identity") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(fold_init_on(call.get(), items, op));
}

/// Like `fold`, but `op.fold(acc, item)` returns an error union; see `try_fold_on`.
pub fn try_fold(strategy: anytype, items: anytype, op: anytype) Return(@TypeOf(op), "fold") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(try_fold_on(call.get(), items, op));
}

/// Writes `op.map(item)` for every item into `out`, in input order.
pub fn map_into(strategy: anytype, items: anytype, out: anytype, op: anytype) void {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(map_into_on(call.get(), items, out, op));
}

/// Like `map_into`, with one `op.init()` state per chunk passed to `op.map(&state, item)`.
pub fn map_init_into(strategy: anytype, items: anytype, out: anytype, op: anytype) void {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(map_init_into_on(call.get(), items, out, op));
}

/// Like `map_into` for a fallible `op.map(item)`; see `try_map_into_on`.
pub fn try_map_into(
    strategy: anytype,
    items: anytype,
    out: anytype,
    op: anytype,
) ops.ErrorOf(Return(@TypeOf(op), "map"))!void {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(try_map_into_on(call.get(), items, out, op));
}

/// Maps every item with `op.map(item)` into a new slice owned by the caller.
pub fn map_collect(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(map_collect_on(call.get(), allocator, items, op));
}

/// Like `map_collect`, with one `op.init()` state per chunk.
pub fn map_init_collect(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(map_init_collect_on(call.get(), allocator, items, op));
}

/// `map_collect` with an estimate of the work per item, which an adaptive strategy keys its
/// serial-or-parallel decision by.
pub fn map_collect_with_multiplier(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    multiplier: usize,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len *| multiplier, .placed);
    return call.finish(map_collect_on(call.get(), allocator, items, op));
}

/// `map_init_collect` with an estimate of the work per item.
pub fn map_init_collect_with_multiplier(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    multiplier: usize,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len *| multiplier, .placed);
    return call.finish(map_init_collect_on(call.get(), allocator, items, op));
}

/// Like `map_collect`, for a fallible `op.map(item)`; see `try_map_into_on`.
pub fn try_map_collect(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) (std.mem.Allocator.Error || ops.ErrorOf(Return(@TypeOf(op), "map")))![]ops.Payload(
    Return(@TypeOf(op), "map"),
) {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(try_map_collect_on(call.get(), allocator, items, op));
}

/// Maps every item with `op.map(item)`, which returns `struct { K, ?U }`; see
/// `map_partition_collect_on`.
pub fn map_partition_collect(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) std.mem.Allocator.Error!ops.Partitioned(ops.PartitionKey(@TypeOf(op)), ops.PartitionValue(
    @TypeOf(op),
)) {
    const len = ops.count(items);
    var call = adapt(strategy, @returnAddress(), len, len, .placed);
    return call.finish(map_partition_collect_on(call.get(), allocator, items, op));
}

/// Runs `a.call()` and `b.call()`, potentially in parallel, and returns both results.
pub fn join(
    strategy: anytype,
    a: anytype,
    b: anytype,
) ops.Pair(Return(@TypeOf(a), "call"), Return(@TypeOf(b), "call")) {
    var call = adapt(strategy, @returnAddress(), 1, 1, .placed);
    return call.finish(join_on(call.get(), a, b));
}

/// Sorts `items` by `lessThan`, preserving the order of equal elements.
pub fn sort_by(
    strategy: anytype,
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    var call = adapt(strategy, @returnAddress(), items.len, items.len, .placed);
    return call.finish(sort_by_on(call.get(), T, items, context, lessThan));
}

/// Sorts `items` by `lessThan`, leaving the order of equal elements unspecified.
pub fn sort_unstable_by(
    strategy: anytype,
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    var call = adapt(strategy, @returnAddress(), items.len, items.len, .placed);
    return call.finish(sort_unstable_by_on(call.get(), T, items, context, lessThan));
}

/// Runs `op.run(batches)` once with batches covering `0..len` (see `Batches`). `multiplier`
/// estimates the work per item for adaptive strategies; input too small for two batches runs
/// as one without consulting them. `try_run_batches` is the same for an `op.run` that returns
/// an error union.
pub fn run_batches(
    strategy: anytype,
    len: usize,
    minimum_batch_len: usize,
    multiplier: usize,
    op: anytype,
) Return(@TypeOf(op), "run") {
    assert(minimum_batch_len > 0);
    if (@min(strategy.parallelism(), len / minimum_batch_len) < 2) {
        return run_batches_on(strategy, len, minimum_batch_len, multiplier, op);
    }
    var call = adapt(strategy, @returnAddress(), len, len *| multiplier, .placed);
    return call.finish(run_batches_on(call.get(), len, minimum_batch_len, multiplier, op));
}

pub const try_run_batches = run_batches;

/// Runs `part.chunk(start, end)` over the chunks of `0..len` the strategy splits it into,
/// storing chunk `i`'s result in `partials[i]`. Returns the chunk count.
fn chunk_all(strategy: anytype, len: usize, part: anytype, partials: anytype) usize {
    const Part = @TypeOf(part);
    const R = Return(Part, "chunk");
    const chunks = strategy.split(len);
    assert(chunks >= 1);
    assert(chunks <= max_chunks);
    if (chunks == 1) {
        partials[0] = part.chunk(0, len);
        return 1;
    }
    const Context = struct {
        part: Part,
        len: usize,
        chunks: usize,
        partials: *[max_chunks]R,

        pub fn body(context: *const @This(), index: usize) void {
            const range = ops.balanced(context.len, context.chunks, index);
            context.partials[index] = context.part.chunk(range.start, range.end);
        }
    };
    const context: Context = .{ .part = part, .len = len, .chunks = chunks, .partials = partials };
    strategy.execute(chunks, &context, Context.body);
    return chunks;
}

/// Calls `op.discard(value)` when the operation declares `discard`, to release a value the
/// strategy drops (an accumulator or output of a failed fallible operation).
fn discard(op: anytype, value: anytype) void {
    if (comptime @hasDecl(ops.Base(@TypeOf(op)), "discard")) op.discard(value);
}

/// Reduces `items` to one value: each chunk folds its items into `op.identity()` with
/// `op.fold(acc, item)`, and the chunk results combine in order with `op.reduce(a, b)`.
fn fold_on(strategy: anytype, items: anytype, op: anytype) Return(@TypeOf(op), "identity") {
    const Op = @TypeOf(op);
    const Items = @TypeOf(items);
    const R = Return(Op, "identity");
    const Part = struct {
        items: Items,
        op: Op,

        pub fn chunk(part: *const @This(), start: usize, end: usize) R {
            return ops.fold_span(part.items, start, end, part.op);
        }
    };
    const part: Part = .{ .items = items, .op = op };
    var partials: [max_chunks]R = undefined;
    const chunks = chunk_all(strategy, ops.count(items), &part, &partials);
    assert(chunks >= 1);
    var acc = partials[0];
    for (partials[1..chunks]) |partial| acc = op.reduce(acc, partial);
    return acc;
}

/// Like `fold`, with one `op.init()` state per chunk passed to `op.fold(acc, &state, item)`.
/// When the operation declares `deinit_state(&state)`, each chunk's state is released after it.
fn fold_init_on(strategy: anytype, items: anytype, op: anytype) Return(@TypeOf(op), "identity") {
    const Op = @TypeOf(op);
    const Items = @TypeOf(items);
    const R = Return(Op, "identity");
    const Part = struct {
        items: Items,
        op: Op,

        pub fn chunk(part: *const @This(), start: usize, end: usize) R {
            assert(start <= end);
            var state = part.op.init();
            defer if (comptime @hasDecl(ops.Base(Op), "deinit_state")) {
                part.op.deinit_state(&state);
            };
            var acc = part.op.identity();
            for (start..end) |index| acc = part.op.fold(acc, &state, ops.at(part.items, index));
            return acc;
        }
    };
    const part: Part = .{ .items = items, .op = op };
    var partials: [max_chunks]R = undefined;
    const chunks = chunk_all(strategy, ops.count(items), &part, &partials);
    assert(chunks >= 1);
    var acc = partials[0];
    for (partials[1..chunks]) |partial| acc = op.reduce(acc, partial);
    return acc;
}

/// Like `fold`, but `op.fold(acc, item)` returns an error union. After an error, chunks stop
/// folding, the first error in chunk order is returned, and the other chunks' accumulators are
/// passed to `op.discard` if the operation declares it.
fn try_fold_on(strategy: anytype, items: anytype, op: anytype) Return(@TypeOf(op), "fold") {
    const Op = @TypeOf(op);
    const Items = @TypeOf(items);
    const Result = Return(Op, "fold");
    comptime assert(ops.Payload(Result) == Return(Op, "identity"));
    const Part = struct {
        items: Items,
        op: Op,
        stop: *std.atomic.Value(bool),

        pub fn chunk(part: *const @This(), start: usize, end: usize) Result {
            var acc = part.op.identity();
            for (start..end) |index| {
                if (part.stop.load(.monotonic)) break;
                acc = part.op.fold(acc, ops.at(part.items, index)) catch |err| {
                    part.stop.store(true, .monotonic);
                    return err;
                };
            }
            return acc;
        }
    };
    var stop: std.atomic.Value(bool) = .init(false);
    const part: Part = .{ .items = items, .op = op, .stop = &stop };
    var partials: [max_chunks]Result = undefined;
    const chunks = chunk_all(strategy, ops.count(items), &part, &partials);
    for (partials[0..chunks]) |partial| {
        _ = partial catch |err| {
            for (partials[0..chunks]) |other| {
                if (other) |acc| discard(op, acc) else |_| {}
            }
            return err;
        };
    }
    assert(!stop.load(.monotonic));
    // Every partial is a success: the loop above returned on the first error.
    var acc = partials[0] catch unreachable;
    for (partials[1..chunks]) |partial| acc = op.reduce(acc, partial catch unreachable);
    return acc;
}

/// Writes `op.map(item)` for every item into `out`, which must have one slot per item. Output
/// order matches input order.
fn map_into_on(strategy: anytype, items: anytype, out: anytype, op: anytype) void {
    const Part = struct {
        items: @TypeOf(items),
        out: @TypeOf(out),
        op: @TypeOf(op),

        pub fn chunk(part: *const @This(), start: usize, end: usize) void {
            ops.map_span(part.items, start, end, part.out, part.op);
        }
    };
    assert(out.len == ops.count(items));
    const part: Part = .{ .items = items, .out = out, .op = op };
    var partials: [max_chunks]void = undefined;
    const chunks = chunk_all(strategy, ops.count(items), &part, &partials);
    assert(chunks >= 1);
}

/// Like `map_into`, with one `op.init()` state per chunk passed to `op.map(&state, item)`.
fn map_init_into_on(strategy: anytype, items: anytype, out: anytype, op: anytype) void {
    const Part = struct {
        items: @TypeOf(items),
        out: @TypeOf(out),
        op: @TypeOf(op),

        pub fn chunk(part: *const @This(), start: usize, end: usize) void {
            ops.map_init_span(part.items, start, end, part.out, part.op);
        }
    };
    assert(out.len == ops.count(items));
    const part: Part = .{ .items = items, .out = out, .op = op };
    var partials: [max_chunks]void = undefined;
    const chunks = chunk_all(strategy, ops.count(items), &part, &partials);
    assert(chunks >= 1);
}

/// Maps every item with `op.map(item)` into a new slice owned by the caller.
fn map_collect_on(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    const out = try allocator.alloc(Return(@TypeOf(op), "map"), ops.count(items));
    map_into_on(strategy, items, out, op);
    assert(out.len == ops.count(items));
    return out;
}

/// Like `map_collect`, with one `op.init()` state per chunk passed to `op.map(&state, item)`.
fn map_init_collect_on(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    const out = try allocator.alloc(Return(@TypeOf(op), "map"), ops.count(items));
    map_init_into_on(strategy, items, out, op);
    assert(out.len == ops.count(items));
    return out;
}

/// `map_collect` with an estimate of the work per item, which adaptive strategies use to decide
/// between serial and parallel execution.
fn map_collect_with_multiplier_on(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    multiplier: usize,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    _ = multiplier;
    return map_collect_on(strategy, allocator, items, op);
}

/// `map_init_collect` with an estimate of the work per item.
fn map_init_collect_with_multiplier_on(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    multiplier: usize,
    op: anytype,
) std.mem.Allocator.Error![]Return(@TypeOf(op), "map") {
    _ = multiplier;
    return map_init_collect_on(strategy, allocator, items, op);
}

/// How far a chunk of a fallible map got: outputs `start..end` were written, and `failure` is
/// the error that stopped it, if any.
fn Progress(comptime E: type) type {
    return struct { end: usize, failure: ?E };
}

/// Like `map_into`, but `op.map(item)` returns an error union. After an error, chunks stop
/// mapping and the first error in chunk order is returned; outputs already written are passed
/// to `op.discard` if the operation declares it, and the contents of `out` are unspecified.
fn try_map_into_on(
    strategy: anytype,
    items: anytype,
    out: anytype,
    op: anytype,
) ops.ErrorOf(Return(@TypeOf(op), "map"))!void {
    const E = ops.ErrorOf(Return(@TypeOf(op), "map"));
    const Part = struct {
        items: @TypeOf(items),
        out: @TypeOf(out),
        op: @TypeOf(op),
        stop: *std.atomic.Value(bool),

        pub fn chunk(part: *const @This(), start: usize, end: usize) Progress(E) {
            for (start..end) |index| {
                if (part.stop.load(.monotonic)) return .{ .end = index, .failure = null };
                part.out[index] = part.op.map(ops.at(part.items, index)) catch |err| {
                    part.stop.store(true, .monotonic);
                    return .{ .end = index, .failure = err };
                };
            }
            return .{ .end = end, .failure = null };
        }
    };
    const len = ops.count(items);
    assert(out.len == len);
    var stop: std.atomic.Value(bool) = .init(false);
    const part: Part = .{ .items = items, .out = out, .op = op, .stop = &stop };
    var partials: [max_chunks]Progress(E) = undefined;
    const chunks = chunk_all(strategy, len, &part, &partials);
    for (partials[0..chunks]) |partial| {
        const err = partial.failure orelse continue;
        for (partials[0..chunks], 0..) |progress, index| {
            const range = ops.balanced(len, chunks, index);
            for (out[range.start..progress.end]) |value| discard(op, value);
        }
        return err;
    }
    assert(!stop.load(.monotonic));
}

/// Like `map_collect`, for a fallible `op.map(item)`; see `try_map_into`.
fn try_map_collect_on(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) (std.mem.Allocator.Error || ops.ErrorOf(Return(@TypeOf(op), "map")))![]ops.Payload(
    Return(@TypeOf(op), "map"),
) {
    const T = ops.Payload(Return(@TypeOf(op), "map"));
    const out = try allocator.alloc(T, ops.count(items));
    errdefer allocator.free(out);
    try try_map_into_on(strategy, items, out, op);
    assert(out.len == ops.count(items));
    return out;
}

/// Maps every item with `op.map(item)`, which returns `struct { K, ?U }`. Values go to
/// `results` and keys of items that mapped to null go to `filtered`, both in input order.
fn map_partition_collect_on(
    strategy: anytype,
    allocator: std.mem.Allocator,
    items: anytype,
    op: anytype,
) std.mem.Allocator.Error!ops.Partitioned(ops.PartitionKey(@TypeOf(op)), ops.PartitionValue(
    @TypeOf(op),
)) {
    const K = ops.PartitionKey(@TypeOf(op));
    const U = ops.PartitionValue(@TypeOf(op));
    const pairs = try map_collect_on(strategy, allocator, items, op);
    defer allocator.free(pairs);
    var values: usize = 0;
    for (pairs) |pair| values += @intFromBool(pair[1] != null);
    const results = try allocator.alloc(U, values);
    errdefer allocator.free(results);
    const filtered = try allocator.alloc(K, pairs.len - values);
    var result_index: usize = 0;
    var filtered_index: usize = 0;
    for (pairs) |pair| {
        if (pair[1]) |value| {
            results[result_index] = value;
            result_index += 1;
        } else {
            filtered[filtered_index] = pair[0];
            filtered_index += 1;
        }
    }
    assert(result_index == results.len);
    assert(filtered_index == filtered.len);
    return .{ .results = results, .filtered = filtered };
}

/// Runs `a.call()` and `b.call()`, potentially in parallel, and returns both results.
fn join_on(
    strategy: anytype,
    a: anytype,
    b: anytype,
) ops.Pair(Return(@TypeOf(a), "call"), Return(@TypeOf(b), "call")) {
    const A = @TypeOf(a);
    const B = @TypeOf(b);
    const Context = struct {
        a: A,
        b: B,
        result_a: Return(A, "call") = undefined,
        result_b: Return(B, "call") = undefined,

        pub fn body(context: *@This(), index: usize) void {
            assert(index < 2);
            if (index == 0) {
                context.result_a = context.a.call();
            } else {
                context.result_b = context.b.call();
            }
        }
    };
    var context: Context = .{ .a = a, .b = b };
    strategy.execute(2, &context, Context.body);
    return .{ context.result_a, context.result_b };
}

/// The shortest run a parallel sort sorts on its own before merging.
pub const sort_run_len_min: usize = 256;

/// Sorts `items` by `lessThan`, preserving the order of equal elements.
fn sort_by_on(
    strategy: anytype,
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    sort(strategy, .stable, T, items, context, lessThan);
}

/// Sorts `items` by `lessThan`, leaving the order of equal elements unspecified.
fn sort_unstable_by_on(
    strategy: anytype,
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    sort(strategy, .unstable, T, items, context, lessThan);
}

fn sort_serial(
    comptime mode: std.sort.Mode,
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    switch (mode) {
        .stable => std.sort.block(T, items, context, lessThan),
        .unstable => std.sort.pdq(T, items, context, lessThan),
    }
}

/// Sorts runs of `items` in parallel, then merges pairs of runs in rounds, alternating between
/// `items` and a scratch buffer. Without parallelism, a scratch allocator, or enough items for
/// two runs, it sorts serially.
fn sort(
    strategy: anytype,
    comptime mode: std.sort.Mode,
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    // Zero-sized items are all alike: nothing to compare or move (commonware's sorts too).
    if (@sizeOf(T) == 0) return;
    const runs = @min(strategy.parallelism(), max_chunks, items.len / sort_run_len_min);
    const allocator = strategy.scratch() orelse
        return sort_serial(mode, T, items, context, lessThan);
    if (runs < 2) return sort_serial(mode, T, items, context, lessThan);
    const buffer = allocator.alloc(T, items.len) catch
        return sort_serial(mode, T, items, context, lessThan);
    defer allocator.free(buffer);

    var bounds: [max_chunks + 1]usize = undefined;
    for (0..runs) |index| bounds[index] = ops.balanced(items.len, runs, index).start;
    bounds[runs] = items.len;
    const Runs = struct {
        items: []T,
        bounds: *const [max_chunks + 1]usize,
        context: @TypeOf(context),

        pub fn body(sorting: *const @This(), index: usize) void {
            const run_items = sorting.items[sorting.bounds[index]..sorting.bounds[index + 1]];
            sort_serial(mode, T, run_items, sorting.context, lessThan);
        }
    };
    const sorting: Runs = .{ .items = items, .bounds = &bounds, .context = context };
    strategy.execute(runs, &sorting, Runs.body);
    merge_runs(strategy, T, items, buffer, &bounds, runs, context, lessThan);
    assert(bounds[0] == 0);
}

/// Merges `runs` sorted runs of `items` delimited by `bounds` into one, using `buffer`.
fn merge_runs(
    strategy: anytype,
    comptime T: type,
    items: []T,
    buffer: []T,
    bounds: *[max_chunks + 1]usize,
    runs_initial: usize,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    assert(buffer.len == items.len);
    assert(runs_initial >= 2 and runs_initial <= max_chunks);
    const Merge = struct {
        source: []const T,
        target: []T,
        bounds: *const [max_chunks + 1]usize,
        runs: usize,
        context: @TypeOf(context),

        pub fn body(merging: *const @This(), index: usize) void {
            const start = merging.bounds[2 * index];
            if (2 * index + 1 == merging.runs) {
                const end = merging.bounds[merging.runs];
                @memcpy(merging.target[start..end], merging.source[start..end]);
                return;
            }
            const middle = merging.bounds[2 * index + 1];
            const end = merging.bounds[2 * index + 2];
            const source = merging.source;
            const left = source[start..middle];
            const right = source[middle..end];
            merge(T, left, right, merging.target[start..end], merging.context, lessThan);
        }
    };
    var source: []T = items;
    var target: []T = buffer;
    var runs = runs_initial;
    // Each round halves the runs, so at most log2(max_chunks) rounds run.
    while (runs > 1) {
        const merges = (runs + 1) / 2;
        const merging: Merge = .{
            .source = source,
            .target = target,
            .bounds = bounds,
            .runs = runs,
            .context = context,
        };
        strategy.execute(merges, &merging, Merge.body);
        for (0..merges) |index| bounds[index] = bounds[2 * index];
        bounds[merges] = items.len;
        runs = merges;
        std.mem.swap([]T, &source, &target);
    }
    if (source.ptr != items.ptr) @memcpy(items, source);
}

/// Merges sorted `left` and `right` into `out`, taking from `left` on ties so the merge is
/// stable.
fn merge(
    comptime T: type,
    left: []const T,
    right: []const T,
    out: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), T, T) bool,
) void {
    assert(left.len + right.len == out.len);
    var left_index: usize = 0;
    var right_index: usize = 0;
    var out_index: usize = 0;
    while (left_index < left.len and right_index < right.len) : (out_index += 1) {
        if (lessThan(context, right[right_index], left[left_index])) {
            out[out_index] = right[right_index];
            right_index += 1;
        } else {
            out[out_index] = left[left_index];
            left_index += 1;
        }
    }
    const left_rest = left[left_index..];
    @memcpy(out[out_index..][0..left_rest.len], left_rest);
    out_index += left_rest.len;
    const right_rest = right[right_index..];
    @memcpy(out[out_index..][0..right_rest.len], right_rest);
    assert(out_index + right_rest.len == out.len);
}

/// Batches supplied to one `run_batches` operation: one whole batch `0..len` that runs on the
/// calling thread, or two or more ordered batches, no shorter than the minimum batch length,
/// whose lengths differ by at most one and which may run in parallel.
pub fn Batches(comptime Strategy: type) type {
    return struct {
        const Self = @This();

        strategy: Strategy,
        len: usize,
        batches: usize,

        /// Whether the strategy supplied the whole input as one batch on the calling thread.
        pub fn is_whole(self: Self) bool {
            assert(self.batches >= 1);
            return self.batches == 1;
        }

        /// The number of batches.
        pub fn count(self: Self) usize {
            assert(self.batches >= 1 and self.batches <= max_chunks);
            return self.batches;
        }

        /// The input range of batch `index`.
        pub fn range(self: Self, index: usize) Range {
            assert(index < self.batches);
            return ops.balanced(self.len, self.batches, index);
        }

        /// Calls `op.map(index, range)` for every batch, possibly in parallel, writing batch
        /// `index`'s result to `out[index]`; `out` must have one slot per batch.
        pub fn map_collect(self: Self, out: anytype, op: anytype) void {
            const Context = struct {
                batches: Self,
                out: @TypeOf(out),
                op: @TypeOf(op),

                pub fn body(context: *const @This(), index: usize) void {
                    context.out[index] = context.op.map(index, context.batches.range(index));
                }
            };
            assert(out.len == self.batches);
            const context: Context = .{ .batches = self, .out = out, .op = op };
            self.strategy.execute(self.batches, &context, Context.body);
        }

        /// Like `map_collect` for a fallible `op.map`. Returns the first error in batch order;
        /// the other batches' results are passed to `op.discard` if the operation declares it.
        pub fn try_map_collect(
            self: Self,
            out: anytype,
            op: anytype,
        ) ops.ErrorOf(Return(@TypeOf(op), "map"))!void {
            const E = ops.ErrorOf(Return(@TypeOf(op), "map"));
            const Context = struct {
                batches: Self,
                out: @TypeOf(out),
                op: @TypeOf(op),
                failures: *[max_chunks]?E,

                pub fn body(context: *const @This(), index: usize) void {
                    const range_batch = context.batches.range(index);
                    context.failures[index] = null;
                    context.out[index] = context.op.map(index, range_batch) catch |err| {
                        context.failures[index] = err;
                        return;
                    };
                }
            };
            assert(out.len == self.batches);
            var failures: [max_chunks]?E = undefined;
            const context: Context = .{
                .batches = self,
                .out = out,
                .op = op,
                .failures = &failures,
            };
            self.strategy.execute(self.batches, &context, Context.body);
            for (failures[0..self.batches]) |failure| {
                const err = failure orelse continue;
                for (failures[0..self.batches], out) |other, value| {
                    if (other == null) discard(op, value);
                }
                return err;
            }
        }
    };
}

/// Runs `op.run(batches)` once with batches covering `0..len` (see `Batches`). `multiplier`
/// estimates the work per item for adaptive strategies. Both shapes must produce equivalent
/// results.
fn run_batches_on(
    strategy: anytype,
    len: usize,
    minimum_batch_len: usize,
    multiplier: usize,
    op: anytype,
) Return(@TypeOf(op), "run") {
    assert(minimum_batch_len > 0);
    _ = multiplier;
    const count = @min(strategy.parallelism(), len / minimum_batch_len, max_chunks);
    const batches: usize = if (count < 2) 1 else count;
    assert(batches == 1 or len / batches >= minimum_batch_len);
    return op.run(Batches(@TypeOf(strategy)){
        .strategy = strategy,
        .len = len,
        .batches = batches,
    });
}
