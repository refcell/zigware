//! Simulation tests: commonware main.rs's `accepts_config`, determinism per seed, and
//! agreement with commonware's statistics.
//!
//! zigware's scheduler and network draw from the RNG in a different order than commonware's
//! tokio-style executor, so a run does not reproduce commonware's numbers sample for sample.
//! `testdata/simplex_commonware.txt` is the commonware binary's output for
//! `simplex.lazy --distribution us-east-1:5,eu-west-1:5,ap-northeast-1:5` (debug lines
//! removed); the test checks the zigware output has the same lines with every number masked,
//! and that each aggregated mean and median lies within a tolerance of commonware's.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const cli = @import("cli.zig");
const report = @import("report.zig");
const simulate = @import("simulate.zig");

const Net = zigware.p2p.simulated.Network(simulate.Key);

test "accepts_config" {
    var runner = try zigware.runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: std.Io) !void {
            const network = try Net.init(testing.allocator, io, .{
                .max_size = zigware.p2p.simulated.network.max_size_limit,
                .max_peers_per_set = 1,
                .disconnect_on_block = true,
                .tracked_peer_sets = 1,
            });
            network.deinit();
        }
    };
    try (try runner.start(Root.run, .{runner.io()}));
}

const Fixture = struct {
    distribution: lib.Distribution,
    task: lib.Task,
    latencies: lib.Latencies,

    fn init(distribution_text: []const u8, content: []const u8) !Fixture {
        var panic: cli.Panic = .{};
        var distribution = try cli.parse_distribution(testing.allocator, distribution_text, &panic);
        errdefer distribution.deinit(testing.allocator);
        var diagnostic: lib.Diagnostic = .{};
        var task = try lib.parse_task(testing.allocator, content, &diagnostic);
        errdefer task.deinit(testing.allocator);
        return .{
            .distribution = distribution,
            .task = task,
            .latencies = try lib.load_latency_data(testing.allocator),
        };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.distribution.deinit(testing.allocator);
        fixture.task.deinit(testing.allocator);
        fixture.latencies.deinit();
    }

    fn input(fixture: *const Fixture) simulate.Input {
        return .{
            .distribution = &fixture.distribution,
            .task = &fixture.task,
            .latencies = &fixture.latencies,
        };
    }
};

fn expect_steps_equal(a: *const simulate.Steps, b: *const simulate.Steps) !void {
    try testing.expectEqual(a.all.len, b.all.len);
    for (a.all, b.all) |x, y| try testing.expectEqualSlices(f64, x.items, y.items);
    try testing.expectEqualSlices(?f64, a.proposer, b.proposer);
}

test "same seed, same simulation" {
    var fixture = try Fixture.init("us-east-1:2,eu-west-1:2", @embedFile("hotstuff.lazy"));
    defer fixture.deinit();
    var first = try simulate.run_single_simulation(testing.allocator, 1, fixture.input());
    defer first.steps.deinit(testing.allocator);
    var second = try simulate.run_single_simulation(testing.allocator, 1, fixture.input());
    defer second.steps.deinit(testing.allocator);
    try expect_steps_equal(&first.steps, &second.steps);
    try testing.expectEqualStrings("eu-west-1", first.proposer_region);
    // The proposer collects its own vote and two of three others (67% of 4 is 3).
    const collect = 3; // `collect{1, ...}` is the fourth command.
    try testing.expect(first.steps.proposer[collect].? > 0);
}

test "stall is reported" {
    var fixture = try Fixture.init("us-east-1:2", @embedFile("stall.lazy"));
    defer fixture.deinit();
    try testing.expectError(
        error.Stalled,
        simulate.run_single_simulation(testing.allocator, 0, fixture.input()),
    );
}

/// Every `wait` (and the proposer's `collect`) is passed, as `validate` predicts.
fn expect_completes(name: []const u8, content: []const u8, distribution: []const u8) !void {
    var fixture = try Fixture.init(distribution, content);
    defer fixture.deinit();
    const peers = try lib.count_peers(&fixture.distribution);
    var simulation = try simulate.run_single_simulation(testing.allocator, 0, fixture.input());
    defer simulation.steps.deinit(testing.allocator);
    for (fixture.task.commands, 0..) |command, index| {
        var gates: usize = 0;
        var collects: usize = 0;
        for (command.items) |item| {
            if (item != .leaf) continue;
            gates += @intFromBool(item.leaf.gate() != null);
            collects += @intFromBool(item.leaf == .collect);
        }
        if (gates == 0) continue;
        var samples: usize = 0;
        for (0..simulation.steps.regions) |region| {
            samples += simulation.steps.at(index, region).items.len;
        }
        // A lone `collect` completes for the proposer only; anything else for every peer.
        const expected: usize = if (collects == gates and gates == 1) 1 else @intCast(peers);
        if (samples != expected) std.debug.print("{s} line {d}\n", .{ name, command.line });
        try testing.expectEqual(expected, samples);
        try testing.expect(simulation.steps.proposer[index] != null);
    }
}

test "every completing example file runs end to end" {
    const files = [_]struct { []const u8, []const u8 }{
        .{ "echo.lazy", @embedFile("echo.lazy") },
        .{ "hotstuff.lazy", @embedFile("hotstuff.lazy") },
        .{ "simplex.lazy", @embedFile("simplex.lazy") },
        .{ "simplex_with_delay.lazy", @embedFile("simplex_with_delay.lazy") },
        .{ "simplex_with_certificates.lazy", @embedFile("simplex_with_certificates.lazy") },
        .{ "simplex_small_block.lazy", @embedFile("simplex_small_block.lazy") },
        .{ "simplex_large_block.lazy", @embedFile("simplex_large_block.lazy") },
        .{
            "simplex_large_block_coding_50.lazy",
            @embedFile("simplex_large_block_coding_50.lazy"),
        },
        .{ "minimmit.lazy", @embedFile("minimmit.lazy") },
        .{ "minimmit_small_block.lazy", @embedFile("minimmit_small_block.lazy") },
        .{ "minimmit_large_block.lazy", @embedFile("minimmit_large_block.lazy") },
        .{
            "minimmit_large_block_coding_50.lazy",
            @embedFile("minimmit_large_block_coding_50.lazy"),
        },
        .{ "kudzu_small_block.lazy", @embedFile("kudzu_small_block.lazy") },
        .{ "kudzu_large_block.lazy", @embedFile("kudzu_large_block.lazy") },
        .{
            "kudzu_large_block_coding_50.lazy",
            @embedFile("kudzu_large_block_coding_50.lazy"),
        },
    };
    for (files) |file| {
        try expect_completes(file[0], file[1], "us-east-1:2,eu-west-1:1");
        // 1 Gbit/s symmetric and asymmetric caps exercise the bandwidth planner.
        const capped = "us-east-1:2:125000000,eu-west-1:1:125000000/62500000";
        try expect_completes(file[0], file[1], capped);
    }
}

/// The full report for every proposer, without colors.
fn render_all(fixture: *const Fixture, content: []const u8) ![]u8 {
    const gpa = testing.allocator;
    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();
    const peers: usize = @intCast(try lib.count_peers(&fixture.distribution));
    const results = try gpa.alloc(simulate.Simulation, peers);
    defer gpa.free(results);
    var finished: usize = 0;
    defer for (results[0..finished]) |*result| result.steps.deinit(gpa);
    const style: report.Style = .{ .colors = false };
    for (results, 0..) |*result, proposer| {
        result.* = try simulate.run_single_simulation(gpa, proposer, fixture.input());
        finished += 1;
        try report.print_simulation(
            gpa,
            style,
            &output.writer,
            result,
            &fixture.distribution,
            &fixture.task,
            content,
        );
    }
    try report.print_aggregated(
        gpa,
        style,
        &output.writer,
        results,
        &fixture.distribution,
        &fixture.task,
        content,
    );
    return output.toOwnedSlice();
}

/// `line` with every run of digits and dots replaced by `#`.
fn mask(line: []const u8, buffer: []u8) []const u8 {
    var length: usize = 0;
    var index: usize = 0;
    while (index < line.len) {
        const byte = line[index];
        if (std.ascii.isDigit(byte)) {
            while (index < line.len and (std.ascii.isDigit(line[index]) or line[index] == '.')) {
                index += 1;
            }
            buffer[length] = '#';
        } else {
            buffer[length] = byte;
            index += 1;
        }
        length += 1;
    }
    return buffer[0..length];
}

/// The number after `key` in a statistics line, up to `ms`.
fn field(line: []const u8, key: []const u8) !f64 {
    const start = (std.mem.indexOf(u8, line, key) orelse return error.TestMissingField) + key.len;
    const end = std.mem.indexOfPos(u8, line, start, "ms") orelse return error.TestMissingField;
    return std.fmt.parseFloat(f64, line[start..end]);
}

fn expect_close(label: []const u8, expected: f64, actual: f64, absolute: f64, relative: f64) !void {
    const tolerance = @max(absolute, relative * expected);
    if (@abs(expected - actual) <= tolerance) return;
    std.debug.print("{s}: commonware {d}, zigware {d}, tolerance {d}\n", .{
        label, expected, actual, tolerance,
    });
    return error.TestOutsideTolerance;
}

test "statistics agree with commonware in distribution" {
    const content = @embedFile("simplex.lazy");
    var fixture = try Fixture.init("us-east-1:5,eu-west-1:5,ap-northeast-1:5", content);
    defer fixture.deinit();
    const ours = try render_all(&fixture, content);
    defer testing.allocator.free(ours);
    const theirs = @embedFile("testdata/simplex_commonware.txt");

    var our_lines = std.mem.splitScalar(u8, ours, '\n');
    var their_lines = std.mem.splitScalar(u8, theirs, '\n');
    var aggregated = false;
    var compared: usize = 0;
    while (their_lines.next()) |their_line| {
        const our_line = our_lines.next() orelse return error.TestMissingLines;
        var their_buffer: [256]u8 = undefined;
        var our_buffer: [256]u8 = undefined;
        const expected_shape = mask(their_line, &their_buffer);
        try testing.expectEqualStrings(expected_shape, mask(our_line, &our_buffer));
        if (std.mem.eql(u8, their_line, "results:")) aggregated = true;
        if (!aggregated or std.mem.indexOf(u8, their_line, " mean: ") == null) continue;
        // Means agree within 2% (or 2ms); medians, being single samples, within 3% (or 5ms).
        const their_mean = try field(their_line, "mean: ");
        try expect_close(their_line, their_mean, try field(our_line, "mean: "), 2, 0.02);
        const their_median = try field(their_line, "median: ");
        try expect_close(their_line, their_median, try field(our_line, "median: "), 5, 0.03);
        compared += 1;
    }
    try testing.expectEqual(@as(?[]const u8, null), our_lines.next());
    // Three waits, each with a proposer, three regions, and an overall line.
    try testing.expectEqual(@as(usize, 15), compared);
}
