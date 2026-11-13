//! Simulate mechanism performance under realistic network conditions (commonware
//! `examples/estimator`).
//!
//! ```sh
//! zig build run-estimator -- examples/estimator/simplex.lazy \
//!     --distribution us-east-1:3,eu-west-1:2
//! ```
//!
//! Runs the `.lazy` task once per proposer on the deterministic runtime and p2p's simulated
//! network, with peers spread over AWS regions at cloudping.co's region-to-region latencies,
//! and prints latency statistics per proposer and averaged, in commonware's format.
//!
//! Where commonware panics, this prints `error: <commonware's panic message>` to stderr and
//! exits with Rust's panic status, 101.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const lib = @import("lib.zig");
const cli = @import("cli.zig");
const report = @import("report.zig");
const simulate = @import("simulate.zig");

/// Rust's exit status after a panic.
const panic_status: u8 = 101;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "estimator";

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    const outcome = try cli.parse(args[@min(args.len, 1)..], bin_name, stderr);
    switch (outcome) {
        .help => {
            try cli.write_help(stdout, bin_name);
            return stdout.flush();
        },
        .version => {
            try cli.write_version(stdout);
            return stdout.flush();
        },
        .usage_error => {
            try stderr.flush();
            std.process.exit(2);
        },
        .run => |arguments| {
            const status = try run(init, arguments, stdout, stderr);
            try stdout.flush();
            try stderr.flush();
            if (status != 0) std.process.exit(status);
        },
    }
    _ = gpa;
}

fn fail(stdout: *Io.Writer, stderr: *Io.Writer, message: []const u8) !u8 {
    try stdout.flush();
    try stderr.print("error: {s}\n", .{message});
    return panic_status;
}

fn now_us(io: Io) u64 {
    const nanoseconds = Io.Clock.real.now(io).nanoseconds;
    return @intCast(@divFloor(nanoseconds, std.time.ns_per_us));
}

fn run(
    init: std.process.Init,
    arguments: cli.Arguments,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const environ = init.environ_map;
    const is_tty = Io.File.stdout().isTty(io) catch false;
    const style: report.Style = .{ .colors = report.should_colorize(
        environ.get("CLICOLOR"),
        environ.get("CLICOLOR_FORCE"),
        environ.get("NO_COLOR"),
        is_tty,
    ) };
    const ansi = report.tracing_ansi(environ.get("NO_COLOR"));

    var panic: cli.Panic = .{};
    var distribution = cli.parse_distribution(gpa, arguments.distribution, &panic) catch |err|
        switch (err) {
            error.Panic => return fail(stdout, stderr, panic.message()),
            error.OutOfMemory => return error.OutOfMemory,
        };
    defer distribution.deinit(gpa);
    const limit: Io.Limit = .limited(lib.dsl.task_size_max);
    const content = Io.Dir.cwd().readFileAlloc(io, arguments.task, gpa, limit) catch |err| {
        panic.fail("Failed to read task file: {t}", .{err}) catch {};
        return fail(stdout, stderr, panic.message());
    };
    defer gpa.free(content);
    const peers = lib.count_peers(&distribution) catch |err| switch (err) {
        error.TooFewPeers => return fail(stdout, stderr, "must have at least 2 peers"),
        error.TooManyPeers => return fail(stdout, stderr, "attempt to add with overflow"),
    };
    var diagnostic: lib.Diagnostic = .{};
    var task = lib.parse_task(gpa, content, &diagnostic) catch |err| switch (err) {
        error.InvalidTask => return fail(stdout, stderr, diagnostic.message()),
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer task.deinit(gpa);
    try report.log_initializing(stdout, ansi, now_us(io), peers, &distribution);
    if (arguments.reload) {
        return fail(stdout, stderr, "--reload is not supported yet: the latency data is embedded");
    }
    try report.log_loading(stdout, ansi, now_us(io));
    var latencies = try lib.load_latency_data(gpa);
    defer latencies.deinit();

    const input: simulate.Input = .{
        .distribution = &distribution,
        .task = &task,
        .latencies = &latencies,
    };
    return run_all_simulations(gpa, style, stdout, stderr, input, peers, content);
}

/// One simulation per proposer, printed as it finishes, then the aggregate.
fn run_all_simulations(
    gpa: Allocator,
    style: report.Style,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    input: simulate.Input,
    peers: u64,
    content: []const u8,
) !u8 {
    const results = try gpa.alloc(simulate.Simulation, @intCast(peers));
    defer gpa.free(results);
    var finished: usize = 0;
    defer for (results[0..finished]) |*result| result.steps.deinit(gpa);
    for (results, 0..) |*result, proposer| {
        result.* = simulate.run_single_simulation(gpa, proposer, input) catch |err| switch (err) {
            error.Stalled => return fail(stdout, stderr, "runtime stalled"),
            error.MissingLatency => return fail(stdout, stderr, "no entry found for key"),
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => unreachable, // Mapped to `Stalled` by the simulation.
        };
        finished += 1;
        try report.print_simulation(
            gpa,
            style,
            stdout,
            result,
            input.distribution,
            input.task,
            content,
        );
        try stdout.flush();
    }
    try report.print_aggregated(
        gpa,
        style,
        stdout,
        results,
        input.distribution,
        input.task,
        content,
    );
    return 0;
}

test {
    _ = lib;
    _ = cli;
    _ = report;
    _ = simulate;
    _ = @import("simulate_test.zig");
}
