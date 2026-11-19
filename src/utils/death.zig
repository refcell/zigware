//! Death tests: commonware's `#[should_panic(expected = ...)]` for Zig, which cannot catch a
//! panic in-process.
//!
//! `expect_panic` reruns this test binary as a child in the test runner's server mode
//! (`--listen=-`, the protocol `zig build test` itself speaks) and asks it to run only the
//! calling test, by its index in `builtin.test_functions`. In the child, marked by
//! `child_env`, the same call runs `body` directly. The parent passes only if the child dies by
//! SIGABRT and its panic line contains `expected` (a substring, as Rust's `expected` is).
//!
//! ```
//! test "decrement panics at zero" {
//!     try death.expect_panic(@src(), "reached unreachable code", struct {
//!         fn body() !void { var record: Record = .{}; record.decrement(); }
//!     }.body);
//! }
//! ```
//!
//! An `assert` panics only with runtime safety on (Debug, ReleaseSafe); without it the call
//! returns `error.SkipZigTest`. POSIX only (it reads the environment with `getPosix`).
//! Test-only: it spawns a process, which library code never does.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const assert = std.debug.assert;

/// Present in the child's environment: the call runs `body` instead of spawning.
pub const child_env = "ZIGWARE_DEATH_TEST";
/// How long the child may run before it is killed; a hang fails the test.
pub const timeout_ms: i64 = 60_000;
/// Whether a wrong panic message is printed; the helper's own test of that case clears it.
pub var report_wrong_message = true;
/// The child's output kept for the panic line; a panic writes its message first.
const output_limit_bytes = 1 << 20;

pub const Error = error{
    /// The child finished the test without panicking.
    DeathTestDidNotPanic,
    /// The child panicked, but its panic line does not contain `expected`.
    DeathTestWrongMessage,
    /// The child ended some other way (a signal other than SIGABRT, or a nonzero exit).
    DeathTestUnexpectedEnd,
    /// The child ran past `timeout_ms`.
    DeathTestTimeout,
};

/// Passes when `body` panics with a message containing `expected`; see the module docs.
/// `src` is the calling test's `@src()`; its name must be unique among the binary's tests.
pub fn expect_panic(
    comptime src: std.builtin.SourceLocation,
    expected: []const u8,
    comptime body: fn () anyerror!void,
) anyerror!void {
    if (!std.debug.runtime_safety or builtin.os.tag == .windows) return error.SkipZigTest;
    if (std.testing.environ.getPosix(child_env) != null) {
        try body();
        return error.DeathTestDidNotPanic;
    }
    const index = test_index(src);
    const gpa = std.testing.allocator;
    const stderr = try run_child(gpa, std.testing.io, index);
    defer gpa.free(stderr.output);
    return judge(stderr.term, stderr.output, expected);
}

/// The index of the calling test: the one named `<file path, dotted>.<src.fn_name>`, as the
/// test runner names it, else the only one whose name ends in `.<src.fn_name>`.
fn test_index(comptime src: std.builtin.SourceLocation) u32 {
    comptime assert(std.mem.startsWith(u8, src.fn_name, "test."));
    const full = comptime dotted(src.file) ++ "." ++ src.fn_name;
    const suffix = "." ++ src.fn_name;
    var found: ?u32 = null;
    for (builtin.test_functions, 0..) |test_fn, index| {
        if (std.mem.eql(u8, test_fn.name, full)) return @intCast(index);
        if (!std.mem.endsWith(u8, test_fn.name, suffix)) continue;
        if (found != null) @panic("death test name is not unique: " ++ full);
        found = @intCast(index);
    }
    return found orelse @panic("no test named " ++ full);
}

/// `a/b/c.zig` as the test runner prefixes its tests: `a.b.c`.
fn dotted(comptime file: []const u8) []const u8 {
    comptime {
        const stem = if (std.mem.endsWith(u8, file, ".zig")) file[0 .. file.len - 4] else file;
        var name: [stem.len]u8 = stem[0..stem.len].*;
        std.mem.replaceScalar(u8, &name, '/', '.');
        const result = name;
        return &result;
    }
}

const Outcome = struct { term: std.process.Child.Term, output: []u8 };

/// Runs test `index` in a child copy of this binary and collects its stderr.
fn run_child(gpa: std.mem.Allocator, io: Io, index: u32) !Outcome {
    const exe = try std.process.executablePathAlloc(io, gpa);
    defer gpa.free(exe);
    var environ = try std.testing.environ.createMap(gpa);
    defer environ.deinit();
    try environ.put(child_env, "1");
    _ = environ.swapRemove("ZIG_PROGRESS"); // The child must not write into our progress.
    var child = try std.process.spawn(io, .{
        .argv = &.{ exe, "--listen=-" },
        .environ_map = &environ,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);
    try send_requests(io, child.stdin.?, index);
    child.stdin.?.close(io);
    child.stdin = null;
    var buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi: Io.File.MultiReader = undefined;
    multi.init(gpa, io, buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi.deinit();
    const deadline = Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(timeout_ms),
        .clock = .awake,
    });
    while (multi.fill(64, .{ .deadline = deadline })) |_| {
        if (multi.reader(1).buffered().len > output_limit_bytes) break;
        multi.reader(0).tossBuffered(); // Protocol replies; only stderr matters.
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.Timeout => return error.DeathTestTimeout,
        else => |other| return other,
    }
    const term = try child.wait(io);
    const output = try gpa.dupe(u8, multi.reader(1).buffered());
    assert(output.len <= output_limit_bytes + 64 * 2);
    return .{ .term = term, .output = output };
}

/// Writes `run_test(index)` then `exit`, the client half of `std.zig.Server`'s protocol.
fn send_requests(io: Io, stdin: Io.File, index: u32) !void {
    const Tag = std.zig.Client.Message.Tag;
    var bytes: [16]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], @backingInt(Tag.run_test), .little);
    std.mem.writeInt(u32, bytes[4..8], 4, .little);
    std.mem.writeInt(u32, bytes[8..12], index, .little);
    std.mem.writeInt(u32, bytes[12..16], @backingInt(Tag.exit), .little);
    var tail: [4]u8 = @splat(0); // The exit message has an empty body.
    try stdin.writeStreamingAll(io, &bytes);
    try stdin.writeStreamingAll(io, &tail);
}

/// Accepts only death by SIGABRT with a panic line that contains `expected`.
fn judge(term: std.process.Child.Term, output: []const u8, expected: []const u8) Error!void {
    switch (term) {
        .signal => |signal| if (signal != .ABRT) return unexpected(term, output),
        .exited => |code| if (code == 0) return error.DeathTestDidNotPanic else {
            return unexpected(term, output);
        },
        else => return unexpected(term, output),
    }
    const marker = " panic: ";
    const start = (std.mem.indexOf(u8, output, marker) orelse
        return unexpected(term, output)) + marker.len;
    const end = std.mem.indexOfScalarPos(u8, output, start, '\n') orelse output.len;
    const message = output[start..end];
    if (std.mem.indexOf(u8, message, expected) != null) return;
    if (report_wrong_message) {
        std.debug.print("death test: panic \"{s}\" lacks \"{s}\"\n", .{ message, expected });
    }
    return error.DeathTestWrongMessage;
}

fn unexpected(term: std.process.Child.Term, output: []const u8) Error {
    const shown = output[0..@min(output.len, 2048)];
    std.debug.print("death test: child {f}; stderr:\n{s}\n", .{ term, shown });
    return error.DeathTestUnexpectedEnd;
}

test "death: a panic with the expected message passes" {
    try expect_panic(@src(), "boom 42", struct {
        fn body() !void {
            std.debug.panic("boom {d} and more", .{42});
        }
    }.body);
}

test "death: an assert panics as unreachable" {
    try expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            var zero: u32 = 0;
            _ = &zero;
            assert(zero == 1);
        }
    }.body);
}

test "death: a body that returns fails" {
    if (!std.debug.runtime_safety) return error.SkipZigTest;
    const result = expect_panic(@src(), "boom", struct {
        fn body() !void {}
    }.body);
    // The child sees DeathTestDidNotPanic too, so its test passes and it exits cleanly.
    try std.testing.expectError(error.DeathTestDidNotPanic, result);
}

test "death: a different panic message fails" {
    if (!std.debug.runtime_safety) return error.SkipZigTest;
    report_wrong_message = false;
    defer report_wrong_message = true;
    const result = expect_panic(@src(), "expected text", struct {
        fn body() !void {
            @panic("other text");
        }
    }.body);
    try std.testing.expectError(error.DeathTestWrongMessage, result);
}
