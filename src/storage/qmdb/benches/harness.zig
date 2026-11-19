//! Shared pieces of the opt-in QMDB CLI harnesses (`cold_read`, `constantinople`, `scale`):
//! positional arguments, wall-clock timing, percentiles, and Linux `/proc/diskstats` deltas.
//!
//! The harnesses run on the production runtime's storage like commonware's tokio binaries, but
//! zigware's databases are not shared across threads, so a mode that commonware runs as
//! concurrent futures issues the same reads one after another (docs/lanes/storage-qmdb.md).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const common = @import("common.zig");

const Digest = common.Digest;

/// Positional arguments consumed in usage order (commonware's `Positional`).
pub const Positional = struct {
    args: []const []const u8,
    index: usize = 0,

    /// The next argument parsed as `T`; null when absent or malformed.
    pub fn required(p: *Positional, comptime T: type) ?T {
        assert(p.index <= p.args.len);
        if (p.index == p.args.len) return null;
        p.index += 1;
        return parse(T, p.args[p.index - 1]);
    }

    /// The next argument, or `default` once the arguments run out. Null is a parse failure.
    pub fn optional(p: *Positional, comptime T: type, default: T) ?T {
        assert(p.index <= p.args.len);
        if (p.index == p.args.len) return default;
        p.index += 1;
        return parse(T, p.args[p.index - 1]);
    }

    pub fn done(p: *const Positional) bool {
        assert(p.index <= p.args.len);
        return p.index == p.args.len;
    }
};

/// Parses `text` as `T`: an unsigned integer, a float, or the text itself.
pub fn parse(comptime T: type, text: []const u8) ?T {
    if (T == []const u8) return text;
    if (@typeInfo(T) == .float) return std.fmt.parseFloat(T, text) catch null;
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    return std.fmt.parseInt(T, text, 10) catch null;
}

/// Drops the trailing `--bench` cargo appends (kept for command lines copied from commonware).
pub fn strip_bench_flag(gpa: Allocator, args: []const []const u8) ![]const []const u8 {
    var kept: std.ArrayList([]const u8) = .empty;
    errdefer kept.deinit(gpa);
    for (args) |arg| {
        if (!std.mem.eql(u8, arg, "--bench")) try kept.append(gpa, arg);
    }
    assert(kept.items.len <= args.len);
    return kept.toOwnedSlice(gpa);
}

/// Monotonic nanoseconds.
pub fn now_ns(io: Io) u64 {
    const now = Io.Clock.awake.now(io).nanoseconds;
    assert(now >= 0);
    return @intCast(now);
}

/// Milliseconds since `start_ns`.
pub fn elapsed_ms(io: Io, start_ns: u64) f64 {
    const end = now_ns(io);
    assert(end >= start_ns);
    return @as(f64, @floatFromInt(end - start_ns)) / std.time.ns_per_ms;
}

/// Commonware's `percentile`: sorts `values` and takes the element at `(len - 1) * q`.
pub fn percentile(values: []f64, q: f64) f64 {
    assert(values.len > 0);
    assert(q >= 0.0 and q <= 1.0);
    std.mem.sort(f64, values, {}, std.sort.asc(f64));
    const index: usize = @intFromFloat(@as(f64, @floatFromInt(values.len - 1)) * q);
    return values[index];
}

pub fn mean(values: []const f64) f64 {
    assert(values.len > 0);
    var sum: f64 = 0;
    for (values) |value| sum += value;
    return sum / @as(f64, @floatFromInt(values.len));
}

/// Sorts `keys` and removes duplicates, returning the deduplicated prefix.
pub fn sort_dedup(keys: []Digest) []Digest {
    std.mem.sort(Digest, keys, {}, Digest.less_than);
    var len: usize = 0;
    for (keys) |key| {
        if (len > 0 and keys[len - 1].eql(key)) continue;
        keys[len] = key;
        len += 1;
    }
    assert(len <= keys.len);
    assert(keys.len == 0 or len > 0);
    return keys[0..len];
}

/// Counters of one block device from `/proc/diskstats`.
pub const DiskStats = struct {
    reads: u64 = 0,
    sectors: u64 = 0,
    read_ms: u64 = 0,
    io_ms: u64 = 0,
    weighted_ms: u64 = 0,
};

/// The counters of `disk`, or zeros when `/proc/diskstats` is absent (not Linux) or lacks it.
pub fn diskstats(gpa: Allocator, io: Io, disk: []const u8) DiskStats {
    assert(disk.len > 0);
    const text = Io.Dir.cwd().readFileAlloc(io, "/proc/diskstats", gpa, .limited(1 << 20)) catch
        return .{};
    defer gpa.free(text);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields: [14][]const u8 = undefined;
        var count: usize = 0;
        var words = std.mem.tokenizeAny(u8, line, " \t");
        while (words.next()) |word| : (count += 1) {
            if (count < fields.len) fields[count] = word;
        }
        if (count <= 13 or !std.mem.eql(u8, fields[2], disk)) continue;
        return .{
            .reads = parse(u64, fields[3]) orelse 0,
            .sectors = parse(u64, fields[5]) orelse 0,
            .read_ms = parse(u64, fields[6]) orelse 0,
            .io_ms = parse(u64, fields[12]) orelse 0,
            .weighted_ms = parse(u64, fields[13]) orelse 0,
        };
    }
    return .{};
}

/// Commonware's `disk_delta`: device reads, KiB, latency, utilization, queue depth, and IOPS.
pub fn print_disk_delta(
    out: *Io.Writer,
    before: DiskStats,
    after: DiskStats,
    ms: f64,
) Io.Writer.Error!void {
    assert(ms >= 0);
    const reads = after.reads -| before.reads;
    const reads_f: f64 = @floatFromInt(reads);
    const per_ms = struct {
        fn of(value: u64, elapsed: f64) f64 {
            return if (elapsed > 0) @as(f64, @floatFromInt(value)) / elapsed else 0;
        }
    }.of;
    const latency = if (reads > 0)
        @as(f64, @floatFromInt(after.read_ms -| before.read_ms)) / reads_f
    else
        0;
    try out.print("disk: dev_reads={d} kb={d} avg_lat_ms={d:.3} util={d:.0}% ", .{
        reads,
        (after.sectors -| before.sectors) / 2,
        latency,
        100.0 * per_ms(after.io_ms -| before.io_ms, ms),
    });
    try out.print("avg_qd={d:.1} iops={d:.0}", .{
        per_ms(after.weighted_ms -| before.weighted_ms, ms),
        1000.0 * per_ms(reads, ms),
    });
}

/// The most tasks `join_all` runs at once.
pub const join_max = 64;

/// Runs `task(context, index)` for every index below `count` at once, on their own threads
/// where the `Io` has them, and returns the first error after all finish (commonware's
/// `try_join_all` over futures that read a shared database).
pub fn join_all(io: Io, count: usize, context: anytype, comptime task: anytype) !void {
    assert(count > 0);
    assert(count <= join_max);
    const Context = @TypeOf(context);
    const Run = struct {
        fn run(ctx: Context, index: usize, slot: *?anyerror) Io.Cancelable!void {
            task(ctx, index) catch |err| {
                slot.* = err;
            };
        }
    };
    var errors: [join_max]?anyerror = @splat(null);
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..count) |index| {
        const args = .{ context, index, &errors[index] };
        group.concurrent(io, Run.run, args) catch group.async(io, Run.run, args);
    }
    try group.await(io);
    for (errors[0..count]) |slot| if (slot) |err| return err;
}

/// A directory of `.zig-cache/tmp` for a harness's smoke test, removed by `cleanup`.
pub const SmokeDir = struct {
    tmp: std.testing.TmpDir,
    buffer: [96]u8 = undefined,
    path: []const u8 = "",

    pub fn init() SmokeDir {
        return .{ .tmp = std.testing.tmpDir(.{}) };
    }

    /// The path of `name` inside the directory.
    pub fn sub(self: *SmokeDir, name: []const u8) []const u8 {
        self.path = std.fmt.bufPrint(&self.buffer, ".zig-cache/tmp/{s}/{s}", .{
            &self.tmp.sub_path, name,
        }) catch unreachable; // The buffer holds the tmp prefix and a short name.
        assert(self.path.len > name.len);
        return self.path;
    }

    pub fn cleanup(self: *SmokeDir) void {
        self.tmp.cleanup();
        self.* = undefined;
    }
};

test "harness: join_all runs every task at once and reports a task's error" {
    const io = std.testing.io;
    var hits: [join_max]std.atomic.Value(u32) = @splat(.init(0));
    const Tasks = struct {
        fn hit(all: *[join_max]std.atomic.Value(u32), index: usize) !void {
            _ = all[index].fetchAdd(1, .monotonic);
            if (index == 5) return error.Planted;
        }
    };
    try std.testing.expectError(error.Planted, join_all(io, 9, &hits, Tasks.hit));
    for (hits[0..9]) |*hit| try std.testing.expectEqual(@as(u32, 1), hit.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 0), hits[9].load(.monotonic));
}

test "harness: percentile, dedup, and parsing" {
    var values = [_]f64{ 4, 1, 3, 2, 5 };
    try std.testing.expectEqual(@as(f64, 3), percentile(&values, 0.5));
    try std.testing.expectEqual(@as(f64, 1), percentile(&values, 0.0));
    try std.testing.expectEqual(@as(f64, 5), percentile(&values, 1.0));
    try std.testing.expectEqual(@as(f64, 3), mean(&values));
    var keys = [_]Digest{ common.key_at(2), common.key_at(1), common.key_at(2) };
    try std.testing.expectEqual(@as(usize, 2), sort_dedup(&keys).len);
    var p: Positional = .{ .args = &.{ "7", "x" } };
    try std.testing.expectEqual(@as(?u64, 7), p.required(u64));
    try std.testing.expectEqual(@as(?u64, null), p.optional(u64, 3));
    try std.testing.expectEqual(@as(?u64, 3), p.optional(u64, 3));
    try std.testing.expect(p.done());
}
