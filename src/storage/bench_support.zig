//! Helpers of the storage package's benchmarks.
//!
//! `Disk` opens storage as qmdb's benches do: production disk storage under a fresh directory
//! of `.zig-cache/tmp` (commonware's benches run on tokio's disk), removed on close. On smoke
//! inputs (`zig build test`) an in-memory storage stands in, so the test suite never waits on
//! the disk.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bench = @import("bench");
const build_options = @import("build_options");
const runtime = @import("runtime");

/// Whether this is a per-push smoke run (`zig build test` without `-Dslow-tests`): it runs
/// one or two cases of each benchmark on the smallest inputs, one of each MMR/MMB or
/// compression pair. With `-Dslow-tests` (nightly), smoke runs every case.
pub fn quick(runner: *const bench.Runner) bool {
    return runner.inputs == .smoke and !build_options.slow_tests;
}

/// `all`, or on a quick run only its first `count` items (at least one).
pub fn cases(
    comptime T: type,
    runner: *const bench.Runner,
    all: []const T,
    count: usize,
) []const T {
    assert(all.len > 0 and count > 0);
    if (!quick(runner)) return all;
    return all[0..@min(count, all.len)];
}

pub const Disk = struct {
    io: Io,
    memory: bool,
    directory: [64]u8 = undefined,
    directory_len: usize = 0,
    backend: union {
        production: runtime.production.storage.WithRing,
        memory: runtime.storage.memory.Storage,
    } = undefined,
    opened: bool = false,

    pub fn init(runner: *const bench.Runner) Disk {
        return .{ .io = runner.io, .memory = runner.inputs == .smoke };
    }

    pub fn open(disk: *Disk, gpa: Allocator, comptime name: []const u8) !void {
        assert(!disk.opened);
        if (disk.memory) {
            disk.backend = .{ .memory = .init(gpa) };
            disk.opened = true;
            return;
        }
        var nonce: [8]u8 = undefined;
        disk.io.random(&nonce);
        const path = try std.fmt.bufPrint(&disk.directory, ".zig-cache/tmp/" ++ name ++ "-{x}", .{
            std.mem.readInt(u64, &nonce, .little),
        });
        disk.directory_len = path.len;
        const root = try Io.Dir.cwd().createDirPathOpen(disk.io, path, .{});
        disk.backend = .{ .production = .{} };
        try disk.backend.production.init(disk.io, gpa, root, bench.io_uring);
        disk.opened = true;
        assert(disk.directory_len > 0);
    }

    pub fn storage(disk: *Disk) runtime.storage.Storage {
        assert(disk.opened);
        if (disk.memory) return disk.backend.memory.storage();
        return disk.backend.production.storage.storage();
    }

    pub fn close(disk: *Disk) void {
        assert(disk.opened);
        disk.opened = false;
        if (disk.memory) return disk.backend.memory.deinit();
        disk.backend.production.deinit();
        const path = disk.directory[0..disk.directory_len];
        Io.Dir.cwd().deleteTree(disk.io, path) catch |err|
            std.log.warn("storage benches: could not remove {s}: {t}", .{ path, err });
    }
};
