//! CLI and configuration types (commonware `runtime/src/storage/benches/config.rs`).
//!
//! Values parse and print under commonware's clap names. zigware has no Tokio: the default
//! backend, `threaded`, is the production runtime on `std.Io.Threaded` (`tokio` is accepted as
//! an alias), and `iouring` routes blob I/O through `production/ring.zig`. Tokio's
//! `--global-queue-interval` has no counterpart and is not offered.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

/// The most concurrent I/O streams: their futures live in fixed arrays.
pub const inflight_max = 256;

/// Runtime whose storage backend is benchmarked.
pub const Backend = enum {
    /// The production runtime on `std.Io.Threaded` (commonware's `tokio`).
    threaded,
    /// The production runtime with io_uring blob I/O (Linux only).
    iouring,
};

/// Benchmark workload to execute.
pub const Workload = enum {
    /// Sequential reads over a fixed-size file.
    read_seq,
    /// Uniform random reads over a fixed-size file.
    read_rand,
    /// Sequential non-overlapping overwrites over a fixed-size file.
    write_seq,
    /// Uniform random in-place overwrites over a fixed-size file.
    write_rand,
    /// Monotonic append writes to a growing file.
    write_append,
    /// Sequential durable positioned writes over a fixed-size file.
    write_sync,
    /// One append writer plus many random readers of the visible prefix.
    read_write_append,

    /// Whether the workload benchmarks writes.
    pub fn has_writes(self: Workload) bool {
        return switch (self) {
            .write_seq, .write_rand, .write_append, .write_sync, .read_write_append => true,
            .read_seq, .read_rand => false,
        };
    }

    /// Whether the workload benchmarks reads.
    pub fn has_reads(self: Workload) bool {
        return switch (self) {
            .read_seq, .read_rand, .read_write_append => true,
            else => false,
        };
    }
};

/// Read cache preparation mode.
pub const CacheMode = enum {
    /// Best-effort warming by touching the file before timing.
    warm,
    /// Best-effort eviction with `posix_fadvise(..., DONTNEED)` before timing. Only the first
    /// pass through the file is truly cold.
    cold,
};

/// Write payload layout.
pub const WriteShape = enum {
    /// Single contiguous buffer per write.
    contiguous,
    /// Four-buffer vectored write per operation.
    vectored,
};

/// Durable write implementation for the `write_sync` workload.
pub const SyncMethod = enum {
    /// Call `write_at`, then call `sync`.
    write_then_sync,
    /// Call `write_at` with `WriteOptions.sync`.
    write_and_sync,
};

/// Write durability policy.
pub const SyncMode = union(enum) {
    /// Flush once at the end of the timed phase.
    end,
    /// Flush every `N` writes in each writer stream.
    every: u64,

    pub fn format(self: SyncMode, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .end => try writer.writeAll("end"),
            .every => |count| try writer.print("{d}", .{count}),
        }
    }

    pub fn eql(a: SyncMode, b: SyncMode) bool {
        return std.meta.eql(a, b);
    }
};

/// Output format.
pub const OutputFormat = enum { human, json };

/// Parsed and validated benchmark configuration.
pub const Config = struct {
    backend: Backend = .threaded,
    workload: Workload,
    /// Timed run duration (`--duration` takes seconds).
    duration_ns: u64 = 30 * std.time.ns_per_s,
    /// Read or write size in bytes.
    io_size: usize = 4096,
    /// Concurrent I/O streams, each run as its own task.
    inflight: u32 = 1,
    /// Worker thread count; null keeps the runtime's own setting.
    worker_threads: ?u32 = null,
    /// io_uring ring capacity, rounded up to a power of two (default 1024).
    ring_size: ?u32 = null,
    /// Initial fixed-size file length.
    file_size: ?u64 = null,
    /// Existing parent directory under which a unique benchmark directory is created.
    root: []const u8 = "/tmp",
    /// Best-effort cache preparation for read-heavy workloads.
    cache: ?CacheMode = null,
    write_shape: WriteShape = .contiguous,
    sync_method: SyncMethod = .write_then_sync,
    sync_mode: SyncMode = .end,
    /// Deterministic seed for payloads and random offsets.
    seed: u64 = 0,
    output: OutputFormat = .human,

    /// Initial file size; only call after validation.
    pub fn file_size_bytes(self: *const Config) u64 {
        return self.file_size.?;
    }

    /// Ring capacity after applying the default and rounding, absent off io_uring.
    pub fn effective_ring_size(self: *const Config) ?u32 {
        if (self.backend != .iouring) return null;
        const size = std.math.ceilPowerOfTwoAssert(u32, self.ring_size orelse 1024);
        assert(size >= 1 and size <= 32768);
        return size;
    }

    /// Why the configuration is invalid, or null (commonware `Config::validate`).
    pub fn validate(self: *const Config) ?[]const u8 {
        const linux = builtin.os.tag == .linux;
        if (self.backend == .iouring and !linux) {
            return "--backend iouring is only supported on Linux";
        }
        if (self.inflight == 0) return "--inflight must be greater than zero";
        if (self.inflight > inflight_max) return "--inflight must be at most 256";
        if (self.worker_threads == 0) return "--worker-threads must be greater than zero";
        if (self.backend != .iouring and self.ring_size != null) {
            return "--ring-size requires --backend iouring";
        }
        if (self.ring_size) |size| {
            if (size == 0 or size > 32768) return "--ring-size must be in 1..=32768";
        }
        if (self.io_size == 0) return "size value must be greater than zero";
        if (self.duration_ns == 0) return "--duration must be at least 1";
        if (self.validate_file()) |message| return message;
        return self.validate_modes();
    }

    fn validate_file(self: *const Config) ?[]const u8 {
        if (self.workload == .write_append) {
            if (self.file_size != null) return "--file-size is not used by write_append";
            if (self.inflight != 1) return "write_append only supports --inflight 1";
            if (self.cache != null) return "--cache is only valid for read-heavy workloads";
            return null;
        }
        const file_size = self.file_size orelse return "--file-size is required for this workload";
        const io_size: u64 = self.io_size;
        if (file_size < io_size) return "--file-size must be at least --io-size";
        if (file_size % io_size != 0) return "--file-size must be a multiple of --io-size";
        switch (self.workload) {
            .write_seq, .write_rand, .write_sync => {
                const total_blocks = file_size / io_size;
                if (total_blocks < self.inflight) {
                    return "write_seq, write_rand, and write_sync require at least one " ++
                        "non-overlapping block per worker";
                }
                if (self.workload == .write_sync and total_blocks % self.inflight != 0) {
                    return "write_sync requires --file-size / --io-size to be divisible by " ++
                        "--inflight";
                }
            },
            else => {},
        }
        return null;
    }

    fn validate_modes(self: *const Config) ?[]const u8 {
        if (self.workload.has_reads()) {
            if (self.cache == null) return "--cache is required for read-heavy workloads";
        } else if (self.cache != null) {
            return "--cache is only valid for read-heavy workloads";
        }
        if (self.cache == .cold and builtin.os.tag != .linux) {
            return "--cache cold is only supported on Linux";
        }
        if (!self.workload.has_writes()) {
            if (self.write_shape != .contiguous) {
                return "--write-shape is only valid for write-heavy workloads";
            }
            if (self.sync_method != .write_then_sync) {
                return "--sync-method is only valid for write_sync";
            }
            if (self.sync_mode != .end) {
                return "--sync-every is only valid for write-heavy workloads";
            }
        } else if (self.workload == .write_sync) {
            if (self.sync_mode != .end) return "--sync-every is not used by write_sync";
        } else if (self.sync_method != .write_then_sync) {
            return "--sync-method is only valid for write_sync";
        }
        return null;
    }
};

/// A parse result: the configuration, or why the arguments are invalid.
pub const Parsed = union(enum) {
    config: Config,
    invalid: []const u8,
};

/// Parses CLI arguments (without the program name) and validates the result (commonware
/// `Config::parse`). Cargo's `--bench` flag is ignored.
pub fn parse(args: []const []const u8) Parsed {
    var config: Config = .{ .workload = .read_seq };
    var workload_set = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "--bench")) continue;
        if (index + 1 >= args.len) return .{ .invalid = "a value is required for every flag" };
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, flag, "--workload")) workload_set = true;
        if (apply(&config, flag, value)) |message| return .{ .invalid = message };
    }
    if (!workload_set) return .{ .invalid = "--workload is required" };
    if (config.validate()) |message| return .{ .invalid = message };
    return .{ .config = config };
}

/// Sets the field `flag` names from `value`, or says why it cannot.
fn apply(config: *Config, flag: []const u8, value: []const u8) ?[]const u8 {
    const eql = std.mem.eql;
    if (eql(u8, flag, "--backend")) {
        const backend = if (eql(u8, value, "tokio")) "threaded" else value;
        config.backend = enum_value(Backend, backend) orelse return "invalid value for --backend";
    } else if (eql(u8, flag, "--workload")) {
        config.workload = enum_value(Workload, value) orelse return "invalid value for --workload";
    } else if (eql(u8, flag, "--duration")) {
        const seconds = std.fmt.parseInt(u64, value, 10) catch
            return "invalid value for --duration";
        if (seconds == 0) return "--duration must be at least 1";
        config.duration_ns = std.math.mul(u64, seconds, std.time.ns_per_s) catch
            return "--duration is too large";
    } else if (eql(u8, flag, "--io-size")) {
        const bytes = parse_byte_size(value) catch |err| return byte_size_message(err);
        config.io_size = std.math.cast(usize, bytes) orelse
            return "value is too large for this platform";
    } else if (eql(u8, flag, "--inflight")) {
        config.inflight = std.fmt.parseInt(u32, value, 10) catch
            return "invalid value for --inflight";
    } else if (eql(u8, flag, "--worker-threads")) {
        config.worker_threads = std.fmt.parseInt(u32, value, 10) catch
            return "invalid value for --worker-threads";
    } else if (eql(u8, flag, "--ring-size")) {
        config.ring_size = std.fmt.parseInt(u32, value, 10) catch
            return "invalid value for --ring-size";
    } else if (eql(u8, flag, "--file-size")) {
        config.file_size = parse_byte_size(value) catch |err| return byte_size_message(err);
    } else if (eql(u8, flag, "--root")) {
        config.root = value;
    } else return apply_modes(config, flag, value);
    return null;
}

fn apply_modes(config: *Config, flag: []const u8, value: []const u8) ?[]const u8 {
    const eql = std.mem.eql;
    if (eql(u8, flag, "--cache")) {
        config.cache = enum_value(CacheMode, value) orelse return "invalid value for --cache";
    } else if (eql(u8, flag, "--write-shape")) {
        config.write_shape = enum_value(WriteShape, value) orelse
            return "invalid value for --write-shape";
    } else if (eql(u8, flag, "--sync-method")) {
        config.sync_method = enum_value(SyncMethod, value) orelse
            return "invalid value for --sync-method";
    } else if (eql(u8, flag, "--sync-every")) {
        config.sync_mode = parse_sync_mode(value) catch
            return "--sync-every must be `end` or a positive integer";
    } else if (eql(u8, flag, "--seed")) {
        config.seed = std.fmt.parseInt(u64, value, 10) catch return "invalid value for --seed";
    } else if (eql(u8, flag, "--output")) {
        config.output = enum_value(OutputFormat, value) orelse return "invalid value for --output";
    } else return "unexpected argument";
    return null;
}

fn enum_value(comptime E: type, value: []const u8) ?E {
    return std.meta.stringToEnum(E, value);
}

/// `end`, or a positive per-stream write count (commonware `parse_sync_mode`).
pub fn parse_sync_mode(value: []const u8) error{InvalidSyncMode}!SyncMode {
    if (std.mem.eql(u8, value, "end")) return .end;
    const count = std.fmt.parseInt(u64, value, 10) catch return error.InvalidSyncMode;
    if (count == 0) return error.InvalidSyncMode;
    return .{ .every = count };
}

pub const ByteSizeError = error{ Empty, InvalidNumber, InvalidSuffix, Overflow, Zero };

fn byte_size_message(err: ByteSizeError) []const u8 {
    return switch (err) {
        error.Empty => "size value cannot be empty",
        error.InvalidNumber => "invalid size value",
        error.InvalidSuffix => "invalid size suffix; expected K, M, G, T, KB, MB, GB, TB, " ++
            "KiB, MiB, GiB, or TiB",
        error.Overflow => "size value is too large",
        error.Zero => "size value must be greater than zero",
    };
}

/// A byte count with an optional binary suffix: `K`, `M`, `G`, `T`, `KB`, `MB`, `GB`, `TB`,
/// `KiB`, `MiB`, `GiB`, or `TiB`, case-insensitive; `_` separates digits (commonware
/// `parse_byte_size`).
pub fn parse_byte_size(value: []const u8) ByteSizeError!u64 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return error.Empty;
    var split: usize = 0;
    while (split < trimmed.len and (std.ascii.isDigit(trimmed[split]) or trimmed[split] == '_'))
        split += 1;
    if (split == 0) return error.InvalidNumber;
    var number: u64 = 0;
    var digits: u32 = 0;
    for (trimmed[0..split]) |char| {
        if (char == '_') continue;
        number = std.math.mul(u64, number, 10) catch return error.InvalidNumber;
        number = std.math.add(u64, number, char - '0') catch return error.InvalidNumber;
        digits += 1;
    }
    if (digits == 0) return error.InvalidNumber;
    const multiplier = try suffix_multiplier(std.mem.trim(u8, trimmed[split..], " \t"));
    const result = std.math.mul(u64, number, multiplier) catch return error.Overflow;
    if (result == 0) return error.Zero;
    return result;
}

fn suffix_multiplier(suffix: []const u8) ByteSizeError!u64 {
    if (suffix.len > 3) return error.InvalidSuffix;
    var upper: [3]u8 = undefined;
    const name = std.ascii.upperString(&upper, suffix);
    const units = [_]struct { []const u8, []const u8, []const u8, u64 }{
        .{ "", "B", "B", 1 },
        .{ "K", "KB", "KIB", 1 << 10 },
        .{ "M", "MB", "MIB", 1 << 20 },
        .{ "G", "GB", "GIB", 1 << 30 },
        .{ "T", "TB", "TIB", 1 << 40 },
    };
    for (units) |unit| {
        const eql = std.mem.eql;
        if (eql(u8, name, unit[0]) or eql(u8, name, unit[1]) or eql(u8, name, unit[2])) {
            return unit[3];
        }
    }
    return error.InvalidSuffix;
}
