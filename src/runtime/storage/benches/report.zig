//! Statistics collection and reporting (commonware `runtime/src/storage/benches/report.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const config_mod = @import("config.zig");
const Config = config_mod.Config;

/// Aggregated stats for one worker stream.
pub const Stats = struct {
    /// Number of completed operations.
    ops: u64 = 0,
    /// Number of bytes transferred.
    bytes: u64 = 0,
    /// Sampled per-operation latencies, in nanoseconds.
    latency_samples: std.ArrayList(u64) = .empty,

    pub fn deinit(self: *Stats, gpa: Allocator) void {
        self.latency_samples.deinit(gpa);
        self.* = undefined;
    }

    /// Records one completed operation, optionally with a latency sample.
    pub fn record(self: *Stats, gpa: Allocator, bytes: u64, latency_ns: ?u64) Allocator.Error!void {
        if (latency_ns) |latency| try self.latency_samples.append(gpa, latency);
        self.ops += 1;
        self.bytes += bytes;
    }

    /// Merges `other` (consumed) into this accumulator.
    pub fn merge(self: *Stats, gpa: Allocator, other: *Stats) Allocator.Error!void {
        try self.latency_samples.appendSlice(gpa, other.latency_samples.items);
        self.ops += other.ops;
        self.bytes += other.bytes;
        other.deinit(gpa);
    }
};

/// Derived metrics for one operation class.
pub const OperationReport = struct {
    ops: u64,
    bytes: u64,
    ops_per_sec: f64,
    mib_per_sec: f64,
    p50_latency_ns: u64,
    p95_latency_ns: u64,
    p99_latency_ns: u64,

    /// Merges `workers` (consumed) and computes summary metrics over `elapsed_ns`.
    pub fn init(gpa: Allocator, workers: []Stats, elapsed_ns: u64) Allocator.Error!OperationReport {
        var merged: Stats = .{};
        defer merged.deinit(gpa);
        for (workers) |*worker| try merged.merge(gpa, worker);
        const samples = merged.latency_samples.items;
        std.sort.pdq(u64, samples, {}, std.sort.asc(u64));
        const elapsed_secs = @max(
            @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s,
            std.math.floatEps(f64),
        );
        const ops: f64 = @floatFromInt(merged.ops);
        const bytes: f64 = @floatFromInt(merged.bytes);
        return .{
            .ops = merged.ops,
            .bytes = merged.bytes,
            .ops_per_sec = ops / elapsed_secs,
            .mib_per_sec = bytes / (1024.0 * 1024.0) / elapsed_secs,
            .p50_latency_ns = percentile(samples, 50),
            .p95_latency_ns = percentile(samples, 95),
            .p99_latency_ns = percentile(samples, 99),
        };
    }

    /// The sample at `pct` percent of sorted `samples` (rounded down), or zero.
    pub fn percentile(samples: []const u64, pct: usize) u64 {
        assert(pct <= 100);
        if (samples.len == 0) return 0;
        return samples[(samples.len - 1) * pct / 100];
    }

    fn print(self: *const OperationReport, writer: *Writer, label: []const u8) Writer.Error!void {
        try writer.print(
            "{s} ops={d} bytes={d} ops_per_sec={d:.0} mib_per_sec={d:.1} p50_us={d:.1} " ++
                "p95_us={d:.1} p99_us={d:.1}\n",
            .{
                label,
                self.ops,
                self.bytes,
                self.ops_per_sec,
                self.mib_per_sec,
                micros(self.p50_latency_ns),
                micros(self.p95_latency_ns),
                micros(self.p99_latency_ns),
            },
        );
    }

    fn write_json(self: *const OperationReport, writer: *Writer) Writer.Error!void {
        try writer.print(
            "{{\"ops\":{d},\"bytes\":{d},\"ops_per_sec\":{d},\"mib_per_sec\":{d}," ++
                "\"p50_latency_ns\":{d},\"p95_latency_ns\":{d},\"p99_latency_ns\":{d}}}",
            .{
                self.ops,            self.bytes,          self.ops_per_sec,
                self.mib_per_sec,    self.p50_latency_ns, self.p95_latency_ns,
                self.p99_latency_ns,
            },
        );
    }
};

fn micros(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000.0;
}

/// Full benchmark report.
pub const Report = struct {
    /// Actual elapsed time, including any final end-of-run sync.
    elapsed_ns: u64,
    read: ?OperationReport,
    write: ?OperationReport,
    /// Final logical file size.
    final_file_size: u64,

    /// A report from worker stats (consumed); null for the side this workload lacks.
    pub fn init(
        gpa: Allocator,
        elapsed_ns: u64,
        read_workers: ?[]Stats,
        write_workers: ?[]Stats,
        final_file_size: u64,
    ) Allocator.Error!Report {
        assert(read_workers != null or write_workers != null);
        const read = if (read_workers) |w| try OperationReport.init(gpa, w, elapsed_ns) else null;
        const write = if (write_workers) |w| try OperationReport.init(gpa, w, elapsed_ns) else null;
        return .{
            .elapsed_ns = elapsed_ns,
            .read = read,
            .write = write,
            .final_file_size = final_file_size,
        };
    }

    /// A concise human-readable report.
    pub fn print_human(self: *const Report, writer: *Writer, cfg: *const Config) Writer.Error!void {
        const elapsed_s = @as(f64, @floatFromInt(self.elapsed_ns)) / std.time.ns_per_s;
        try writer.print("backend={t} workload={t} elapsed_s={d:.3}\n", .{
            cfg.backend, cfg.workload, elapsed_s,
        });
        try writer.print("io_size={d} inflight={d} worker_threads=", .{
            cfg.io_size,
            cfg.inflight,
        });
        if (cfg.worker_threads) |count| {
            try writer.print("{d}", .{count});
        } else try writer.writeAll("default");
        try writer.print(" seed={d} output={t}\n", .{ cfg.seed, cfg.output });
        if (cfg.effective_ring_size()) |size| try writer.print("ring_size={d}\n", .{size});
        if (cfg.file_size) |size| try writer.print("file_size={d}\n", .{size});
        try writer.print("root={s}\n", .{cfg.root});
        if (cfg.cache) |cache| try writer.print("cache={t}\n", .{cache});
        if (cfg.workload.has_writes()) {
            try writer.print("write_shape={t}\n", .{cfg.write_shape});
            if (cfg.workload == .write_sync) {
                try writer.print("sync_method={t}\n", .{cfg.sync_method});
            } else {
                try writer.print("sync_every={f}\n", .{cfg.sync_mode});
            }
        }
        if (self.read) |*read| try read.print(writer, "read");
        if (self.write) |*write| try write.print(writer, "write");
        try writer.print("final_file_size={d}\n", .{self.final_file_size});
    }

    /// A single JSON object for downstream processing.
    pub fn print_json(self: *const Report, writer: *Writer, cfg: *const Config) Writer.Error!void {
        try writer.print("{{\"backend\":\"{t}\",\"workload\":\"{t}\",\"duration_seconds\":{d}," ++
            "\"io_size\":{d},\"inflight\":{d},\"worker_threads\":", .{
            cfg.backend,                         cfg.workload,
            cfg.duration_ns / std.time.ns_per_s, cfg.io_size,
            cfg.inflight,
        });
        try json_optional(writer, cfg.worker_threads);
        try writer.writeAll(",\"ring_size\":");
        try json_optional(writer, cfg.effective_ring_size());
        try writer.writeAll(",\"file_size\":");
        try json_optional(writer, cfg.file_size);
        try writer.writeAll(",\"root\":");
        try std.json.Stringify.encodeJsonString(cfg.root, .{}, writer);
        try writer.writeAll(",\"cache\":");
        if (cfg.cache) |cache| {
            try writer.print("\"{t}\"", .{cache});
        } else try writer.writeAll("null");
        try writer.writeAll(",\"write_shape\":");
        if (cfg.workload.has_writes()) {
            try writer.print("\"{t}\"", .{cfg.write_shape});
        } else try writer.writeAll("null");
        try writer.writeAll(",\"sync_every\":");
        if (cfg.workload.has_writes() and cfg.workload != .write_sync) {
            try writer.print("\"{f}\"", .{cfg.sync_mode});
        } else try writer.writeAll("null");
        try writer.writeAll(",\"sync_method\":");
        if (cfg.workload == .write_sync) {
            try writer.print("\"{t}\"", .{cfg.sync_method});
        } else try writer.writeAll("null");
        try writer.print(",\"seed\":{d},\"elapsed_ns\":{d},\"read\":", .{
            cfg.seed,
            self.elapsed_ns,
        });
        if (self.read) |*read| try read.write_json(writer) else try writer.writeAll("null");
        try writer.writeAll(",\"write\":");
        if (self.write) |*write| try write.write_json(writer) else try writer.writeAll("null");
        try writer.print(",\"final_file_size\":{d}}}\n", .{self.final_file_size});
    }
};

fn json_optional(writer: *Writer, value: anytype) Writer.Error!void {
    if (value) |present| try writer.print("{d}", .{present}) else try writer.writeAll("null");
}
