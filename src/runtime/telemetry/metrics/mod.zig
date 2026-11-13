//! Metrics (commonware `runtime::telemetry::metrics`): a registry of counters, gauges,
//! histograms, and labeled families, encoded in the OpenMetrics text format byte-identical to
//! commonware's (prometheus-client 0.25).
//!
//! ```zig
//! var registry: metrics.Registry = .init(gpa);
//! defer registry.deinit();
//! const root: metrics.Scope = .init(&registry);
//! const engine = root.child("engine").with_attribute("epoch", 5);
//! var votes = try engine.counter("votes", "vote count");
//! defer votes.deinit();
//! votes.metric().inc(); // engine_votes_total{epoch="5"} 1
//! const text = try root.encode(gpa);
//! ```

const std = @import("std");
const assert = std.debug.assert;

pub const encoding = @import("encoding.zig");
pub const raw = @import("raw.zig");
pub const registry = @import("registry.zig");
pub const scope = @import("scope.zig");
pub const dtoa = @import("dtoa.zig");
pub const histogram = @import("histogram.zig");
pub const batched = @import("batched.zig");
pub const status = @import("status.zig");
pub const task = @import("task.zig");

pub const MetricType = encoding.MetricType;
pub const Registry = registry.Registry;
pub const Registered = registry.Registered;
pub const Registration = registry.Registration;
pub const Attribute = registry.Attribute;
pub const Scope = scope.Scope;
pub const Buckets = histogram.Buckets;
pub const Timed = histogram.Timed;
pub const Batched = batched.Batched;
pub const metrics_prefix = registry.metrics_prefix;
pub const is_valid_label = registry.is_valid_label;
pub const validate_label = registry.validate_label;

/// A registered counter.
pub const Counter = Registered(raw.Counter);
/// A registered gauge.
pub const Gauge = Registered(raw.Gauge);
/// A registered histogram.
pub const Histogram = Registered(raw.Histogram);
/// A registered family of counters keyed by `L`.
pub fn CounterFamily(comptime L: type) type {
    return Registered(raw.Family(L, raw.Counter));
}
/// A registered family of gauges keyed by `L`.
pub fn GaugeFamily(comptime L: type) type {
    return Registered(raw.Family(L, raw.Gauge));
}

/// Whether an encoded sample name is `name` or ends in `_<name>`.
fn matches_metric_name(full: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, full, name)) return true;
    if (!std.mem.endsWith(u8, full, name)) return false;
    const prefix = full[0 .. full.len - name.len];
    return prefix.len > 0 and prefix[prefix.len - 1] == '_';
}

/// One encoded sample: its label set without braces (empty when unlabeled) and its value.
pub const Sample = struct {
    labels: []const u8,
    value: []const u8,
};

/// Iterates the samples of encoded metrics whose name is `name` or ends in `_<name>`
/// (commonware `metric_samples`, a test utility).
pub const SampleIterator = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    name: []const u8,

    pub fn next(iterator: *SampleIterator) ?Sample {
        while (iterator.lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, &std.ascii.whitespace);
            if (parse_sample(line, iterator.name)) |sample| return sample;
        }
        return null;
    }

    fn parse_sample(line: []const u8, name: []const u8) ?Sample {
        if (line.len == 0 or line[0] == '#') return null;
        const name_end = std.mem.indexOfAny(u8, line, "{ \t\r\n") orelse return null;
        if (!matches_metric_name(line[0..name_end], name)) return null;
        var rest = line[name_end..];
        var labels: []const u8 = "";
        if (rest[0] == '{') {
            const labels_end = label_set_end(rest[1..]) orelse return null;
            labels = rest[1 .. 1 + labels_end];
            rest = rest[labels_end + 2 ..];
        }
        if (rest.len == 0 or !std.ascii.isWhitespace(rest[0])) return null;
        var values = std.mem.tokenizeAny(u8, rest, &std.ascii.whitespace);
        const value = values.next() orelse return null;
        return .{ .labels = labels, .value = value };
    }

    /// Index of the unquoted `}` ending a label set; values may hold braces and `\"`.
    fn label_set_end(labeled: []const u8) ?usize {
        var quoted = false;
        var escaped = false;
        for (labeled, 0..) |byte, index| {
            if (quoted) {
                if (escaped) {
                    escaped = false;
                } else if (byte == '\\') {
                    escaped = true;
                } else if (byte == '"') {
                    quoted = false;
                }
            } else if (byte == '"') {
                quoted = true;
            } else if (byte == '}') {
                return index;
            }
        }
        return null;
    }
};

pub fn metric_samples(text: []const u8, name: []const u8) SampleIterator {
    return .{ .lines = std.mem.splitScalar(u8, text, '\n'), .name = name };
}

/// Whether encoded metrics hold a sample named `name` (or `*_<name>`) with value `value`
/// (commonware `has_metric_value`). `value` is formatted like Rust's `Display`.
pub fn has_metric_value(text: []const u8, name: []const u8, value: anytype) bool {
    var buffer: [64]u8 = undefined;
    const numeric = switch (@typeInfo(@TypeOf(value))) {
        .int, .comptime_int, .float, .comptime_float => true,
        else => false,
    };
    const format = if (numeric) "{d}" else "{s}";
    const expected = std.fmt.bufPrint(&buffer, format, .{value}) catch return false;
    var samples = metric_samples(text, name);
    while (samples.next()) |sample| {
        if (std.mem.eql(u8, sample.value, expected)) return true;
    }
    return false;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("registry_test.zig");
}
