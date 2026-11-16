//! OpenMetrics text encoding, byte-identical to prometheus-client 0.25 (`encoding/text.rs`),
//! which commonware's registry uses for every sample line.
//!
//! A sample is `name[_suffix]{const_labels,extra_labels,family_labels} value\n`. Const labels
//! are a context's attributes; extra labels are a histogram bucket's `le`; family labels come
//! from a `Family` entry's label set. Braces appear when any of the three is present, even if
//! the family label set is empty (`blank_total{} 1`). Label values are written unescaped, as
//! prometheus-client does. Integers print in decimal (Rust `itoa`); floats go through `dtoa`.

const std = @import("std");
const dtoa = @import("dtoa.zig");
const assert = std.debug.assert;
const Writer = std.Io.Writer;

/// The OpenMetrics type written on a family's `# TYPE` line.
pub const MetricType = enum {
    counter,
    gauge,
    histogram,
    info,
    unknown,

    pub fn as_str(metric_type: MetricType) []const u8 {
        return @tagName(metric_type);
    }
};

/// Longest encoded label set a `Family` accepts (keys, quotes, values, and commas).
pub const label_set_size_max = 1024;

/// Writes `value` as prometheus-client's `EncodeLabelValue` does: strings verbatim, integers in
/// decimal, `bool` as `true`/`false`, `f64` through `dtoa`, enums by `label_value()` when the
/// type declares it and by tag name otherwise, types with a `format` method through `{f}`
/// (commonware's `EncodeStruct`, which uses `Display`), and `null` as the empty string.
pub fn write_label_value(writer: *Writer, value: anytype) Writer.Error!void {
    const T = @TypeOf(value);
    if (@typeInfo(T) == .optional) {
        if (value) |inner| try write_plain_value(writer, inner);
        return;
    }
    try write_plain_value(writer, value);
}

fn write_plain_value(writer: *Writer, value: anytype) Writer.Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int, .comptime_int => try writer.print("{d}", .{value}),
        .float, .comptime_float => {
            comptime assert(T == f64 or T == comptime_float);
            var buffer: [dtoa.buffer_size]u8 = undefined;
            try writer.writeAll(dtoa.format(&buffer, value));
        },
        .bool => try writer.writeAll(if (value) "true" else "false"),
        .@"enum" => |info| {
            if (comptime @hasDecl(T, "label_value")) {
                try writer.writeAll(value.label_value());
            } else if (info.mode == .exhaustive) {
                try writer.writeAll(@tagName(value));
            } else if (std.enums.tagName(T, value)) |name| {
                try writer.writeAll(name);
            } else {
                // A non-exhaustive enum's unnamed value (`enum(u64) { _ }`) has no tag name.
                try writer.print("{d}", .{@backingInt(value)});
            }
        },
        .pointer => {
            comptime assert(is_string(T));
            try writer.writeAll(value);
        },
        .@"struct", .@"union" => {
            comptime assert(@hasDecl(T, "format"));
            try writer.print("{f}", .{value});
        },
        else => @compileError("unsupported label value type " ++ @typeName(T)),
    }
}

fn is_string(comptime T: type) bool {
    const info = @typeInfo(T).pointer;
    return switch (info.size) {
        .slice => info.child == u8,
        .one => @typeInfo(info.child) == .array and @typeInfo(info.child).array.child == u8,
        else => false,
    };
}

/// Writes a label set struct as `field="value",...` in field order, like the
/// `EncodeLabelSet` derive. A struct with no fields writes nothing.
pub fn write_label_set(writer: *Writer, label_set: anytype) Writer.Error!void {
    const T = @TypeOf(label_set);
    const field_names = @typeInfo(T).@"struct".field_names;
    inline for (field_names, 0..) |field_name, index| {
        comptime assert(field_name.len > 0);
        if (index > 0) try writer.writeByte(',');
        try writer.writeAll(field_name ++ "=\"");
        try write_label_value(writer, @field(label_set, field_name));
        try writer.writeByte('"');
    }
}

/// Writes one family's `# HELP` and `# TYPE` lines. `help` already ends with `.`.
pub fn write_descriptor(
    writer: *Writer,
    name: []const u8,
    help: []const u8,
    metric_type: MetricType,
) Writer.Error!void {
    assert(name.len > 0);
    try writer.writeAll("# HELP ");
    try writer.writeAll(name);
    try writer.writeByte(' ');
    try writer.writeAll(help);
    try writer.writeAll("\n# TYPE ");
    try writer.writeAll(name);
    try writer.writeByte(' ');
    try writer.writeAll(metric_type.as_str());
    try writer.writeByte('\n');
}

/// Writes the sample lines of one metric. A metric's `encode_samples` receives one.
pub const SampleEncoder = struct {
    writer: *Writer,
    /// The full metric name, without a type suffix.
    name: []const u8,
    /// The encoded attributes (`key="value",...`), or empty.
    const_labels: []const u8,
    /// The encoded label set of a `Family` entry, or null outside a family.
    family_labels: ?[]const u8 = null,

    /// The encoder for one entry of a family.
    pub fn with_family(encoder: SampleEncoder, family_labels: []const u8) SampleEncoder {
        assert(encoder.family_labels == null);
        var result = encoder;
        result.family_labels = family_labels;
        return result;
    }

    pub fn counter(encoder: SampleEncoder, value: u64) Writer.Error!void {
        try encoder.writer.writeAll(encoder.name);
        try encoder.writer.writeAll("_total");
        try encoder.labels(null);
        try encoder.writer.print(" {d}\n", .{value});
    }

    pub fn gauge(encoder: SampleEncoder, value: i64) Writer.Error!void {
        try encoder.writer.writeAll(encoder.name);
        try encoder.labels(null);
        try encoder.writer.print(" {d}\n", .{value});
    }

    /// `bounds` and `counts` are per bucket (not cumulative); a bound of `f64` max is `+Inf`.
    pub fn histogram(
        encoder: SampleEncoder,
        sum: f64,
        count: u64,
        bounds: []const f64,
        counts: []const u64,
    ) Writer.Error!void {
        assert(bounds.len == counts.len);
        const writer = encoder.writer;
        var buffer: [dtoa.buffer_size]u8 = undefined;
        try writer.writeAll(encoder.name);
        try writer.writeAll("_sum");
        try encoder.labels(null);
        try writer.writeByte(' ');
        try writer.writeAll(dtoa.format(&buffer, sum));
        try writer.writeByte('\n');
        try writer.writeAll(encoder.name);
        try writer.writeAll("_count");
        try encoder.labels(null);
        try writer.print(" {d}\n", .{count});
        var cumulative: u64 = 0;
        for (bounds, counts) |bound, bucket_count| {
            cumulative += bucket_count;
            var label_buffer: [dtoa.buffer_size + 8]u8 = undefined;
            const le = if (bound == std.math.floatMax(f64))
                "le=\"+Inf\""
            else
                std.fmt.bufPrint(&label_buffer, "le=\"{s}\"", .{dtoa.format(&buffer, bound)}) catch
                    unreachable; // 25 formatted bytes plus `le=""` fit in 33.
            try writer.writeAll(encoder.name);
            try writer.writeAll("_bucket");
            try encoder.labels(le);
            try writer.print(" {d}\n", .{cumulative});
        }
        assert(cumulative <= count);
    }

    /// prometheus-client's `encode_labels`: const labels, then the extra label, then the family
    /// labels, comma-separated, inside braces whenever any of them is present.
    fn labels(encoder: SampleEncoder, extra: ?[]const u8) Writer.Error!void {
        const writer = encoder.writer;
        if (encoder.const_labels.len == 0 and extra == null and encoder.family_labels == null) {
            return;
        }
        try writer.writeByte('{');
        try writer.writeAll(encoder.const_labels);
        if (extra) |label| {
            if (encoder.const_labels.len > 0) try writer.writeByte(',');
            try writer.writeAll(label);
        }
        if (encoder.family_labels) |family_labels| {
            // A comma only when the family actually writes something after other labels.
            const preceded = encoder.const_labels.len > 0 or extra != null;
            if (preceded and family_labels.len > 0) try writer.writeByte(',');
            try writer.writeAll(family_labels);
        }
        try writer.writeByte('}');
    }
};

const testing = std.testing;

test "label values encode like prometheus-client" {
    var buffer: [256]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    const Kind = enum {
        shared_blocking,
        root,
        pub fn label_value(kind: @This()) []const u8 {
            return switch (kind) {
                .shared_blocking => "SharedBlocking",
                .root => "Root",
            };
        }
    };
    const Plain = enum { Success };
    const Labels = struct {
        method: []const u8,
        status: u16,
        ok: bool,
        kind: Kind,
        plain: Plain,
        ratio: f64,
        missing: ?u32,
        delta: i64,
    };
    try write_label_set(&writer, Labels{
        .method = "a\"b}",
        .status = 200,
        .ok = false,
        .kind = .shared_blocking,
        .plain = .Success,
        .ratio = 0.001,
        .missing = null,
        .delta = std.math.minInt(i64),
    });
    try testing.expectEqualStrings(
        "method=\"a\"b}\",status=\"200\",ok=\"false\",kind=\"SharedBlocking\"," ++
            "plain=\"Success\",ratio=\"0.001\",missing=\"\",delta=\"-9223372036854775808\"",
        writer.buffered(),
    );
}

test "label placement matches prometheus-client" {
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    const bare: SampleEncoder = .{ .writer = &writer, .name = "a", .const_labels = "" };
    try bare.counter(1);
    try bare.with_family("").counter(2);
    try bare.with_family("peer=\"x\"").gauge(-3);
    const attributed: SampleEncoder = .{
        .writer = &writer,
        .name = "b",
        .const_labels = "e=\"1\"",
    };
    try attributed.with_family("").gauge(4);
    try attributed.with_family("peer=\"y\"").histogram(
        0.25,
        1,
        &.{ 0.5, std.math.floatMax(f64) },
        &.{ 1, 0 },
    );
    try testing.expectEqualStrings(
        \\a_total 1
        \\a_total{} 2
        \\a{peer="x"} -3
        \\b{e="1"} 4
        \\b_sum{e="1",peer="y"} 0.25
        \\b_count{e="1",peer="y"} 1
        \\b_bucket{e="1",le="0.5",peer="y"} 1
        \\b_bucket{e="1",le="+Inf",peer="y"} 1
        \\
    , writer.buffered());
}
