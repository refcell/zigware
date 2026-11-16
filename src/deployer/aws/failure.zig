//! Why a deployment was refused before any AWS call: the configuration variants of commonware's
//! `deployer::aws::Error`, with their payloads. Zig errors carry no data, so validation returns
//! a `Failure` (null when valid); `format` prints commonware's `Display` text.

const std = @import("std");
const Io = std.Io;

pub const Failure = union(enum) {
    invalid_tag: []const u8,
    invalid_instance_name: []const u8,
    duplicate_instance_name: []const u8,
    invalid_storage_class: struct { target: []const u8, storage_class: []const u8 },
    missing_storage_iops: struct { target: []const u8, storage_class: []const u8 },
    invalid_storage_iops: struct {
        target: []const u8,
        storage_class: []const u8,
        storage_iops: i32,
    },
    unsupported_storage_throughput: struct { target: []const u8, storage_class: []const u8 },
    invalid_storage_throughput: struct { target: []const u8, storage_throughput: i32 },
    availability_zone_group_unsupported: struct {
        region: []const u8,
        group: []const u8,
        /// Sorted and distinct, as commonware's `BTreeSet` yields them.
        instance_types: []const []const u8,
    },

    pub fn format(failure: Failure, writer: *Io.Writer) Io.Writer.Error!void {
        switch (failure) {
            .invalid_tag => |tag| try writer.print(
                "invalid tag (must match [A-Za-z0-9_-]+): {s}",
                .{tag},
            ),
            .invalid_instance_name => |name| try writer.print(
                "invalid instance name (must match [A-Za-z0-9_-]+ and not be `monitoring`): {s}",
                .{name},
            ),
            .duplicate_instance_name => |name| try writer.print(
                "duplicate instance name: {s}",
                .{name},
            ),
            .invalid_storage_class => |f| try writer.print(
                "invalid storage class for {s}: {s}",
                .{ f.target, f.storage_class },
            ),
            .missing_storage_iops => |f| try writer.print(
                "storage_iops is required for {s} when storage_class is {s}",
                .{ f.target, f.storage_class },
            ),
            .invalid_storage_iops => |f| try writer.print(
                "storage_iops for {s} is invalid for storage_class {s}: {d}",
                .{ f.target, f.storage_class, f.storage_iops },
            ),
            .unsupported_storage_throughput => |f| try writer.print(
                "storage_throughput is only supported for {s} when storage_class is gp3: {s}",
                .{ f.target, f.storage_class },
            ),
            .invalid_storage_throughput => |f| try writer.print(
                "storage_throughput for {s} must be between 125 and 2000 MiB/s: {d}",
                .{ f.target, f.storage_throughput },
            ),
            .availability_zone_group_unsupported => |f| {
                try writer.print(
                    "availability zone group '{s}' in region '{s}' has no mutually-supported " ++
                        "AZ for instance types ",
                    .{ f.group, f.region },
                );
                try write_debug_list(writer, f.instance_types);
            },
        }
    }
};

/// Rust's `Debug` of a `Vec<String>`: `["a", "b"]`.
fn write_debug_list(writer: *Io.Writer, items: []const []const u8) Io.Writer.Error!void {
    try writer.writeByte('[');
    for (items, 0..) |item, index| {
        if (index > 0) try writer.writeAll(", ");
        try writer.writeByte('"');
        for (item) |byte| switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11, 12, 14...31, 127 => try writer.print("\\u{{{x}}}", .{byte}),
            else => try writer.writeByte(byte),
        };
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}

const testing = std.testing;

test "failures print commonware's messages" {
    var buffer: [256]u8 = undefined;
    const failure: Failure = .{ .availability_zone_group_unsupported = .{
        .region = "us-east-1",
        .group = "indexers",
        .instance_types = &.{ "c8g.4xlarge", "m8g.large" },
    } };
    try testing.expectEqualStrings(
        "availability zone group 'indexers' in region 'us-east-1' has no mutually-supported " ++
            "AZ for instance types [\"c8g.4xlarge\", \"m8g.large\"]",
        try std.fmt.bufPrint(&buffer, "{f}", .{failure}),
    );
    const iops: Failure = .{ .invalid_storage_iops = .{
        .target = "worker",
        .storage_class = "io1",
        .storage_iops = 64_001,
    } };
    try testing.expectEqualStrings(
        "storage_iops for worker is invalid for storage_class io1: 64001",
        try std.fmt.bufPrint(&buffer, "{f}", .{iops}),
    );
}
