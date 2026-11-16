//! Why a deployment failed: the configuration and launch variants of commonware's
//! `deployer::aws::Error`, with their payloads. Zig errors carry no data, so validation returns
//! a `Failure` (null when valid); `format` prints commonware's `Display` text.

const std = @import("std");
const Io = std.Io;
const LaunchError = @import("client.zig").ApiError;
const s3 = @import("s3.zig");

/// Why accessing a bucket was refused.
pub const BucketForbiddenReason = enum {
    /// Missing `s3:ListBucket` permission, or another account owns the bucket.
    access_denied,

    pub fn text(reason: BucketForbiddenReason) []const u8 {
        return switch (reason) {
            .access_denied => "access denied (check IAM permissions or bucket ownership)",
        };
    }
};

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
    unsupported_instance_type: []const u8,
    no_subnets_available,
    deployment_does_not_exist: []const u8,
    deployment_not_complete: []const u8,
    deployment_already_destroyed: []const u8,
    /// Rust's `AddrParseError`.
    ip_addr_parse,
    ip_addr_not_v4: []const u8,
    private_key_not_found,
    instance_not_found: []const u8,
    metadata_not_found: []const u8,
    missing_tag_or_config,
    regions_not_enabled: []const []const u8,
    creation_attempted,
    /// A file could not be read or written; `error` names the cause.
    io: struct { path: []const u8, err: anyerror },
    /// A YAML file did not parse as the expected type.
    yaml: []const u8,
    /// Neither the environment nor the shared credentials file had credentials.
    no_credentials,
    aws_ec2: LaunchError,
    aws_s3: struct { bucket: []const u8, operation: s3.Operation, err: LaunchError },
    s3_bucket_forbidden: struct { bucket: []const u8, reason: BucketForbiddenReason },

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
            else => try format_operation(failure, writer),
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

/// The failures of commands talking to AWS or the filesystem.
fn format_operation(failure: Failure, writer: *Io.Writer) Io.Writer.Error!void {
    switch (failure) {
        .unsupported_instance_type => |instance_type| try writer.print(
            "no subnet supports instance type: {s}",
            .{instance_type},
        ),
        .no_subnets_available => try writer.writeAll("no subnets available"),
        .deployment_does_not_exist => |tag| try writer.print(
            "deployment does not exist: {s}",
            .{tag},
        ),
        .deployment_not_complete => |tag| try writer.print(
            "deployment is not complete: {s}",
            .{tag},
        ),
        .deployment_already_destroyed => |tag| try writer.print(
            "deployment already destroyed: {s}",
            .{tag},
        ),
        .ip_addr_parse => try writer.writeAll("invalid IP address: invalid IP address syntax"),
        .ip_addr_not_v4 => |ip| try writer.print("IP address is not IPv4: {s}", .{ip}),
        .private_key_not_found => try writer.writeAll("private key not found"),
        .instance_not_found => |ip| try writer.print("instance not found: {s}", .{ip}),
        .metadata_not_found => |tag| try writer.print(
            "metadata not found for deployment: {s}",
            .{tag},
        ),
        .missing_tag_or_config => try writer.writeAll("must specify either --config or --tag"),
        .regions_not_enabled => |regions| {
            try writer.writeAll("regions not enabled: ");
            try write_debug_list(writer, regions);
        },
        .creation_attempted => try writer.writeAll("creation already attempted"),
        .io => |f| try writer.print("IO error: {s}: {t}", .{ f.path, f.err }),
        .yaml => |path| try writer.print("YAML error: {s}", .{path}),
        .no_credentials => try writer.writeAll(
            "no AWS credentials (set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or " ++
                "add a profile to ~/.aws/credentials)",
        ),
        .aws_ec2 => |err| try writer.print("AWS EC2 error: {f}", .{err}),
        .aws_s3 => |f| try writer.print(
            "S3 operation failed: {f} on bucket '{s}'",
            .{ f.operation, f.bucket },
        ),
        .s3_bucket_forbidden => |f| try writer.print(
            "S3 bucket '{s}' forbidden: {s}",
            .{ f.bucket, f.reason.text() },
        ),
        // Proof: `Failure.format` handles the configuration failures itself.
        else => unreachable,
    }
}

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
