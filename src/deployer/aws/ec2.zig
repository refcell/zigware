//! The pure parts of commonware's `deployer::aws::ec2`: EBS storage classes and their
//! request-side limits, and how a failed `RunInstances` call is classified (retry the same
//! request, try another availability zone, or give up). The EC2 calls themselves go through
//! the AWS client.

const std = @import("std");
const assert = std.debug.assert;
const Failure = @import("failure.zig").Failure;

/// EBS volume types (the EC2 API's `VolumeType`). Any other storage class is refused, as the
/// SDK's `VolumeType::try_parse` refuses unknown values.
pub const VolumeType = enum {
    standard,
    io1,
    io2,
    gp2,
    sc1,
    st1,
    gp3,

    pub fn as_str(volume_type: VolumeType) []const u8 {
        return @tagName(volume_type);
    }
};

/// The volume type named `storage_class`, or the failure naming `target`.
pub fn parse_storage_class(target: []const u8, storage_class: []const u8) union(enum) {
    ok: VolumeType,
    failure: Failure,
} {
    const volume_type = std.meta.stringToEnum(VolumeType, storage_class) orelse return .{
        .failure = .{ .invalid_storage_class = .{
            .target = target,
            .storage_class = storage_class,
        } },
    };
    return .{ .ok = volume_type };
}

/// Validates configured EBS options against the EbsBlockDevice request limits and the gp3,
/// io1, and io2 size ratios (docs.aws.amazon.com/ebs/latest/userguide/general-purpose.html and
/// provisioned-iops.html). Returns null when they are valid.
pub fn validate_storage_options(
    target: []const u8,
    storage_class: VolumeType,
    storage_size: i32,
    storage_iops: ?i32,
    storage_throughput: ?i32,
) ?Failure {
    const class = storage_class.as_str();
    // Provisioned IOPS SSD volumes require an explicit IOPS value at launch.
    const provisioned = storage_class == .io1 or storage_class == .io2;
    if (storage_iops == null and provisioned) {
        return .{ .missing_storage_iops = .{ .target = target, .storage_class = class } };
    }
    if (storage_iops) |iops| {
        if (!iops_valid(storage_class, storage_size, iops)) return .{ .invalid_storage_iops = .{
            .target = target,
            .storage_class = class,
            .storage_iops = iops,
        } };
    }
    // Throughput is a gp3-only request field, capped at 0.25 MiB/s per provisioned IOPS.
    const throughput = storage_throughput orelse return null;
    const invalid: Failure = .{ .invalid_storage_throughput = .{
        .target = target,
        .storage_throughput = throughput,
    } };
    if (throughput < 125 or throughput > 2_000) return invalid;
    if (storage_class != .gp3) return .{ .unsupported_storage_throughput = .{
        .target = target,
        .storage_class = class,
    } };
    if (throughput > @divTrunc(storage_iops orelse 3_000, 4)) return invalid;
    return null;
}

/// Whether `iops` is within the EbsBlockDevice range and the size ratio of `storage_class`.
fn iops_valid(storage_class: VolumeType, storage_size: i32, iops: i32) bool {
    const size: i64 = storage_size;
    const value: i64 = iops;
    const low: i64, const high: i64 = switch (storage_class) {
        .gp3 => .{ 3_000, @min(80_000, @max(3_000, size * 500)) },
        .io1 => .{ 100, @min(64_000, size * 50) },
        .io2 => .{ 100, @min(256_000, size * 1_000) },
        else => return false,
    };
    assert(low > 0);
    return value >= low and value <= high;
}

// --- RunInstances failures ---------------------------------------------------------------------

/// Error code families that no retry fixes: authorization, configuration, and quotas. Some
/// families append a subtype, such as `InvalidAMIID.NotFound`.
const fatal_launch_error_code_prefixes = [_][]const u8{
    "UnauthorizedOperation", "OptInRequired",                "VcpuLimitExceeded",
    "InstanceLimitExceeded", "MaxSpotInstanceCountExceeded", "VolumeLimitExceeded",
    "InvalidParameterValue", "InvalidAMIID",                 "InvalidSubnetID",
    "InvalidGroup",          "InvalidKeyPair",
};

/// The SDK's standard transient error codes, kept because RunInstances disables SDK retries.
const retryable_launch_error_codes = [_][]const u8{
    "Throttling",                     "ThrottlingException",
    "ThrottledException",             "RequestThrottledException",
    "TooManyRequestsException",       "ProvisionedThroughputExceededException",
    "TransactionInProgressException", "RequestLimitExceeded",
    "BandwidthLimitExceeded",         "LimitExceededException",
    "RequestThrottled",               "SlowDown",
    "PriorRequestNotComplete",        "EC2ThrottledException",
    "RequestTimeout",                 "RequestTimeoutException",
};

const retryable_launch_status_codes = [_]u16{ 500, 502, 503, 504 };

/// How a RunInstances call failed: a service error with its code and HTTP status, or a
/// transport failure (timeout, I/O, or an unparseable response), which may resolve on retry.
pub const LaunchError = union(enum) {
    service: struct { code: ?[]const u8, status: u16 },
    transport,
    /// Request construction failed; retrying the same request cannot help.
    construction,
};

/// Whether the region may have capacity for the instance type later.
pub fn is_capacity_error(err: LaunchError) bool {
    return code_is(err, "InsufficientInstanceCapacity");
}

/// Whether the subnet is unusable for the rest of this launch.
pub fn is_subnet_unavailable_error(err: LaunchError) bool {
    return code_is(err, "InsufficientFreeAddressesInSubnet");
}

fn code_is(err: LaunchError, expected: []const u8) bool {
    assert(expected.len > 0);
    const service = switch (err) {
        .service => |service| service,
        else => return false,
    };
    const code = service.code orelse return false;
    return std.mem.eql(u8, code, expected);
}

pub fn is_fatal_launch_error_code(code: []const u8) bool {
    for (fatal_launch_error_code_prefixes) |prefix| {
        if (std.mem.startsWith(u8, code, prefix)) return true;
    }
    return false;
}

/// Whether retrying the same idempotent RunInstances request may resolve the failure.
pub fn is_retryable_launch_error(err: LaunchError) bool {
    const service = switch (err) {
        .transport => return true,
        .construction => return false,
        .service => |service| service,
    };
    if (service.code) |code| {
        if (is_fatal_launch_error_code(code)) return false;
        for (retryable_launch_error_codes) |retryable| {
            if (std.mem.eql(u8, code, retryable)) return true;
        }
    }
    return std.mem.indexOfScalar(u16, &retryable_launch_status_codes, service.status) != null;
}

const testing = std.testing;

fn service_error(code: ?[]const u8, status: u16) LaunchError {
    return .{ .service = .{ .code = code, .status = status } };
}

test "launch errors are classified as commonware classifies them" {
    try testing.expect(is_capacity_error(service_error("InsufficientInstanceCapacity", 500)));
    try testing.expect(!is_capacity_error(service_error("InsufficientInstanceCapacity2", 500)));
    try testing.expect(!is_capacity_error(.transport));
    const no_addresses = service_error("InsufficientFreeAddressesInSubnet", 400);
    try testing.expect(is_subnet_unavailable_error(no_addresses));
    // Fatal families match by prefix and win over a retryable status.
    try testing.expect(is_fatal_launch_error_code("InvalidAMIID.NotFound"));
    try testing.expect(!is_retryable_launch_error(service_error("InvalidAMIID.NotFound", 503)));
    try testing.expect(!is_retryable_launch_error(service_error("UnauthorizedOperation", 500)));
    // Throttling codes retry whatever the status; unknown codes retry only on 5xx gateways.
    try testing.expect(is_retryable_launch_error(service_error("RequestLimitExceeded", 400)));
    try testing.expect(is_retryable_launch_error(service_error("Unknown", 503)));
    try testing.expect(!is_retryable_launch_error(service_error("Unknown", 501)));
    try testing.expect(is_retryable_launch_error(service_error(null, 500)));
    try testing.expect(!is_retryable_launch_error(service_error(null, 400)));
    try testing.expect(is_retryable_launch_error(.transport));
    try testing.expect(!is_retryable_launch_error(.construction));
}

test "storage boundaries follow the AWS limits" {
    const Case = struct { VolumeType, i32, ?i32, ?i32, bool };
    for ([_]Case{
        .{ .gp3, 10, 3_000, null, true }, // gp3 floor; 10 GiB still allows 3000
        .{ .gp3, 10, 5_000, null, true },
        .{ .gp3, 10, 5_001, null, false }, // 500 IOPS per GiB
        .{ .gp3, 1_000, 80_000, null, true },
        .{ .gp3, 1_000, 80_001, null, false },
        .{ .io1, 10, 500, null, true },
        .{ .io1, 10, 501, null, false }, // 50 IOPS per GiB
        .{ .io1, 10, 99, null, false },
        .{ .io2, 300, 256_000, null, true },
        .{ .io2, 300, 256_001, null, false },
        .{ .gp3, 10, null, 750, true }, // 3000 / 4
        .{ .gp3, 10, null, 751, false },
        .{ .gp3, 100, 8_000, 2_000, true },
        .{ .gp3, 100, 8_000, 2_001, false },
        .{ .gp3, 10, null, 125, true },
        .{ .gp3, 10, null, 124, false },
        .{ .st1, 500, null, null, true },
        .{ .st1, 500, 100, null, false },
    }) |case| {
        const failure = validate_storage_options("t", case[0], case[1], case[2], case[3]);
        testing.expectEqual(case[4], failure == null) catch |err| {
            std.debug.print("case {any}\n", .{case});
            return err;
        };
    }
    try testing.expect(parse_storage_class("t", "gp3") == .ok);
    try testing.expect(parse_storage_class("t", "GP3") == .failure);
    try testing.expect(parse_storage_class("t", "") == .failure);
}
