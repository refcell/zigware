//! commonware's `deployer::aws::ec2`: EBS storage classes and their request-side limits, how a
//! failed `RunInstances` call is classified (retry the same request, try another availability
//! zone, or give up), and `launch_instances`, which sends `RunInstances` through the AWS client.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Failure = @import("failure.zig").Failure;
const aws = @import("mod.zig");
const aws_utils = @import("utils.zig");
const create = @import("create.zig");
const query = @import("query.zig");
const Client = @import("client.zig").Client;

const log = std.log.scoped(.deployer);

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
    service: struct { code: ?[]const u8, status: u16, message: ?[]const u8 = null },
    transport,
    /// Request construction failed; retrying the same request cannot help.
    construction,
    /// A dispatch failure the transport did not classify as transient (such as failing to
    /// resolve credentials); retrying cannot help.
    dispatch,

    /// The SDK's error text differs; this names the same facts.
    pub fn format(err: LaunchError, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (err) {
            .service => |service| {
                try writer.print("service error (status {d})", .{service.status});
                if (service.code) |code| try writer.print(": {s}", .{code});
                if (service.message) |message| try writer.print(": {s}", .{message});
            },
            .transport => try writer.writeAll("transport failure"),
            .construction => try writer.writeAll("request construction failure"),
            .dispatch => try writer.writeAll("dispatch failure"),
        }
    }
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
        .construction, .dispatch => return false,
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

// --- RunInstances ------------------------------------------------------------------------------

/// How long `launch_instances` waits before retrying (zero in tests, as in commonware).
pub const launch_retry_interval_ms: u64 = if (builtin.is_test) 0 else aws_utils.retry_interval_ms;

/// What to launch: commonware `launch_instances`' arguments other than the subnets.
pub const LaunchRequest = struct {
    ami_id: []const u8,
    instance_type: []const u8,
    storage_size: i32,
    storage_class: VolumeType,
    storage_iops: ?i32 = null,
    storage_throughput: ?i32 = null,
    bandwidth_weighting: aws.BandwidthWeighting = .default,
    key_name: []const u8,
    sg_id: []const u8,
    count: i32,
    name: []const u8,
    tag: []const u8,
};

pub const Launched = struct { instance_ids: []const []const u8, az: []const u8 };

pub const LaunchResult = union(enum) { ok: Launched, failure: Failure };

/// The `RunInstances` Query body for one probe of `subnet_id` (allocates from `arena`).
/// Parameter order is not significant to EC2.
pub fn run_instances_body(
    arena: Allocator,
    request: *const LaunchRequest,
    subnet_id: []const u8,
    client_token: []const u8,
) ![]const u8 {
    assert(subnet_id.len > 0);
    assert(client_token.len > 0);
    var body = try query.Body.init(arena, "RunInstances", query.ec2_version);
    try body.add("BlockDeviceMapping.1.DeviceName", "/dev/sda1");
    try body.add("BlockDeviceMapping.1.Ebs.DeleteOnTermination", "true");
    if (request.storage_iops) |iops| try body.add_int("BlockDeviceMapping.1.Ebs.Iops", iops);
    if (request.storage_throughput) |throughput| {
        try body.add_int("BlockDeviceMapping.1.Ebs.Throughput", throughput);
    }
    try body.add_int("BlockDeviceMapping.1.Ebs.VolumeSize", request.storage_size);
    try body.add("BlockDeviceMapping.1.Ebs.VolumeType", request.storage_class.as_str());
    try body.add("ImageId", request.ami_id);
    try body.add("InstanceType", request.instance_type);
    try body.add("KeyName", request.key_name);
    try body.add_int("MaxCount", request.count);
    try body.add_int("MinCount", request.count);
    try body.add("TagSpecification.1.ResourceType", "instance");
    try body.add("TagSpecification.1.Tag.1.Key", "deployer");
    try body.add("TagSpecification.1.Tag.1.Value", request.tag);
    try body.add("TagSpecification.1.Tag.2.Key", "name");
    try body.add("TagSpecification.1.Tag.2.Value", request.name);
    try body.add("ClientToken", client_token);
    try body.add("NetworkInterface.1.AssociatePublicIpAddress", "true");
    try body.add("NetworkInterface.1.DeviceIndex", "0");
    try body.add("NetworkInterface.1.SecurityGroupId.1", request.sg_id);
    try body.add("NetworkInterface.1.SubnetId", subnet_id);
    // The standard split is left unset so instance types without configurable weighting
    // launch unchanged.
    if (!request.bandwidth_weighting.is_default()) {
        const weighting = request.bandwidth_weighting.name();
        try body.add("NetworkPerformanceOptions.BandwidthWeighting", weighting);
    }
    return body.written();
}

/// A random (version 4) UUID, as `uuid::Uuid::new_v4().to_string()` formats it.
pub fn new_client_token(io: Io) [36]u8 {
    var bytes: [16]u8 = undefined;
    io.random(&bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(bytes, .lower);
    var out: [36]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{s}-{s}-{s}-{s}-{s}", .{
        hex[0..8], hex[8..12], hex[12..16], hex[16..20], hex[20..32],
    }) catch unreachable; // Proof: 32 hex digits and 4 dashes fill exactly 36 bytes.
    assert(out[14] == '4');
    return out;
}

const Attempt = union(enum) { instances: []const []const u8, failed: LaunchError };

/// Sends one `RunInstances` request. Results are allocated from `arena`.
fn try_launch_instances(client: *const Client, arena: Allocator, body: []const u8) !Attempt {
    assert(body.len > 0);
    const outcome = try client.ec2_query(arena, body);
    const response = switch (outcome) {
        .io_failure, .timeout => return .{ .failed = .transport },
        .other => |other| return .{ .failed = if (other.transient) .transport else .dispatch },
        .response => |response| response,
    };
    if (response.status < 200 or response.status >= 300) {
        // An unreadable error body is still a service error, classified by its status.
        const parsed = query.service_error(arena, response.body) catch
            query.ServiceError{ .code = null, .message = null };
        return .{ .failed = .{ .service = .{
            .code = parsed.code,
            .status = response.status,
            .message = parsed.message,
        } } };
    }
    var ids: std.ArrayList([]const u8) = .empty;
    const path = [_][]const u8{ "RunInstancesResponse", "instancesSet", "item", "instanceId" };
    const Collector = struct { list: *std.ArrayList([]const u8), arena: Allocator, failed: bool };
    var collector: Collector = .{ .list = &ids, .arena = arena, .failed = false };
    query.scan(response.body, &path, &collector, struct {
        fn visit(c: *Collector, text: []const u8) bool {
            c.list.append(c.arena, text) catch {
                c.failed = true;
                return false;
            };
            return true;
        }
    }.visit) catch return .{ .failed = .transport }; // Like the SDK's response error.
    if (collector.failed) return error.OutOfMemory;
    if (ids.items.len == 0) return .{ .failed = .transport };
    return .{ .instances = ids.items };
}

/// Launches EC2 instances (commonware `launch_instances`). Filters `subnets` to availability
/// zones that offer the instance type, probes them in turn from `start_index`, and rescans every
/// usable subnet after a capacity failure; a subnet out of addresses is dropped for this launch.
/// Each probe owns one client token across retries of the same request. Results are allocated
/// from `arena`; each attempt's scratch comes from `gpa` and is freed.
pub fn launch_instances(
    client: *const Client,
    gpa: Allocator,
    arena: Allocator,
    request: *const LaunchRequest,
    subnets: []const create.Subnet,
    az_support: []const create.AzSupport,
    start_index: usize,
) !LaunchResult {
    if (validate_storage_options(
        request.name,
        request.storage_class,
        request.storage_size,
        request.storage_iops,
        request.storage_throughput,
    )) |failure| return .{ .failure = failure };
    const eligible = try eligible_subnets(arena, request.instance_type, subnets, az_support);
    if (eligible.len == 0) {
        return .{ .failure = .{ .unsupported_instance_type = request.instance_type } };
    }
    const unavailable = try arena.alloc(bool, eligible.len);
    @memset(unavailable, false);
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    var last_error: ?LaunchError = null;
    var scan: u64 = 0;
    // Retries until capacity returns, as commonware does; a canceled sleep ends it.
    while (true) {
        scan +|= 1;
        var retry_capacity = false;
        for (0..eligible.len) |offset| {
            const index = (start_index + offset) % eligible.len;
            if (unavailable[index]) continue;
            const subnet = eligible[index];
            const err = switch (try probe(client, &scratch, arena, request, subnet.id)) {
                .instances => |ids| return .{ .ok = .{ .instance_ids = ids, .az = subnet.az } },
                .failed => |err| err,
            };
            last_error = err;
            if (is_capacity_error(err)) {
                retry_capacity = true;
                log.warn("insufficient instance capacity, trying next subnet: name={s} " ++
                    "az={s} scan={d} error={f}", .{ request.name, subnet.az, scan, err });
            } else if (is_subnet_unavailable_error(err)) {
                unavailable[index] = true;
                log.debug("subnet unavailable, trying next subnet: name={s} az={s} error={f}", .{
                    request.name, subnet.az, err,
                });
            } else return .{ .failure = .{ .aws_ec2 = err } };
        }
        // Another scan starts only after a capacity failure; other completed scans are final.
        if (!retry_capacity) break;
        try client.io.sleep(.fromMilliseconds(launch_retry_interval_ms), .awake);
    }
    // Proof: the first scan probes every eligible subnet, and there is at least one.
    return .{ .failure = .{ .aws_ec2 = last_error.? } };
}

/// The subnets whose availability zone offers `instance_type`, in order.
fn eligible_subnets(
    arena: Allocator,
    instance_type: []const u8,
    subnets: []const create.Subnet,
    az_support: []const create.AzSupport,
) ![]const create.Subnet {
    assert(instance_type.len > 0);
    var eligible: std.ArrayList(create.Subnet) = try .initCapacity(arena, subnets.len);
    for (subnets) |subnet| {
        const support = for (az_support) |support| {
            if (std.mem.eql(u8, support.az, subnet.az)) break support;
        } else continue;
        for (support.instance_types) |offered| {
            if (std.mem.eql(u8, offered, instance_type)) {
                eligible.appendAssumeCapacity(subnet);
                break;
            }
        }
    }
    assert(eligible.items.len <= subnets.len);
    return eligible.items;
}

/// Probes one subnet: retries the same request, with the same client token, while the failure
/// is retryable and says nothing about capacity or addresses. The result is copied to `arena`.
fn probe(
    client: *const Client,
    scratch: *std.heap.ArenaAllocator,
    arena: Allocator,
    request: *const LaunchRequest,
    subnet_id: []const u8,
) !Attempt {
    const token = new_client_token(client.io);
    while (true) {
        _ = scratch.reset(.retain_capacity);
        const allocator = scratch.allocator();
        const body = try run_instances_body(allocator, request, subnet_id, &token);
        const err = switch (try try_launch_instances(client, allocator, body)) {
            .instances => |ids| {
                const owned = try arena.alloc([]const u8, ids.len);
                for (owned, ids) |*slot, id| slot.* = try arena.dupe(u8, id);
                return .{ .instances = owned };
            },
            .failed => |err| err,
        };
        const moves_on = is_capacity_error(err) or is_subnet_unavailable_error(err);
        if (moves_on or !is_retryable_launch_error(err)) {
            return .{ .failed = try dupe_launch_error(arena, err) };
        }
        log.debug("launch_instances failed, retrying: name={s} error={f}", .{ request.name, err });
        try client.io.sleep(.fromMilliseconds(launch_retry_interval_ms), .awake);
    }
}

fn dupe_launch_error(arena: Allocator, err: LaunchError) !LaunchError {
    const service = switch (err) {
        .service => |service| service,
        else => return err,
    };
    return .{ .service = .{
        .code = if (service.code) |code| try arena.dupe(u8, code) else null,
        .status = service.status,
        .message = if (service.message) |message| try arena.dupe(u8, message) else null,
    } };
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
    try testing.expect(!is_retryable_launch_error(.dispatch));
}

test {
    _ = @import("ec2_test.zig");
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
