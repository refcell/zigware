//! Utility functions for interacting with EC2 instances (commonware `deployer::aws::utils`).
//!
//! The SSH and SCP helpers run the system `ssh`/`scp` through `std.process` on the caller's
//! `std.Io`, retrying every `retry_interval_ms`. Their argument vectors and the service status
//! rules are pure functions, tested here; the commands themselves are never run by tests.
//! Downloads (`download_file`, `get_public_ip`) live with the HTTP client.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddr = @import("../ip.zig").IpAddr;

const log = std.log.scoped(.deployer);

/// Maximum number of SSH connection attempts before failing.
pub const max_ssh_attempts: u32 = 30;
/// Maximum number of polling attempts for service status.
pub const max_poll_attempts: u32 = 30;
/// Interval between retries.
pub const retry_interval_ms: u64 = 15_000;
/// Maximum attempts per EC2 or S3 request. With the backoff doubling from
/// `sdk_initial_backoff_ms` up to `sdk_max_backoff_ms`, this retries for over two hours.
pub const max_sdk_attempts: u32 = 256;
/// Backoff before the first AWS retry (doubles on each subsequent retry).
pub const sdk_initial_backoff_ms: u64 = 500;
/// Upper bound on the backoff between AWS retries.
pub const sdk_max_backoff_ms: u64 = 30_000;
/// Maximum number of download attempts before failing.
pub const max_download_attempts: u32 = 10;

/// Protocol for deployer ingress.
pub const deployer_protocol = "tcp";
/// Minimum port for deployer ingress.
pub const deployer_min_port: i32 = 0;
/// Maximum port for deployer ingress.
pub const deployer_max_port: i32 = 65535;

/// Longest `ip` the target helpers accept: a hostname or an address.
pub const host_length_max = 253;

pub const Error = error{
    SshFailed,
    /// A service did not reach the wanted state within `max_poll_attempts`.
    ServiceTimeout,
    NoSpaceLeft,
    OutOfMemory,
} || std.process.RunError || std.process.SpawnError || std.process.Child.WaitError;

/// The host part of an SCP target: IPv6 addresses (in Rust's display form) are bracketed;
/// anything else is used as given.
fn scp_host(writer: *Io.Writer, ip: []const u8) Io.Writer.Error!void {
    const parsed = IpAddr.parse(ip) catch return writer.writeAll(ip);
    switch (parsed) {
        .v6 => try writer.print("[{f}]", .{parsed}),
        .v4 => try writer.writeAll(ip),
    }
}

/// `ubuntu@{ip}`.
pub fn ssh_target(buffer: []u8, ip: []const u8) error{NoSpaceLeft}![]const u8 {
    assert(ip.len > 0);
    const target = try std.fmt.bufPrint(buffer, "ubuntu@{s}", .{ip});
    assert(std.mem.endsWith(u8, target, ip));
    return target;
}

/// `ubuntu@{host}:{remote_path}`, with IPv6 hosts bracketed.
pub fn scp_target(
    buffer: []u8,
    ip: []const u8,
    remote_path: []const u8,
) error{NoSpaceLeft}![]const u8 {
    assert(ip.len > 0);
    var writer: Io.Writer = .fixed(buffer);
    writer.writeAll("ubuntu@") catch return error.NoSpaceLeft;
    scp_host(&writer, ip) catch return error.NoSpaceLeft;
    writer.print(":{s}", .{remote_path}) catch return error.NoSpaceLeft;
    assert(std.mem.endsWith(u8, writer.buffered(), remote_path));
    return writer.buffered();
}

/// Whether an interactive SSH session ended normally: exit 0, or 130 after Ctrl-C.
pub fn ssh_attach_code_ok(code: ?i32) bool {
    const value = code orelse return false;
    return value == 0 or value == 130;
}

/// `{ip}/32`.
pub fn exact_cidr(buffer: []u8, ip: []const u8) error{NoSpaceLeft}![]const u8 {
    assert(ip.len > 0);
    return std.fmt.bufPrint(buffer, "{s}/32", .{ip});
}

/// The options every `ssh`/`scp` call passes after the program name.
const ssh_options = [_][]const u8{
    "-o", "IdentitiesOnly=yes", "-o", "ServerAliveInterval=600", "-o", "StrictHostKeyChecking=no",
};

/// Longest argument vector: program, `-i key`, the options, and two operands.
pub const argv_max = 3 + ssh_options.len + 2;

/// `{program} -i {key_file} {options...} {operands...}`.
pub fn ssh_argv(
    out: *[argv_max][]const u8,
    program: []const u8,
    key_file: []const u8,
    operands: []const []const u8,
) []const []const u8 {
    assert(operands.len >= 1 and operands.len <= 2);
    assert(std.mem.eql(u8, program, "ssh") or std.mem.eql(u8, program, "scp"));
    out[0] = program;
    out[1] = "-i";
    out[2] = key_file;
    @memcpy(out[3..][0..ssh_options.len], &ssh_options);
    @memcpy(out[3 + ssh_options.len ..][0..operands.len], operands);
    return out[0 .. 3 + ssh_options.len + operands.len];
}

pub const ServiceState = enum { active, inactive };

/// Whether polling `service` for `wanted` is done given `systemctl is-active`'s output. A
/// failed `binary` service ends the poll too (its logs say why; `update` replaces it).
pub fn service_reached(stdout: []const u8, service: []const u8, wanted: ServiceState) bool {
    assert(service.len > 0);
    const status = std.mem.trim(u8, stdout, &std.ascii.whitespace);
    if (std.mem.eql(u8, status, @tagName(wanted))) return true;
    return std.mem.eql(u8, service, "binary") and std.mem.eql(u8, status, "failed");
}

fn retry_sleep(io: Io) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(@intCast(retry_interval_ms)), .awake);
}

/// Runs `argv` to completion, returning whether it exited with status 0 and its stdout.
fn run(gpa: Allocator, io: Io, argv: []const []const u8) Error!struct { bool, []u8 } {
    assert(argv.len > 0);
    const result = try std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
    });
    defer gpa.free(result.stderr);
    const ok = result.term == .exited and result.term.exited == 0;
    if (!ok) log.warn("{s} failed: {s}", .{ argv[0], result.stderr });
    return .{ ok, result.stdout };
}

/// Executes `command` on a remote instance via SSH, with retries.
pub fn ssh_execute(
    gpa: Allocator,
    io: Io,
    key_file: []const u8,
    ip: []const u8,
    command: []const u8,
) Error!void {
    var target_buffer: [host_length_max + 8]u8 = undefined;
    const target = try ssh_target(&target_buffer, ip);
    var argv_buffer: [argv_max][]const u8 = undefined;
    const argv = ssh_argv(&argv_buffer, "ssh", key_file, &.{ target, command });
    for (0..max_ssh_attempts) |_| {
        const ok, const stdout = try run(gpa, io, argv);
        gpa.free(stdout);
        if (ok) return;
        try retry_sleep(io);
    }
    return error.SshFailed;
}

/// Opens an interactive SSH session to a remote instance.
pub fn ssh_attach(io: Io, key_file: []const u8, ip: []const u8) Error!void {
    var target_buffer: [host_length_max + 8]u8 = undefined;
    const target = try ssh_target(&target_buffer, ip);
    var argv_buffer: [argv_max][]const u8 = undefined;
    const argv = ssh_argv(&argv_buffer, "ssh", key_file, &.{target});
    assert(argv.len == argv_max - 1);
    var child = try std.process.spawn(io, .{ .argv = argv });
    const term = try child.wait(io);
    const code: ?i32 = if (term == .exited) term.exited else null;
    if (!ssh_attach_code_ok(code)) return error.SshFailed;
}

/// Polls a systemd service on a remote instance until it reaches `wanted`.
pub fn poll_service(
    gpa: Allocator,
    io: Io,
    key_file: []const u8,
    ip: []const u8,
    service: []const u8,
    wanted: ServiceState,
) Error!void {
    var target_buffer: [host_length_max + 8]u8 = undefined;
    const target = try ssh_target(&target_buffer, ip);
    var command_buffer: [256]u8 = undefined;
    const command = try std.fmt.bufPrint(&command_buffer, "systemctl is-active {s}", .{service});
    var argv_buffer: [argv_max][]const u8 = undefined;
    const argv = ssh_argv(&argv_buffer, "ssh", key_file, &.{ target, command });
    for (0..max_poll_attempts) |_| {
        _, const stdout = try run(gpa, io, argv);
        defer gpa.free(stdout);
        if (service_reached(stdout, service, wanted)) return;
        log.warn("service {s} not yet {t}: {s}", .{ service, wanted, stdout });
        try retry_sleep(io);
    }
    log.err("service {s} on {s} timed out", .{ service, ip });
    return error.ServiceTimeout;
}

/// Downloads a file from a remote instance via SCP, with retries.
pub fn scp_download(
    gpa: Allocator,
    io: Io,
    key_file: []const u8,
    ip: []const u8,
    remote_path: []const u8,
    local_path: []const u8,
) Error!void {
    var target_buffer: [host_length_max + 4096]u8 = undefined;
    const target = try scp_target(&target_buffer, ip, remote_path);
    var argv_buffer: [argv_max][]const u8 = undefined;
    const argv = ssh_argv(&argv_buffer, "scp", key_file, &.{ target, local_path });
    for (0..max_ssh_attempts) |_| {
        const ok, const stdout = try run(gpa, io, argv);
        gpa.free(stdout);
        if (ok) return;
        try retry_sleep(io);
    }
    return error.SshFailed;
}

const testing = std.testing;

test "ssh target ipv4" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("ubuntu@1.2.3.4", try ssh_target(&buffer, "1.2.3.4"));
}

test "ssh target ipv6" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("ubuntu@2001:db8::1", try ssh_target(&buffer, "2001:db8::1"));
}

test "scp target ipv6" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "ubuntu@[2001:db8::1]:/tmp/profile.json",
        try scp_target(&buffer, "2001:db8::1", "/tmp/profile.json"),
    );
    // Rust brackets the parsed address's display form; IPv4 and names pass through.
    try testing.expectEqualStrings(
        "ubuntu@[2001:db8::1]:/x",
        try scp_target(&buffer, "2001:0db8:0:0::1", "/x"),
    );
    try testing.expectEqualStrings("ubuntu@1.2.3.4:/x", try scp_target(&buffer, "1.2.3.4", "/x"));
    try testing.expectEqualStrings("ubuntu@host:/x", try scp_target(&buffer, "host", "/x"));
    var small: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, scp_target(&small, "2001:db8::1", "/x"));
}

test "ssh attach code ok" {
    try testing.expect(ssh_attach_code_ok(0));
    try testing.expect(ssh_attach_code_ok(130));
    try testing.expect(!ssh_attach_code_ok(1));
    try testing.expect(!ssh_attach_code_ok(255));
    try testing.expect(!ssh_attach_code_ok(null));
}

test "ssh and scp argument vectors" {
    var out: [argv_max][]const u8 = undefined;
    const ssh = ssh_argv(&out, "ssh", "/k", &.{ "ubuntu@1.2.3.4", "uptime" });
    const expected = [_][]const u8{
        "ssh",
        "-i",
        "/k",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ServerAliveInterval=600",
        "-o",
        "StrictHostKeyChecking=no",
        "ubuntu@1.2.3.4",
        "uptime",
    };
    try testing.expectEqual(expected.len, ssh.len);
    for (expected, ssh) |want, got| try testing.expectEqualStrings(want, got);
    const scp = ssh_argv(&out, "scp", "/k", &.{"ubuntu@[::1]:/a"});
    try testing.expectEqualStrings("scp", scp[0]);
    try testing.expectEqualStrings("ubuntu@[::1]:/a", scp[scp.len - 1]);
}

test "service status polling rules" {
    try testing.expect(service_reached("active\n", "loki", .active));
    try testing.expect(!service_reached("activating\n", "loki", .active));
    try testing.expect(!service_reached("failed\n", "loki", .active));
    try testing.expect(service_reached("failed\n", "binary", .active));
    try testing.expect(service_reached("failed", "binary", .inactive));
    try testing.expect(service_reached(" inactive \n", "promtail", .inactive));
    try testing.expect(!service_reached("active", "promtail", .inactive));
}

test "exact cidr" {
    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("1.2.3.4/32", try exact_cidr(&buffer, "1.2.3.4"));
}
