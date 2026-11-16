//! DNS resolution (commonware `runtime::Resolver`): a host name to its IP addresses.
//!
//! `Context.resolve(host)` asks the runner's resolver. The deterministic runner answers from
//! a `Dns` table that tests fill with `Context.resolver_register` (commonware
//! `deterministic::Context::resolver_register`); it lives as long as the runner, so it
//! survives a restart (another `start` on the same runner). The production runner asks the
//! system (`production/resolver.zig`). Addresses are `codec.IpAddr`, Rust's `IpAddr`: no port.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const Auditor = @import("deterministic.zig").Auditor;

pub const IpAddr = codec.IpAddr;

/// commonware `Error::ResolveFailed`, plus what resolving can run into.
pub const Error = error{ ResolveFailed, Canceled } || Allocator.Error;

/// Most addresses one host maps to in a `Dns` table.
pub const addresses_max = 64;
/// Most hosts a `Dns` table holds.
pub const hosts_max = 4096;
/// Longest host name (RFC 1035).
pub const host_size_max = 253;

/// Resolves host names (commonware `Resolver`).
pub const Resolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        resolve: *const fn (ptr: *anyopaque, gpa: Allocator, host: []const u8) Error![]IpAddr,
    };

    /// The addresses `host` resolves to, in order; the caller frees them with `gpa`.
    /// `error.ResolveFailed` if it resolves to none.
    pub fn resolve(resolver: Resolver, gpa: Allocator, host: []const u8) Error![]IpAddr {
        const addresses = try resolver.vtable.resolve(resolver.ptr, gpa, host);
        assert(addresses.len > 0);
        return addresses;
    }
};

/// The deterministic runtime's DNS records. One task touches it at a time (the deterministic
/// runner runs one fiber at once).
pub const Dns = struct {
    gpa: Allocator,
    /// Hashes registrations and lookups as commonware's executor does; set by the runner.
    auditor: ?*Auditor = null,
    /// Host (owned) to addresses (owned).
    hosts: std.StringArrayHashMapUnmanaged([]IpAddr) = .empty,

    pub fn init(gpa: Allocator) Dns {
        return .{ .gpa = gpa };
    }

    pub fn deinit(dns: *Dns) void {
        for (dns.hosts.keys(), dns.hosts.values()) |host, addresses| {
            dns.gpa.free(host);
            dns.gpa.free(addresses);
        }
        dns.hosts.deinit(dns.gpa);
        dns.* = undefined;
    }

    /// Maps `host` to `addresses`, replacing an earlier mapping, or removes it when null.
    pub fn register(dns: *Dns, host: []const u8, addresses: ?[]const IpAddr) Allocator.Error!void {
        assert(host.len > 0 and host.len <= host_size_max);
        if (addresses) |list| assert(list.len <= addresses_max);
        dns.audit("resolver_register", host, addresses);
        if (dns.hosts.fetchSwapRemove(host)) |old| {
            dns.gpa.free(old.key);
            dns.gpa.free(old.value);
        }
        const list = addresses orelse return;
        assert(dns.hosts.count() < hosts_max);
        const owned_host = try dns.gpa.dupe(u8, host);
        errdefer dns.gpa.free(owned_host);
        const owned = try dns.gpa.dupe(IpAddr, list);
        errdefer dns.gpa.free(owned);
        try dns.hosts.put(dns.gpa, owned_host, owned);
        assert(dns.hosts.contains(host));
    }

    pub fn resolver(dns: *Dns) Resolver {
        return .{ .ptr = dns, .vtable = &.{ .resolve = resolve } };
    }

    fn resolve(ptr: *anyopaque, gpa: Allocator, host: []const u8) Error![]IpAddr {
        const dns: *Dns = @ptrCast(@alignCast(ptr));
        const found = dns.hosts.get(host);
        dns.audit("resolve", host, found);
        const addresses = found orelse return error.ResolveFailed;
        // commonware maps a host to `Some(vec![])` too; that resolves to nothing.
        if (addresses.len == 0) return error.ResolveFailed;
        return gpa.dupe(IpAddr, addresses);
    }

    /// Hashes `host` and the encoding of `Option<Vec<IpAddr>>`, as commonware does.
    fn audit(dns: *Dns, label: []const u8, host: []const u8, addresses: ?[]const IpAddr) void {
        const auditor = dns.auditor orelse return;
        var buffer: [3 + addresses_max * IpAddr.max_encode_size]u8 = undefined;
        var writer: codec.Writer = .init(&buffer);
        codec.write(?[]const IpAddr, addresses, &writer);
        assert(writer.end <= buffer.len);
        auditor.event(label, &.{ host, buffer[0..writer.end] });
    }
};

const testing = std.testing;

test "a dns table resolves, replaces, and removes mappings" {
    var dns: Dns = .init(testing.allocator);
    defer dns.deinit();
    const resolver = dns.resolver();
    const ip1: IpAddr = .{ .v4 = .init(192, 168, 1, 1) };
    const ip2: IpAddr = .{ .v6 = .localhost };
    try dns.register("example.com", &.{ ip1, ip2 });
    const addresses = try resolver.resolve(testing.allocator, "example.com");
    defer testing.allocator.free(addresses);
    try testing.expectEqualSlices(IpAddr, &.{ ip1, ip2 }, addresses);
    try dns.register("example.com", &.{ip2});
    const replaced = try resolver.resolve(testing.allocator, "example.com");
    defer testing.allocator.free(replaced);
    try testing.expectEqualSlices(IpAddr, &.{ip2}, replaced);
    try testing.expectError(error.ResolveFailed, resolver.resolve(testing.allocator, "other"));
    try dns.register("empty.com", &.{});
    try testing.expectError(error.ResolveFailed, resolver.resolve(testing.allocator, "empty.com"));
    try dns.register("example.com", null);
    const removed = resolver.resolve(testing.allocator, "example.com");
    try testing.expectError(error.ResolveFailed, removed);
}
