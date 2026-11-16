//! The production resolver (commonware `tokio::Context`'s `Resolver`): the system's name
//! lookup through `std.Io` (hosts file, then the configured name servers), as tokio's
//! `lookup_host` delegates to the system resolver.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = Io.net;
const codec = @import("codec");
const resolver_mod = @import("../resolver.zig");

const IpAddr = resolver_mod.IpAddr;
const Error = resolver_mod.Error;

/// Lookup results kept per query: `HostName.lookup` never blocks with at least 16.
const results_max = 32;

pub const Resolver = struct {
    io: Io,

    pub fn resolver(self: *Resolver) resolver_mod.Resolver {
        return .{ .ptr = self, .vtable = &.{ .resolve = resolve } };
    }

    fn resolve(ptr: *anyopaque, gpa: Allocator, host: []const u8) Error![]IpAddr {
        const self: *Resolver = @ptrCast(@alignCast(ptr));
        const name = net.HostName.init(host) catch return error.ResolveFailed;
        var buffer: [results_max]net.HostName.LookupResult = undefined;
        var queue: Io.Queue(net.HostName.LookupResult) = .init(&buffer);
        name.lookup(self.io, &queue, .{ .port = 0 }) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => error.ResolveFailed,
        };
        var addresses: [results_max]IpAddr = undefined;
        var count: usize = 0;
        while (queue.getOne(self.io)) |result| switch (result) {
            .address => |address| {
                assert(count < results_max);
                addresses[count] = ip_addr(address);
                count += 1;
            },
            .canonical_name => {},
        } else |err| switch (err) {
            error.Closed => {},
            error.Canceled => return error.Canceled,
        }
        if (count == 0) return error.ResolveFailed;
        return gpa.dupe(IpAddr, addresses[0..count]);
    }
};

fn ip_addr(address: net.IpAddress) IpAddr {
    return switch (address) {
        .ip4 => |ip4| .{ .v4 = .{ .octets = ip4.bytes } },
        .ip6 => |ip6| .{ .v6 = .{ .octets = ip6.bytes } },
    };
}

const testing = std.testing;

test "the production resolver resolves localhost and IP literals" {
    var system: Resolver = .{ .io = testing.io };
    const resolver = system.resolver();
    const local = try resolver.resolve(testing.allocator, "localhost");
    defer testing.allocator.free(local);
    for (local) |address| {
        const loopback = switch (address) {
            .v4 => |v4| v4.octets[0] == 127,
            .v6 => |v6| std.mem.eql(u8, &v6.octets, &codec.net.Ipv6.localhost.octets),
        };
        try testing.expect(loopback);
    }
    const literal = try resolver.resolve(testing.allocator, "10.1.2.3");
    defer testing.allocator.free(literal);
    try testing.expectEqualSlices(IpAddr, &.{.{ .v4 = .init(10, 1, 2, 3) }}, literal);
    const bad = resolver.resolve(testing.allocator, "not a host name");
    try testing.expectError(error.ResolveFailed, bad);
}
