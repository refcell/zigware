//! IP address helpers (commonware `utils/src/net.rs`): subnet grouping and `is_global`.
//!
//! Addresses are codec's `IpAddr`/`Ipv4`/`Ipv6` (big-endian octets). `is_global` follows the
//! IANA IPv4 and IPv6 Special-Purpose Address Registries, mirroring Rust's unstable
//! `IpAddr::is_global` exactly as commonware does.

const std = @import("std");
const codec = @import("codec");
const assert = std.debug.assert;

const IpAddr = codec.IpAddr;
const Ipv4 = codec.Ipv4;
const Ipv6 = codec.Ipv6;

/// The network part of an address under a `SubnetMask`; IPv4-mapped IPv6 addresses are
/// grouped with their IPv4 address.
pub const Subnet = struct {
    addr: IpAddr,

    pub fn eql(a: Subnet, b: Subnet) bool {
        return std.meta.eql(a.addr, b.addr);
    }
};

/// Prefix masks for IPv4 and IPv6; prefix lengths beyond the address width are clamped.
pub const SubnetMask = struct {
    ipv4: u32,
    ipv6: u128,

    pub fn init(ipv4_bits: u8, ipv6_bits: u8) SubnetMask {
        const v4_bits: u8 = @min(ipv4_bits, 32);
        const v6_bits: u8 = @min(ipv6_bits, 128);
        const mask: SubnetMask = .{
            .ipv4 = if (v4_bits == 0) 0 else ~@as(u32, 0) << @intCast(32 - @as(u32, v4_bits)),
            .ipv6 = if (v6_bits == 0) 0 else ~@as(u128, 0) << @intCast(128 - @as(u32, v6_bits)),
        };
        assert(@popCount(mask.ipv4) == v4_bits and @popCount(mask.ipv6) == v6_bits);
        return mask;
    }
};

fn v4_subnet(ip: Ipv4, mask: SubnetMask) IpAddr {
    var octets: [4]u8 = undefined;
    std.mem.writeInt(u32, &octets, std.mem.readInt(u32, &ip.octets, .big) & mask.ipv4, .big);
    return .{ .v4 = .{ .octets = octets } };
}

/// The IPv4 address embedded in an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
pub fn to_ipv4_mapped(ip: Ipv6) ?Ipv4 {
    const prefix: [12]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (!std.mem.eql(u8, ip.octets[0..12], &prefix)) return null;
    return .{ .octets = ip.octets[12..16].* };
}

/// Groups `ip` by `mask` (commonware `IpAddrExt::subnet`).
pub fn subnet(ip: IpAddr, mask: SubnetMask) Subnet {
    switch (ip) {
        .v4 => |v4| return .{ .addr = v4_subnet(v4, mask) },
        .v6 => |v6| {
            if (to_ipv4_mapped(v6)) |v4| return .{ .addr = v4_subnet(v4, mask) };
            var octets: [16]u8 = undefined;
            const value = std.mem.readInt(u128, &v6.octets, .big) & mask.ipv6;
            std.mem.writeInt(u128, &octets, value, .big);
            return .{ .addr = .{ .v6 = .{ .octets = octets } } };
        },
    }
}

/// Whether `ip` is globally reachable (commonware `IpAddrExt::is_global`).
pub fn is_global(ip: IpAddr) bool {
    return switch (ip) {
        .v4 => |v4| is_global_v4(v4),
        .v6 => |v6| is_global_v6(v6),
    };
}

pub fn is_global_v4(ip: Ipv4) bool {
    const o = ip.octets;
    const broadcast = std.mem.eql(u8, &o, &.{ 255, 255, 255, 255 });
    const private = o[0] == 10 or (o[0] == 172 and o[1] & 0xf0 == 16) or
        (o[0] == 192 and o[1] == 168);
    const shared = o[0] == 100 and o[1] & 0b1100_0000 == 0b0100_0000;
    const loopback = o[0] == 127;
    const link_local = o[0] == 169 and o[1] == 254;
    const future_protocol = o[0] == 192 and o[1] == 0 and o[2] == 0 and o[3] != 9 and o[3] != 10;
    const relay_anycast = std.mem.eql(u8, &o, &.{ 192, 88, 99, 2 });
    const documentation = (o[0] == 192 and o[1] == 0 and o[2] == 2) or
        (o[0] == 198 and o[1] == 51 and o[2] == 100) or
        (o[0] == 203 and o[1] == 0 and o[2] == 113);
    const benchmarking = o[0] == 198 and o[1] & 0xfe == 18;
    const reserved = o[0] & 240 == 240 and !broadcast;
    return !(o[0] == 0 or private or shared or loopback or link_local or future_protocol or
        relay_anycast or documentation or benchmarking or reserved or broadcast);
}

/// IETF Protocol Assignments (`2001::/23`) that are nonetheless globally reachable.
fn is_global_ietf_exception(value: u128, s: [8]u16) bool {
    const anycast_base: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0000;
    return (value >= anycast_base + 1 and value <= anycast_base + 3) or // PCP, TURN, DNS-SD
        (s[0] == 0x2001 and s[1] == 3) or // AMT
        (s[0] == 0x2001 and s[1] == 4 and s[2] == 0x112) or // AS112-v6
        (s[0] == 0x2001 and s[1] >= 0x20 and s[1] <= 0x3f); // ORCHIDv2, drone DETs
}

pub fn is_global_v6(ip: Ipv6) bool {
    var s: [8]u16 = undefined;
    for (&s, 0..) |*segment, index| {
        segment.* = std.mem.readInt(u16, ip.octets[index * 2 ..][0..2], .big);
    }
    const value = std.mem.readInt(u128, &ip.octets, .big);
    const ietf = s[0] == 0x2001 and s[1] < 0x200 and !is_global_ietf_exception(value, s);
    const not_global = value == 0 or // unspecified
        value == 1 or // loopback
        to_ipv4_mapped(ip) != null or
        (s[0] == 0x64 and s[1] == 0xff9b and s[2] == 1) or // IPv4-IPv6 translation
        (s[0] == 0x100 and s[1] == 0 and s[2] == 0 and s[3] <= 1) or // discard-only, dummy
        ietf or
        s[0] == 0x2002 or // 6to4
        (s[0] == 0x2001 and s[1] == 0xdb8) or (s[0] == 0x3fff and s[1] <= 0x0fff) or // docs
        s[0] == 0x5f00 or // SRv6 SIDs
        s[0] & 0xfe00 == 0xfc00 or // unique local
        s[0] & 0xffc0 == 0xfe80; // unicast link local
    return !not_global;
}

const testing = std.testing;

fn ip4(a: u8, b: u8, c: u8, d: u8) IpAddr {
    return .{ .v4 = Ipv4.init(a, b, c, d) };
}

fn ip6(segments: [8]u16) IpAddr {
    return .{ .v6 = Ipv6.init(segments) };
}

test "net: subnets" {
    const mask = SubnetMask.init(24, 48);
    try testing.expect(subnet(ip4(192, 168, 1, 123), mask).eql(.{ .addr = ip4(192, 168, 1, 0) }));
    const v6 = ip6(.{ 0x2001, 0xdb8, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x1357, 0x2468 });
    const expected = ip6(.{ 0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0 });
    try testing.expect(subnet(v6, mask).eql(.{ .addr = expected }));
    const mapped = ip6(.{ 0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x017b }); // ::ffff:192.168.1.123
    try testing.expect(subnet(mapped, mask).eql(.{ .addr = ip4(192, 168, 1, 0) }));

    const max = SubnetMask.init(40, 200);
    try testing.expectEqual(std.math.maxInt(u32), max.ipv4);
    try testing.expectEqual(std.math.maxInt(u128), max.ipv6);
    const min = SubnetMask.init(0, 0);
    try testing.expectEqual(@as(u32, 0), min.ipv4);
    try testing.expectEqual(@as(u128, 0), min.ipv6);
}

test "net: is_global v4" {
    const global = [_]IpAddr{
        ip4(8, 8, 8, 8),    ip4(1, 1, 1, 1),     ip4(123, 45, 67, 89), ip4(192, 0, 0, 9),
        ip4(192, 0, 0, 10), ip4(192, 88, 99, 1), ip4(192, 88, 99, 3),  ip4(1, 2, 3, 4),
    };
    for (global) |ip| try testing.expect(is_global(ip));
    const local = [_]IpAddr{
        ip4(10, 0, 0, 1),        ip4(192, 168, 1, 1),     ip4(172, 16, 0, 1),
        ip4(172, 31, 255, 254),  ip4(100, 64, 0, 1),      ip4(100, 127, 255, 254),
        ip4(127, 0, 0, 1),       ip4(127, 255, 255, 254), ip4(169, 254, 0, 1),
        ip4(169, 254, 255, 254), ip4(192, 0, 0, 1),       ip4(192, 0, 0, 254),
        ip4(192, 0, 2, 1),       ip4(198, 51, 100, 1),    ip4(203, 0, 113, 1),
        ip4(192, 88, 99, 2),     ip4(198, 18, 0, 1),      ip4(198, 19, 255, 254),
        ip4(240, 0, 0, 1),       ip4(254, 255, 255, 254), ip4(255, 255, 255, 255),
        ip4(0, 1, 2, 3),
    };
    for (local) |ip| try testing.expect(!is_global(ip));
}

test "net: is_global v6" {
    const f = 0xffff;
    const global = [_][8]u16{
        .{ 0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888 },
        .{ 0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 },
        .{ 0x2005, 0x1db8, 0x85a3, 0, 0, 0x8a2e, 0x0370, 0x7334 },
        .{ 0x100, 0, 0, 2, 0, 0, 0, 1 },
        .{ 0x2001, 0x200, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 1, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 1, 0, 0, 0, 0, 0, 2 },
        .{ 0x2001, 1, 0, 0, 0, 0, 0, 3 },
        .{ 0x2001, 3, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 4, 0x112, 0, 0, 0, 0, 1 },
        .{ 0x2001, 0x20, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 0x30, 0, 0, 0, 0, 0, 1 },
        .{ 0x3fff, 0x1000, 0, 0, 0, 0, 0, 1 },
        .{ 0x5eff, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x5f01, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xff00, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x2003, 0, 0, 0, 0, 0, 0, 1 },
    };
    for (global) |segments| try testing.expect(is_global(ip6(segments)));
    const local = [_][8]u16{
        .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        .{ 0, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0, 0, 0, 0, 0, f, 0xc000, 0x0280 },
        .{ 0x64, 0xff9b, 1, 0, 0, 0, 0, 1 },
        .{ 0x100, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x100, 0, 0, 1, 0, 0, 0, 1 },
        .{ 0x100, 0, 0, 1, f, f, f, f },
        .{ 0x2001, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 0x1ff, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 1, 0, 0, 0, 0, 0, 4 },
        .{ 0x2002, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 },
        .{ 0x3fff, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x3fff, 0xfff, f, f, f, f, f, f },
        .{ 0x5f00, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0x5f00, f, f, f, f, f, f, f },
        .{ 0xfc00, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xfdff, f, f, f, f, f, f, f },
        .{ 0xfe80, 0, 0, 0, 0, 0, 0, 1 },
    };
    for (local) |segments| try testing.expect(!is_global(ip6(segments)));
}
