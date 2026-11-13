//! Network address codecs (codec/src/types/net.rs).
//!
//! | zigware | commonware | wire |
//! | --- | --- | --- |
//! | `Ipv4` | `Ipv4Addr` | 4 octets |
//! | `Ipv6` | `Ipv6Addr` | 16 octets |
//! | `SocketAddrV4` | `SocketAddrV4` | ip, port (u16 big-endian) |
//! | `SocketAddrV6` | `SocketAddrV6` | ip, port; flowinfo and scope id are not encoded |
//! | `IpAddr` | `IpAddr` | version byte 4 or 6, then the address |
//! | `SocketAddr` | `SocketAddr` | `IpAddr`, then port |

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("../buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("../error.zig").Error;

pub const Ipv4 = struct {
    octets: [4]u8,

    pub const fixed_size = 4;
    pub const unspecified = Ipv4{ .octets = .{ 0, 0, 0, 0 } };
    pub const localhost = Ipv4{ .octets = .{ 127, 0, 0, 1 } };

    pub fn init(a: u8, b: u8, c: u8, d: u8) Ipv4 {
        return .{ .octets = .{ a, b, c, d } };
    }

    pub fn write(self: Ipv4, writer: *Writer) void {
        writer.write_bytes(&self.octets);
    }

    pub fn read(_: Allocator, reader: *Reader, _: void) Error!Ipv4 {
        return .{ .octets = (try reader.take_array(4)).* };
    }

    pub fn order(a: Ipv4, b: Ipv4) std.math.Order {
        return std.mem.order(u8, &a.octets, &b.octets);
    }
};

pub const Ipv6 = struct {
    octets: [16]u8,

    pub const fixed_size = 16;
    pub const unspecified = Ipv6{ .octets = @splat(0) };
    pub const localhost = Ipv6.init(.{ 0, 0, 0, 0, 0, 0, 0, 1 });

    /// Builds an address from eight 16-bit segments, like Rust's `Ipv6Addr::new`.
    pub fn init(segments: [8]u16) Ipv6 {
        var octets: [16]u8 = undefined;
        for (segments, 0..) |segment, index| {
            std.mem.writeInt(u16, octets[index * 2 ..][0..2], segment, .big);
        }
        return .{ .octets = octets };
    }

    pub fn write(self: Ipv6, writer: *Writer) void {
        writer.write_bytes(&self.octets);
    }

    pub fn read(_: Allocator, reader: *Reader, _: void) Error!Ipv6 {
        return .{ .octets = (try reader.take_array(16)).* };
    }

    pub fn order(a: Ipv6, b: Ipv6) std.math.Order {
        return std.mem.order(u8, &a.octets, &b.octets);
    }
};

pub const SocketAddrV4 = struct {
    ip: Ipv4,
    port: u16,

    pub const fixed_size = Ipv4.fixed_size + 2;

    pub fn write(self: SocketAddrV4, writer: *Writer) void {
        self.ip.write(writer);
        writer.write_int(u16, self.port);
    }

    pub fn read(gpa: Allocator, reader: *Reader, _: void) Error!SocketAddrV4 {
        const ip = try Ipv4.read(gpa, reader, {});
        return .{ .ip = ip, .port = try reader.read_int(u16) };
    }

    pub fn order(a: SocketAddrV4, b: SocketAddrV4) std.math.Order {
        const ip_order = Ipv4.order(a.ip, b.ip);
        return if (ip_order != .eq) ip_order else std.math.order(a.port, b.port);
    }
};

pub const SocketAddrV6 = struct {
    ip: Ipv6,
    port: u16,

    pub const fixed_size = Ipv6.fixed_size + 2;

    pub fn write(self: SocketAddrV6, writer: *Writer) void {
        self.ip.write(writer);
        writer.write_int(u16, self.port);
    }

    pub fn read(gpa: Allocator, reader: *Reader, _: void) Error!SocketAddrV6 {
        const ip = try Ipv6.read(gpa, reader, {});
        return .{ .ip = ip, .port = try reader.read_int(u16) };
    }

    pub fn order(a: SocketAddrV6, b: SocketAddrV6) std.math.Order {
        const ip_order = Ipv6.order(a.ip, b.ip);
        return if (ip_order != .eq) ip_order else std.math.order(a.port, b.port);
    }
};

pub const IpAddr = union(enum) {
    v4: Ipv4,
    v6: Ipv6,

    pub const max_encode_size = 1 + Ipv6.fixed_size;

    pub fn write(self: IpAddr, writer: *Writer) void {
        switch (self) {
            .v4 => |ip| {
                writer.write_byte(4);
                ip.write(writer);
            },
            .v6 => |ip| {
                writer.write_byte(6);
                ip.write(writer);
            },
        }
    }

    pub fn encode_size(self: IpAddr) usize {
        const size: usize = switch (self) {
            .v4 => 1 + Ipv4.fixed_size,
            .v6 => 1 + Ipv6.fixed_size,
        };
        assert(size <= max_encode_size);
        return size;
    }

    pub fn read(gpa: Allocator, reader: *Reader, _: void) Error!IpAddr {
        return switch (try reader.read_byte()) {
            4 => .{ .v4 = try Ipv4.read(gpa, reader, {}) },
            6 => .{ .v6 = try Ipv6.read(gpa, reader, {}) },
            else => reader.invalid("IpAddr", "Invalid version"),
        };
    }

    /// Rust's derived order: every IPv4 address sorts before every IPv6 address.
    pub fn order(a: IpAddr, b: IpAddr) std.math.Order {
        return switch (a) {
            .v4 => |left| switch (b) {
                .v4 => |right| Ipv4.order(left, right),
                .v6 => .lt,
            },
            .v6 => |left| switch (b) {
                .v4 => .gt,
                .v6 => |right| Ipv6.order(left, right),
            },
        };
    }
};

pub const SocketAddr = struct {
    ip: IpAddr,
    port: u16,

    pub const max_encode_size = IpAddr.max_encode_size + 2;

    pub fn write(self: SocketAddr, writer: *Writer) void {
        self.ip.write(writer);
        writer.write_int(u16, self.port);
    }

    pub fn encode_size(self: SocketAddr) usize {
        return self.ip.encode_size() + 2;
    }

    pub fn read(gpa: Allocator, reader: *Reader, _: void) Error!SocketAddr {
        const ip = try IpAddr.read(gpa, reader, {});
        return .{ .ip = ip, .port = try reader.read_int(u16) };
    }

    pub fn order(a: SocketAddr, b: SocketAddr) std.math.Order {
        const ip_order = IpAddr.order(a.ip, b.ip);
        return if (ip_order != .eq) ip_order else std.math.order(a.port, b.port);
    }
};

const testing = std.testing;
const codec = @import("../codec.zig");
const test_gpa = testing.allocator;

fn expect_roundtrip(comptime T: type, value: T, expected_len: usize) !void {
    const encoded = try codec.encode(T, test_gpa, value);
    defer test_gpa.free(encoded);
    try testing.expectEqual(expected_len, encoded.len);
    try testing.expectEqual(expected_len, codec.encode_size(T, value));
    try testing.expectEqual(value, try codec.decode(T, test_gpa, encoded));
    const truncated = encoded[0 .. encoded.len - 1];
    try testing.expectError(error.EndOfBuffer, codec.decode(T, test_gpa, truncated));
}

fn expect_encoding(comptime T: type, value: T, expected: []const u8) !void {
    const encoded = try codec.encode(T, test_gpa, value);
    defer test_gpa.free(encoded);
    try testing.expectEqualSlices(u8, expected, encoded);
}

const documentation = Ipv6.init(.{ 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1 });

test "ipv4 and ipv6" {
    const v4 = [_]Ipv4{
        .unspecified, .localhost, .init(192, 168, 1, 1), .init(255, 255, 255, 255),
    };
    for (v4) |ip| try expect_roundtrip(Ipv4, ip, 4);
    const all: [8]u16 = @splat(0xffff);
    const v6 = [_]Ipv6{ .unspecified, .localhost, documentation, .init(all) };
    for (v6) |ip| try expect_roundtrip(Ipv6, ip, 16);
}

test "socket addresses" {
    try expect_roundtrip(SocketAddrV4, .{ .ip = .unspecified, .port = 0 }, 6);
    try expect_roundtrip(SocketAddrV4, .{ .ip = .localhost, .port = 8080 }, 6);
    try expect_roundtrip(SocketAddrV4, .{ .ip = .init(192, 168, 1, 1), .port = 65535 }, 6);
    try expect_roundtrip(SocketAddrV6, .{ .ip = .unspecified, .port = 0 }, 18);
    try expect_roundtrip(SocketAddrV6, .{ .ip = .localhost, .port = 8080 }, 18);
    try expect_roundtrip(SocketAddrV6, .{ .ip = documentation, .port = 65535 }, 18);
}

test "ip addr" {
    try expect_roundtrip(IpAddr, .{ .v4 = .init(192, 168, 1, 1) }, 5);
    try expect_roundtrip(IpAddr, .{ .v6 = documentation }, 17);
    var reader = Reader.init(&.{5});
    try testing.expectError(error.Invalid, codec.decode_reader(IpAddr, test_gpa, &reader, {}));
    try testing.expectEqualStrings("IpAddr", reader.diagnostic.context);
    try testing.expectError(error.EndOfBuffer, codec.decode(IpAddr, test_gpa, &.{ 4, 127, 0, 0 }));
    const short_v6 = [_]u8{6} ++ @as([15]u8, @splat(0));
    try testing.expectError(error.EndOfBuffer, codec.decode(IpAddr, test_gpa, &short_v6));
}

test "socket addr" {
    try expect_roundtrip(SocketAddr, .{ .ip = .{ .v4 = .init(196, 168, 0, 1) }, .port = 8080 }, 7);
    const segments = [8]u16{ 0x2001, 0x0db8, 0xffff, 0x1234, 0x5678, 0x9abc, 0xdeff, 1 };
    try expect_roundtrip(SocketAddr, .{ .ip = .{ .v6 = .init(segments) }, .port = 8080 }, 19);
    try testing.expectError(error.Invalid, codec.decode(SocketAddr, test_gpa, &.{5}));
    const short_v4 = [_]u8{ 4, 127, 0, 0, 1, 0x1f };
    try testing.expectError(error.EndOfBuffer, codec.decode(SocketAddr, test_gpa, &short_v4));
    const short_v6 = [_]u8{6} ++ @as([17]u8, @splat(0));
    try testing.expectError(error.EndOfBuffer, codec.decode(SocketAddr, test_gpa, &short_v6));
}

test "net conformity" {
    try expect_encoding(Ipv4, .init(0, 0, 0, 0), &.{ 0, 0, 0, 0 });
    try expect_encoding(Ipv4, .init(127, 0, 0, 1), &.{ 127, 0, 0, 1 });
    try expect_encoding(Ipv4, .init(192, 168, 1, 100), &.{ 192, 168, 1, 100 });
    try expect_encoding(Ipv4, .init(255, 255, 255, 255), &.{ 255, 255, 255, 255 });

    try expect_encoding(Ipv6, .unspecified, &@as([16]u8, @splat(0)));
    try expect_encoding(Ipv6, .localhost, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    // 2001:db8::ff00:42:8329
    const parsed = Ipv6.init(.{ 0x2001, 0x0db8, 0, 0, 0, 0xff00, 0x0042, 0x8329 });
    const parsed_bytes = [_]u8{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0x00, 0, 0x42, 0x83, 0x29,
    };
    try expect_encoding(Ipv6, parsed, &parsed_bytes);
    try expect_encoding(Ipv6, .init(@splat(0xffff)), &@as([16]u8, @splat(0xff)));

    try expect_encoding(SocketAddrV4, .{ .ip = .init(10, 0, 0, 1), .port = 80 }, &.{
        10, 0, 0, 1, 0x00, 0x50,
    });
    try expect_encoding(SocketAddrV4, .{ .ip = .init(192, 168, 20, 30), .port = 65535 }, &.{
        192, 168, 20, 30, 0xff, 0xff,
    });
    try expect_encoding(SocketAddrV6, .{ .ip = documentation, .port = 8080 }, &.{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90,
    });
    try expect_encoding(SocketAddr, .{ .ip = .{ .v4 = .localhost }, .port = 8080 }, &.{
        0x04, 127, 0, 0, 1, 0x1f, 0x90,
    });
    try expect_encoding(SocketAddr, .{ .ip = .{ .v6 = .localhost }, .port = 443 }, &.{
        0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
    });
}

test "net max encode size" {
    const v6 = SocketAddr{ .ip = .{ .v6 = .localhost }, .port = 65535 };
    try testing.expectEqual(codec.max_encode_size(IpAddr).?, v6.ip.encode_size());
    try testing.expectEqual(codec.max_encode_size(SocketAddr).?, v6.encode_size());
    const v4 = SocketAddr{ .ip = .{ .v4 = .localhost }, .port = 65535 };
    try testing.expect(v4.ip.encode_size() < codec.max_encode_size(IpAddr).?);
    try testing.expect(v4.encode_size() < codec.max_encode_size(SocketAddr).?);
}

test "net order" {
    const a = IpAddr{ .v4 = .init(255, 255, 255, 255) };
    const b = IpAddr{ .v6 = .unspecified };
    try testing.expectEqual(std.math.Order.lt, codec.order(IpAddr, a, b));
    const low = SocketAddr{ .ip = a, .port = 2 };
    const high = SocketAddr{ .ip = a, .port = 3 };
    try testing.expectEqual(std.math.Order.lt, codec.order(SocketAddr, low, high));
}
