//! Shared address types for p2p networking (commonware `p2p/src/types.rs`).
//!
//! `Ingress` is what a peer dials (a socket address or a DNS name and port) and `Address`
//! pairs it with the egress socket a peer connects from. Both encode byte-identically to
//! commonware.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");

const Hostname = utils.Hostname;
const is_global = utils.net.is_global;

const SocketAddr = codec.SocketAddr;
const IpAddr = codec.IpAddr;
const Ipv4 = codec.Ipv4;
const Ipv6 = codec.Ipv6;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;

const ingress_socket_prefix: u8 = 0;
const ingress_dns_prefix: u8 = 1;
const address_symmetric_prefix: u8 = 0;
const address_asymmetric_prefix: u8 = 1;

/// What we dial to connect to a peer.
pub const Ingress = union(enum) {
    /// IP-based ingress address.
    socket: SocketAddr,
    /// DNS-based ingress address.
    dns: Dns,

    pub const Dns = struct {
        /// Hostname to resolve.
        host: Hostname,
        /// Port to connect to.
        port: u16,
    };

    /// A DNS ingress with a maximum-length hostname is wider than any socket address.
    pub const max_encode_size: usize =
        1 + @max(SocketAddr.max_encode_size, Hostname.max_encode_size + 2);

    pub fn port(ingress: Ingress) u16 {
        return switch (ingress) {
            .socket => |addr| addr.port,
            .dns => |dns| dns.port,
        };
    }

    /// The IP address of a socket ingress, or null for DNS.
    pub fn ip(ingress: Ingress) ?IpAddr {
        return switch (ingress) {
            .socket => |addr| addr.ip,
            .dns => null,
        };
    }

    /// Socket addresses must be global unless `allow_private_ips`; DNS needs `allow_dns`.
    /// Private-IP checks for DNS happen after resolution.
    pub fn is_valid(ingress: Ingress, allow_private_ips: bool, allow_dns: bool) bool {
        return switch (ingress) {
            .socket => |addr| allow_private_ips or is_global(addr.ip),
            .dns => allow_dns,
        };
    }

    pub fn eql(a: Ingress, b: Ingress) bool {
        return a.order(b) == .eq;
    }

    /// Rust's derived `Debug` (what commonware's `?ingress` trace fields print):
    /// `Socket(127.0.0.1:3000)` or `Dns { host: Hostname("example.com"), port: 80 }`.
    pub fn format(ingress: Ingress, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (ingress) {
            .socket => |addr| {
                const address: std.Io.net.IpAddress = switch (addr.ip) {
                    .v4 => |ip4| .{ .ip4 = .{ .bytes = ip4.octets, .port = addr.port } },
                    .v6 => |ip6| .{ .ip6 = .{ .bytes = ip6.octets, .port = addr.port } },
                };
                try writer.print("Socket({f})", .{address});
            },
            .dns => |dns| try writer.print(
                "Dns {{ host: Hostname(\"{f}\"), port: {d} }}",
                .{ dns.host, dns.port },
            ),
        }
    }

    /// Rust's derived `Ord`: variant first, then fields in order.
    pub fn order(a: Ingress, b: Ingress) std.math.Order {
        const tags = std.math.order(@backingInt(a), @backingInt(b));
        if (tags != .eq) return tags;
        return switch (a) {
            .socket => |addr| addr.order(b.socket),
            .dns => |dns| switch (dns.host.order(b.dns.host)) {
                .eq => std.math.order(dns.port, b.dns.port),
                else => |host_order| host_order,
            },
        };
    }

    pub fn write(ingress: Ingress, writer: *codec.Writer) void {
        switch (ingress) {
            .socket => |addr| {
                writer.write_byte(ingress_socket_prefix);
                addr.write(writer);
            },
            .dns => |dns| {
                writer.write_byte(ingress_dns_prefix);
                dns.host.write(writer);
                codec.write(u16, dns.port, writer);
            },
        }
    }

    pub fn encode_size(ingress: Ingress) usize {
        return 1 + switch (ingress) {
            .socket => |addr| addr.encode_size(),
            .dns => |dns| dns.host.encode_size() + 2,
        };
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Ingress {
        const prefix = try reader.read_byte();
        switch (prefix) {
            ingress_socket_prefix => return .{ .socket = try SocketAddr.read(gpa, reader, {}) },
            ingress_dns_prefix => {
                const host = try Hostname.read(gpa, reader, {});
                const port_value = try codec.read(u16, gpa, reader);
                return .{ .dns = .{ .host = host, .port = port_value } };
            },
            else => return reader.fail(error.InvalidEnum, prefix),
        }
    }

    /// commonware's `Arbitrary for Ingress`.
    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Ingress {
        if (u.int_in_range(u32, 1, 2) <= 1) return .{ .socket = arbitrary_socket(u) };
        const host = try Hostname.arbitrary(gpa, u);
        return .{ .dns = .{ .host = host, .port = u.int(u16) } };
    }
};

/// Full address specification for peer-to-peer networking.
pub const Address = union(enum) {
    /// Same address for both ingress (dialing) and egress (IP filtering).
    symmetric: SocketAddr,
    /// Different addresses for ingress and egress.
    asymmetric: Asymmetric,

    pub const Asymmetric = struct {
        /// The address we dial to connect.
        ingress: Ingress,
        /// The IP we expect connections from (used for filtering).
        egress: SocketAddr,
    };

    /// An asymmetric address carries an ingress and an egress socket address.
    pub const max_encode_size: usize = 1 + Ingress.max_encode_size + SocketAddr.max_encode_size;

    /// The ingress address for dialing.
    pub fn ingress(address: Address) Ingress {
        return switch (address) {
            .symmetric => |addr| .{ .socket = addr },
            .asymmetric => |asymmetric| asymmetric.ingress,
        };
    }

    /// The egress IP address for filtering.
    pub fn egress_ip(address: Address) IpAddr {
        return address.egress().ip;
    }

    /// The egress socket address.
    pub fn egress(address: Address) SocketAddr {
        return switch (address) {
            .symmetric => |addr| addr,
            .asymmetric => |asymmetric| asymmetric.egress,
        };
    }

    pub fn eql(a: Address, b: Address) bool {
        return a.order(b) == .eq;
    }

    pub fn order(a: Address, b: Address) std.math.Order {
        const tags = std.math.order(@backingInt(a), @backingInt(b));
        if (tags != .eq) return tags;
        return switch (a) {
            .symmetric => |addr| addr.order(b.symmetric),
            .asymmetric => |asymmetric| switch (asymmetric.ingress.order(b.asymmetric.ingress)) {
                .eq => asymmetric.egress.order(b.asymmetric.egress),
                else => |ingress_order| ingress_order,
            },
        };
    }

    pub fn write(address: Address, writer: *codec.Writer) void {
        switch (address) {
            .symmetric => |addr| {
                writer.write_byte(address_symmetric_prefix);
                addr.write(writer);
            },
            .asymmetric => |asymmetric| {
                writer.write_byte(address_asymmetric_prefix);
                asymmetric.ingress.write(writer);
                asymmetric.egress.write(writer);
            },
        }
    }

    pub fn encode_size(address: Address) usize {
        return 1 + switch (address) {
            .symmetric => |addr| addr.encode_size(),
            .asymmetric => |a| a.ingress.encode_size() + a.egress.encode_size(),
        };
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Address {
        const prefix = try reader.read_byte();
        switch (prefix) {
            address_symmetric_prefix => {
                return .{ .symmetric = try SocketAddr.read(gpa, reader, {}) };
            },
            address_asymmetric_prefix => {
                const ingress_value = try Ingress.read(gpa, reader, {});
                const egress_value = try SocketAddr.read(gpa, reader, {});
                return .{ .asymmetric = .{ .ingress = ingress_value, .egress = egress_value } };
            },
            else => return reader.fail(error.InvalidEnum, prefix),
        }
    }

    /// commonware's `Arbitrary for Address`.
    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Address {
        if (u.int_in_range(u32, 1, 2) <= 1) return .{ .symmetric = arbitrary_socket(u) };
        const ingress_value = try Ingress.arbitrary(gpa, u);
        return .{ .asymmetric = .{ .ingress = ingress_value, .egress = arbitrary_socket(u) } };
    }
};

/// `SocketAddr::arbitrary`: a variant bit, the address, the port (and for V6 a flowinfo and a
/// scope id that the codec does not encode).
fn arbitrary_socket(u: *Unstructured) SocketAddr {
    if (u.boolean()) {
        var octets: [4]u8 = undefined;
        std.mem.writeInt(u32, &octets, u.int(u32), .big);
        return .{ .ip = .{ .v4 = .{ .octets = octets } }, .port = u.int(u16) };
    }
    var octets: [16]u8 = undefined;
    std.mem.writeInt(u128, &octets, u.int(u128), .big);
    const port_value = u.int(u16);
    _ = u.int(u32);
    _ = u.int(u32);
    return .{ .ip = .{ .v6 = .{ .octets = octets } }, .port = port_value };
}

const testing = std.testing;

fn v4(a: u8, b: u8, c: u8, d: u8, port_value: u16) SocketAddr {
    return .{ .ip = .{ .v4 = Ipv4.init(a, b, c, d) }, .port = port_value };
}

fn roundtrip(comptime T: type, value: T) !void {
    var buffer: [Address.max_encode_size]u8 = undefined;
    const encoded = codec.encode_to(T, value, &buffer);
    try testing.expectEqual(codec.encode_size(T, value), encoded.len);
    const decoded = try codec.decode(T, testing.allocator, encoded);
    try testing.expect(value.eql(decoded));
}

/// A hostname of the maximum length: three 63-character labels and one of 61, joined by dots.
fn widest_hostname() Hostname {
    var text: [Hostname.len_max]u8 = undefined;
    var index: usize = 0;
    for ([_]u8{ 'a', 'b', 'c', 'd' }, [_]usize{ 63, 63, 63, 61 }) |letter, len| {
        if (index > 0) {
            text[index] = '.';
            index += 1;
        }
        @memset(text[index..][0..len], letter);
        index += len;
    }
    assert(index == Hostname.len_max);
    return Hostname.literal(&text);
}

test "ingress socket roundtrip (test_ingress_socket_roundtrip)" {
    try roundtrip(Ingress, .{ .socket = v4(127, 0, 0, 1, 8080) });
    try roundtrip(Ingress, .{ .socket = .{ .ip = .{ .v6 = Ipv6.localhost }, .port = 443 } });
    try roundtrip(Ingress, .{ .socket = v4(192, 168, 1, 1, 65535) });
}

test "ingress dns roundtrip (test_ingress_dns_roundtrip)" {
    const cases = [_]struct { []const u8, u16 }{
        .{ "localhost", 8080 },
        .{ "example.com", 443 },
        .{ "a.b.c.d.e.f.g", 1234 },
    };
    for (cases) |case| {
        try roundtrip(Ingress, .{ .dns = .{ .host = Hostname.literal(case[0]), .port = case[1] } });
    }
}

test "ingress dns hostname too long (test_ingress_dns_max_len_exceeded)" {
    var buffer: [320]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    writer.write_byte(ingress_dns_prefix);
    codec.write(usize, 300, &writer);
    for (0..300) |_| writer.write_byte('a');
    codec.write(u16, 8080, &writer);
    const result = codec.decode(Ingress, testing.allocator, writer.written());
    try testing.expectError(error.InvalidLength, result);
}

test "ingress and address max encode size" {
    const host = widest_hostname();
    const slack = Hostname.max_encode_size - host.encode_size();
    const dns: Ingress = .{ .dns = .{ .host = host, .port = std.math.maxInt(u16) } };
    try testing.expectEqual(Ingress.max_encode_size, dns.encode_size() + slack);
    const egress: SocketAddr = .{ .ip = .{ .v6 = Ipv6.localhost }, .port = 65535 };
    const socket: Ingress = .{ .socket = egress };
    try testing.expect(socket.encode_size() < Ingress.max_encode_size);

    const asymmetric: Address = .{ .asymmetric = .{ .ingress = dns, .egress = egress } };
    try testing.expectEqual(Address.max_encode_size, asymmetric.encode_size() + slack);
    const symmetric: Address = .{ .symmetric = egress };
    try testing.expect(symmetric.encode_size() < Address.max_encode_size);
    try roundtrip(Address, asymmetric);
}

test "ingress port and ip" {
    const socket: Ingress = .{ .socket = v4(127, 0, 0, 1, 8080) };
    const dns: Ingress = .{ .dns = .{ .host = Hostname.literal("example.com"), .port = 443 } };
    try testing.expectEqual(@as(u16, 8080), socket.port());
    try testing.expectEqual(@as(u16, 443), dns.port());
    try testing.expect(socket.ip().?.order(.{ .v4 = Ipv4.localhost }) == .eq);
    try testing.expect(dns.ip() == null);
}

test "ingress formats like Rust's Debug" {
    var buffer: [128]u8 = undefined;
    const cases = [_]struct { Ingress, []const u8 }{
        .{ .{ .socket = v4(127, 0, 0, 1, 8080) }, "Socket(127.0.0.1:8080)" },
        .{ .{ .socket = .{ .ip = .{ .v6 = Ipv6.localhost }, .port = 443 } }, "Socket([::1]:443)" },
        .{
            .{ .dns = .{ .host = Hostname.literal("example.com"), .port = 443 } },
            "Dns { host: Hostname(\"example.com\"), port: 443 }",
        },
    };
    for (cases) |case| {
        try testing.expectEqualStrings(case[1], try std.fmt.bufPrint(&buffer, "{f}", .{case[0]}));
    }
}

test "address roundtrips and helpers" {
    const socket = v4(10, 0, 0, 1, 8080);
    const egress = v4(192, 168, 1, 1, 9090);
    try roundtrip(Address, .{ .symmetric = v4(192, 168, 1, 1, 8080) });
    const socket_ingress: Ingress = .{ .socket = socket };
    try roundtrip(Address, .{ .asymmetric = .{ .ingress = socket_ingress, .egress = egress } });
    const node = Hostname.literal("node.example.com");
    const dns: Ingress = .{ .dns = .{ .host = node, .port = 8080 } };
    try roundtrip(Address, .{ .asymmetric = .{ .ingress = dns, .egress = egress } });

    const symmetric: Address = .{ .symmetric = socket };
    try testing.expect(symmetric.ingress().eql(.{ .socket = socket }));
    try testing.expect(symmetric.egress_ip().order(.{ .v4 = Ipv4.init(10, 0, 0, 1) }) == .eq);
    try testing.expect(symmetric.egress().order(socket) == .eq);
    const asymmetric: Address = .{ .asymmetric = .{ .ingress = dns, .egress = egress } };
    try testing.expect(asymmetric.ingress().eql(dns));
    try testing.expect(asymmetric.egress_ip().order(.{ .v4 = Ipv4.init(192, 168, 1, 1) }) == .eq);
    try testing.expect(asymmetric.egress().order(egress) == .eq);
}

test "ingress is_valid (test_ingress_is_allowed)" {
    const public: Ingress = .{ .socket = v4(8, 8, 8, 8, 8080) };
    const private: Ingress = .{ .socket = v4(10, 0, 0, 1, 8080) };
    const dns: Ingress = .{ .dns = .{ .host = Hostname.literal("example.com"), .port = 8080 } };
    for ([_]bool{ false, true }) |allow_private| {
        for ([_]bool{ false, true }) |allow_dns| {
            try testing.expect(public.is_valid(allow_private, allow_dns));
            try testing.expectEqual(allow_private, private.is_valid(allow_private, allow_dns));
            try testing.expectEqual(allow_dns, dns.is_valid(allow_private, allow_dns));
        }
    }
}

fn CodecConformance(comptime T: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(T);
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

test "conformance: Ingress and Address encodings match commonware" {
    const conformance = @import("conformance");
    const file = @embedFile("conformance.toml");
    const prefix = "commonware_p2p::types::tests::conformance::";
    const gpa = testing.allocator;
    const n_cases = 65536;
    const ingress_name = prefix ++ "CodecConformance<Ingress>";
    try conformance.verify(CodecConformance(Ingress), gpa, ingress_name, n_cases, file);
    const address_name = prefix ++ "CodecConformance<Address>";
    try conformance.verify(CodecConformance(Address), gpa, address_name, n_cases, file);
}
