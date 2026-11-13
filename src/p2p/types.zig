//! Shared address types for p2p networking (commonware `p2p/src/types.rs`).
//!
//! `Ingress` is what a peer dials (a socket address or a DNS name and port) and `Address`
//! pairs it with the egress socket a peer connects from. Both encode byte-identically to
//! commonware. `Hostname` and `is_global` stand in for `commonware_utils::Hostname` and
//! `IpAddrExt::is_global` until the utils lane ports `hostname.rs` and `net.rs`; they keep the
//! same validation and wire format, so switching later changes no bytes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");

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

/// A hostname validated against RFC 1035/1123 (commonware `utils::Hostname`), stored inline.
///
/// At most 253 characters; labels of 1 to 63 ASCII letters, digits, and hyphens, not starting
/// or ending with a hyphen. Encodes as `Vec<u8>` (varint length, then the bytes).
pub const Hostname = struct {
    bytes: [len_max]u8,
    len: u8,

    /// Maximum length of a hostname (253 characters per RFC 1035).
    pub const len_max = 253;
    /// Maximum length of a single label (63 characters per RFC 1035).
    pub const label_len_max = 63;
    pub const max_encode_size: usize = codec.varint.max_size(u32) + len_max;

    pub const Error = error{
        Empty,
        TooLong,
        LabelTooLong,
        EmptyLabel,
        InvalidCharacter,
        LabelStartsWithHyphen,
        LabelEndsWithHyphen,
    };

    comptime {
        assert(len_max <= std.math.maxInt(u8));
        assert(max_encode_size == 258);
    }

    /// Validates `text` and copies it into a hostname.
    pub fn init(text: []const u8) Error!Hostname {
        try validate(text);
        var hostname: Hostname = .{ .bytes = undefined, .len = @intCast(text.len) };
        @memcpy(hostname.bytes[0..text.len], text);
        assert(hostname.len == text.len);
        return hostname;
    }

    /// `hostname!`: panics on an invalid hostname. For tests and known-valid constants.
    pub fn literal(text: []const u8) Hostname {
        return init(text) catch @panic("invalid hostname");
    }

    fn validate(text: []const u8) Error!void {
        if (text.len == 0) return error.Empty;
        if (text.len > len_max) return error.TooLong;
        var labels = std.mem.splitScalar(u8, text, '.');
        while (labels.next()) |label| try validate_label(label);
    }

    fn validate_label(label: []const u8) Error!void {
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > label_len_max) return error.LabelTooLong;
        for (label) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidCharacter;
        }
        if (label[0] == '-') return error.LabelStartsWithHyphen;
        if (label[label.len - 1] == '-') return error.LabelEndsWithHyphen;
    }

    pub fn as_str(hostname: *const Hostname) []const u8 {
        assert(hostname.len <= len_max);
        return hostname.bytes[0..hostname.len];
    }

    pub fn eql(a: Hostname, b: Hostname) bool {
        return std.mem.eql(u8, a.as_str(), b.as_str());
    }

    /// Rust `String` ordering: lexicographic by bytes.
    pub fn order(a: Hostname, b: Hostname) std.math.Order {
        return std.mem.order(u8, a.as_str(), b.as_str());
    }

    pub fn write(hostname: Hostname, writer: *codec.Writer) void {
        codec.write(usize, hostname.len, writer);
        writer.write_bytes(hostname.as_str());
    }

    pub fn encode_size(hostname: Hostname) usize {
        return codec.encode_size(usize, hostname.len) + hostname.len;
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Hostname {
        const len = try codec.read_usize(reader, .to_inclusive(len_max));
        const bytes = try reader.take(len);
        if (!std.unicode.utf8ValidateSlice(bytes)) {
            return reader.invalid("Hostname", "invalid UTF-8");
        }
        return init(bytes) catch reader.invalid("Hostname", "invalid hostname");
    }

    pub fn format(hostname: Hostname, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(hostname.as_str());
    }

    /// commonware's `Arbitrary for Hostname`: 1 to 4 labels of 1 to 10 characters.
    pub fn arbitrary(_: Allocator, u: *Unstructured) ArbitraryError!Hostname {
        const edge = "abcde123";
        const inner = "abcde123-";
        var hostname: Hostname = .{ .bytes = undefined, .len = 0 };
        const labels = u.int_in_range(u8, 1, 4);
        for (0..labels) |label_index| {
            if (label_index > 0) hostname.push('.');
            const label_len = u.int_in_range(u8, 1, 10);
            for (0..label_len) |index| {
                const choices = if (index == 0 or index == label_len - 1) edge else inner;
                hostname.push(choices[u.int_in_range(u64, 0, choices.len - 1)]);
            }
        }
        assert(hostname.len > 0);
        return hostname;
    }

    fn push(hostname: *Hostname, byte: u8) void {
        assert(hostname.len < len_max);
        hostname.bytes[hostname.len] = byte;
        hostname.len += 1;
    }
};

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

/// Whether `ip` is globally reachable per the IANA IPv4 and IPv6 Special-Purpose Address
/// Registries (commonware `IpAddrExt::is_global`, mirroring Rust's unstable `is_global`).
pub fn is_global(ip: IpAddr) bool {
    return switch (ip) {
        .v4 => |addr| is_global_v4(addr),
        .v6 => |addr| is_global_v6(addr),
    };
}

fn is_global_v4(ip: Ipv4) bool {
    const o = ip.octets;
    const broadcast = std.mem.eql(u8, &o, &.{ 255, 255, 255, 255 });
    const private = o[0] == 10 or (o[0] == 172 and o[1] & 0xf0 == 16) or
        (o[0] == 192 and o[1] == 168);
    const shared = o[0] == 100 and o[1] & 0b1100_0000 == 0b0100_0000;
    const loopback = o[0] == 127;
    const link_local = o[0] == 169 and o[1] == 254;
    const future_protocol = o[0] == 192 and o[1] == 0 and o[2] == 0 and o[3] != 9 and
        o[3] != 10;
    const relay_anycast = std.mem.eql(u8, &o, &.{ 192, 88, 99, 2 });
    const documentation = (o[0] == 192 and o[1] == 0 and o[2] == 2) or
        (o[0] == 198 and o[1] == 51 and o[2] == 100) or (o[0] == 203 and o[1] == 0 and o[2] == 113);
    const benchmarking = o[0] == 198 and o[1] & 0xfe == 18;
    const reserved = o[0] & 240 == 240 and !broadcast;
    return !(o[0] == 0 or private or shared or loopback or link_local or future_protocol or
        relay_anycast or documentation or benchmarking or reserved or broadcast);
}

fn is_global_v6(ip: Ipv6) bool {
    var s: [8]u16 = undefined;
    for (&s, 0..) |*segment, index| {
        segment.* = std.mem.readInt(u16, ip.octets[index * 2 ..][0..2], .big);
    }
    const value = std.mem.readInt(u128, &ip.octets, .big);
    const unspecified = value == 0;
    const loopback = value == 1;
    const ipv4_mapped = std.mem.allEqual(u16, s[0..5], 0) and s[5] == 0xffff;
    const translation = s[0] == 0x64 and s[1] == 0xff9b and s[2] == 1;
    const discard_only = s[0] == 0x100 and s[1] == 0 and s[2] == 0 and s[3] == 0;
    const dummy = s[0] == 0x100 and s[1] == 0 and s[2] == 0 and s[3] == 1;
    const ietf_global = value == 0x2001_0001_0000_0000_0000_0000_0000_0001 or
        value == 0x2001_0001_0000_0000_0000_0000_0000_0002 or
        value == 0x2001_0001_0000_0000_0000_0000_0000_0003 or
        (s[0] == 0x2001 and s[1] == 3) or (s[0] == 0x2001 and s[1] == 4 and s[2] == 0x112) or
        (s[0] == 0x2001 and s[1] >= 0x20 and s[1] <= 0x3f);
    const ietf = s[0] == 0x2001 and s[1] < 0x200 and !ietf_global;
    const six_to_four = s[0] == 0x2002;
    const documentation = (s[0] == 0x2001 and s[1] == 0xdb8) or (s[0] == 0x3fff and s[1] <= 0x0fff);
    const segment_routing = s[0] == 0x5f00;
    const unique_local = s[0] & 0xfe00 == 0xfc00;
    const link_local = s[0] & 0xffc0 == 0xfe80;
    return !(unspecified or loopback or ipv4_mapped or translation or discard_only or dummy or
        ietf or six_to_four or documentation or segment_routing or unique_local or link_local);
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

test "hostname validation" {
    const valid = [_][]const u8{
        "localhost",       "a",   "sub.example.com",     "my-host",
        "a-b-c.d-e-f.com", "123", "1host.2example.3com", "MyHost.Example.Com",
    };
    for (valid) |text| {
        _ = try Hostname.init(text);
    }
    try testing.expectError(error.Empty, Hostname.init(""));
    try testing.expectError(error.TooLong, Hostname.init(&(@as([254]u8, @splat('a')))));
    try testing.expectError(error.LabelTooLong, Hostname.init(&(@as([64]u8, @splat('a')))));
    try testing.expectError(error.EmptyLabel, Hostname.init("a..b"));
    try testing.expectError(error.EmptyLabel, Hostname.init(".a"));
    try testing.expectError(error.EmptyLabel, Hostname.init("a."));
    try testing.expectError(error.InvalidCharacter, Hostname.init("a_b"));
    try testing.expectError(error.InvalidCharacter, Hostname.init("a b"));
    try testing.expectError(error.LabelStartsWithHyphen, Hostname.init("-a"));
    try testing.expectError(error.LabelEndsWithHyphen, Hostname.init("a-.b"));
    _ = try Hostname.init(&(@as([63]u8, @splat('a'))));
    _ = widest_hostname();
}

test "hostname decode rejects invalid hostnames" {
    const gpa = testing.allocator;
    try testing.expectError(error.Invalid, codec.decode(Hostname, gpa, "\x03a_b"));
    try testing.expectError(error.Invalid, codec.decode(Hostname, gpa, "\x02\xff\xfe"));
    try testing.expectError(error.EndOfBuffer, codec.decode(Hostname, gpa, "\x05abc"));
    const host = try codec.decode(Hostname, gpa, "\x0bexample.com");
    try testing.expectEqualStrings("example.com", host.as_str());
}

test "is_global" {
    const globals = [_]IpAddr{
        .{ .v4 = Ipv4.init(8, 8, 8, 8) },
        .{ .v4 = Ipv4.init(192, 0, 0, 9) },
        .{ .v6 = Ipv6.init(.{ 0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111 }) },
        .{ .v6 = Ipv6.init(.{ 0x2001, 1, 0, 0, 0, 0, 0, 1 }) },
    };
    for (globals) |ip| try testing.expect(is_global(ip));
    const locals = [_]IpAddr{
        .{ .v4 = Ipv4.init(0, 1, 2, 3) },
        .{ .v4 = Ipv4.init(10, 0, 0, 1) },
        .{ .v4 = Ipv4.init(172, 16, 0, 1) },
        .{ .v4 = Ipv4.init(192, 168, 1, 1) },
        .{ .v4 = Ipv4.init(100, 64, 0, 1) },
        .{ .v4 = Ipv4.localhost },
        .{ .v4 = Ipv4.init(169, 254, 0, 1) },
        .{ .v4 = Ipv4.init(192, 0, 0, 1) },
        .{ .v4 = Ipv4.init(192, 88, 99, 2) },
        .{ .v4 = Ipv4.init(203, 0, 113, 1) },
        .{ .v4 = Ipv4.init(198, 18, 0, 1) },
        .{ .v4 = Ipv4.init(240, 0, 0, 1) },
        .{ .v4 = Ipv4.init(255, 255, 255, 255) },
        .{ .v6 = Ipv6.unspecified },
        .{ .v6 = Ipv6.localhost },
        .{ .v6 = Ipv6.init(.{ 0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808 }) },
        .{ .v6 = Ipv6.init(.{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 }) },
        .{ .v6 = Ipv6.init(.{ 0xfc00, 0, 0, 0, 0, 0, 0, 1 }) },
        .{ .v6 = Ipv6.init(.{ 0xfe80, 0, 0, 0, 0, 0, 0, 1 }) },
        .{ .v6 = Ipv6.init(.{ 0x2002, 0, 0, 0, 0, 0, 0, 1 }) },
        .{ .v6 = Ipv6.init(.{ 0x2001, 0x100, 0, 0, 0, 0, 0, 1 }) },
    };
    for (locals) |ip| try testing.expect(!is_global(ip));
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
