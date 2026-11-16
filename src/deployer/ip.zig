//! IP addresses as Rust's `std::net::IpAddr` parses and displays them, which is how the
//! deployer's YAML files hold them (`Host.ip`, `Ips`). `std.Io.net.IpAddress` carries a port
//! and formats it, so the deployer keeps its own type.
//!
//! Parsing follows Rust's `core::net::parser`: IPv4 is four decimal octets without leading
//! zeros; IPv6 is up to eight hex groups of at most four digits with at most one `::`, and may
//! end in an embedded IPv4 address. Display follows Rust's `Display`: IPv4-mapped addresses
//! print as `::ffff:a.b.c.d`; otherwise the first longest run of two or more zero groups
//! collapses to `::` and groups print in lowercase hex without leading zeros.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

pub const IpAddr = union(enum) {
    v4: [4]u8,
    v6: [8]u16,

    /// Rust `IpAddr::from_str`: IPv4 first, then IPv6; the whole text must be an address.
    pub fn parse(text: []const u8) error{InvalidIp}!IpAddr {
        var v4: Cursor = .{ .text = text };
        if (v4.ipv4()) |octets| if (v4.done()) return .{ .v4 = octets };
        var v6: Cursor = .{ .text = text };
        if (v6.ipv6()) |groups| if (v6.done()) return .{ .v6 = groups };
        return error.InvalidIp;
    }

    pub fn format(ip: IpAddr, writer: *Io.Writer) Io.Writer.Error!void {
        switch (ip) {
            .v4 => |octets| try write_v4(writer, octets),
            .v6 => |groups| try write_v6(writer, groups),
        }
    }

    pub fn eql(a: IpAddr, b: IpAddr) bool {
        return switch (a) {
            .v4 => |octets| b == .v4 and std.mem.eql(u8, &octets, &b.v4),
            .v6 => |groups| b == .v6 and std.mem.eql(u16, &groups, &b.v6),
        };
    }

    /// The `std.Io.net` address of this IP at `port`.
    pub fn to_io(ip: IpAddr, port: u16) Io.net.IpAddress {
        return switch (ip) {
            .v4 => |octets| .{ .ip4 = .{ .bytes = octets, .port = port } },
            .v6 => |groups| blk: {
                var bytes: [16]u8 = undefined;
                for (groups, 0..) |group, index| {
                    std.mem.writeInt(u16, bytes[2 * index ..][0..2], group, .big);
                }
                break :blk .{ .ip6 = .{ .bytes = bytes, .port = port } };
            },
        };
    }
};

fn write_v4(writer: *Io.Writer, octets: [4]u8) Io.Writer.Error!void {
    try writer.print("{d}.{d}.{d}.{d}", .{ octets[0], octets[1], octets[2], octets[3] });
}

fn write_groups(writer: *Io.Writer, groups: []const u16) Io.Writer.Error!void {
    for (groups, 0..) |group, index| {
        if (index > 0) try writer.writeByte(':');
        try writer.print("{x}", .{group});
    }
}

fn write_v6(writer: *Io.Writer, groups: [8]u16) Io.Writer.Error!void {
    const mapped = std.mem.allEqual(u16, groups[0..5], 0) and groups[5] == 0xffff;
    if (mapped) {
        try writer.writeAll("::ffff:");
        const a = groups[6];
        const b = groups[7];
        const octets: [4]u8 = .{ @truncate(a >> 8), @truncate(a), @truncate(b >> 8), @truncate(b) };
        return write_v4(writer, octets);
    }
    // The first longest run of zero groups.
    var longest_start: usize = 0;
    var longest_len: usize = 0;
    var current_start: usize = 0;
    var current_len: usize = 0;
    for (groups, 0..) |group, index| {
        if (group != 0) {
            current_len = 0;
            continue;
        }
        if (current_len == 0) current_start = index;
        current_len += 1;
        if (current_len > longest_len) {
            longest_start = current_start;
            longest_len = current_len;
        }
    }
    assert(longest_len <= groups.len);
    if (longest_len < 2) return write_groups(writer, &groups);
    try write_groups(writer, groups[0..longest_start]);
    try writer.writeAll("::");
    try write_groups(writer, groups[longest_start + longest_len ..]);
}

/// Rust's parser over `text`: each reader restores the position when it fails.
const Cursor = struct {
    text: []const u8,
    position: usize = 0,

    fn done(cursor: *const Cursor) bool {
        return cursor.position == cursor.text.len;
    }

    fn char(cursor: *Cursor, expected: u8) bool {
        if (cursor.position == cursor.text.len) return false;
        if (cursor.text[cursor.position] != expected) return false;
        cursor.position += 1;
        return true;
    }

    /// Rust `read_number`: at most `digits_max` digits; with `zero_prefix` false, a number
    /// of several digits may not start with `0`.
    fn number(cursor: *Cursor, radix: u8, digits_max: usize, zero_prefix: bool) ?u32 {
        const start = cursor.position;
        var value: u32 = 0;
        var count: usize = 0;
        while (cursor.position < cursor.text.len) : (cursor.position += 1) {
            const digit = std.fmt.charToDigit(cursor.text[cursor.position], radix) catch break;
            value = value * radix + digit;
            count += 1;
            if (count > digits_max) break;
        }
        const leading_zero = count > 1 and cursor.text[start] == '0';
        if (count == 0 or count > digits_max or (!zero_prefix and leading_zero)) {
            cursor.position = start;
            return null;
        }
        return value;
    }

    fn ipv4(cursor: *Cursor) ?[4]u8 {
        const start = cursor.position;
        var octets: [4]u8 = undefined;
        for (&octets, 0..) |*octet, index| {
            const separated = index == 0 or cursor.char('.');
            const value = if (separated) cursor.number(10, 3, false) else null;
            octet.* = std.math.cast(u8, value orelse 256) orelse {
                cursor.position = start;
                return null;
            };
        }
        return octets;
    }

    /// Rust `read_groups`: fills `groups` from the front; returns how many were read and
    /// whether the last two came from an embedded IPv4 address.
    fn groups_into(cursor: *Cursor, groups: []u16) struct { usize, bool } {
        for (0..groups.len) |index| {
            if (index + 1 < groups.len) {
                const before = cursor.position;
                if (index == 0 or cursor.char(':')) {
                    if (cursor.ipv4()) |octets| {
                        groups[index] = @as(u16, octets[0]) << 8 | octets[1];
                        groups[index + 1] = @as(u16, octets[2]) << 8 | octets[3];
                        return .{ index + 2, true };
                    }
                }
                cursor.position = before;
            }
            const before = cursor.position;
            const separated = index == 0 or cursor.char(':');
            const group = if (separated) cursor.number(16, 4, true) else null;
            groups[index] = @intCast(group orelse {
                cursor.position = before;
                return .{ index, false };
            });
        }
        return .{ groups.len, false };
    }

    fn ipv6(cursor: *Cursor) ?[8]u16 {
        const start = cursor.position;
        var head: [8]u16 = @splat(0);
        const head_size, const head_ipv4 = cursor.groups_into(&head);
        if (head_size == 8) return head;
        // An IPv4 part is not allowed before `::`.
        if (head_ipv4 or !cursor.char(':') or !cursor.char(':')) {
            cursor.position = start;
            return null;
        }
        var tail: [7]u16 = @splat(0);
        const limit = 8 - (head_size + 1);
        const tail_size, _ = cursor.groups_into(tail[0..limit]);
        assert(head_size + tail_size < 8);
        @memcpy(head[8 - tail_size ..], tail[0..tail_size]);
        return head;
    }
};

const testing = std.testing;

fn expect_display(text: []const u8, expected: []const u8) !void {
    const ip = try IpAddr.parse(text);
    var buffer: [64]u8 = undefined;
    const shown = try std.fmt.bufPrint(&buffer, "{f}", .{ip});
    try testing.expectEqualStrings(expected, shown);
}

test "ipv4 parses as Rust does" {
    try expect_display("1.2.3.4", "1.2.3.4");
    try expect_display("0.0.0.0", "0.0.0.0");
    try expect_display("255.255.255.255", "255.255.255.255");
    for ([_][]const u8{
        "256.0.0.1", "01.2.3.4",   "1.2.3", "1.2.3.4.5", "1..2.3", " 1.2.3.4", "1.2.3.4 ",
        "",          "1.2.3.0004",
    }) |text| try testing.expectError(error.InvalidIp, IpAddr.parse(text));
}

test "ipv6 parses and displays as Rust does" {
    try expect_display("::", "::");
    try expect_display("::1", "::1");
    try expect_display("2001:db8::1", "2001:db8::1");
    try expect_display("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1");
    // The first longest zero run collapses; a single zero group does not.
    try expect_display("1:0:0:2:0:0:0:3", "1:0:0:2::3");
    try expect_display("1:0:0:2:0:0:3:4", "1::2:0:0:3:4");
    try expect_display("1:2:3:4:5:6:0:8", "1:2:3:4:5:6:0:8");
    // IPv4-mapped addresses print their IPv4 part; other embedded IPv4 prints as hex.
    try expect_display("::ffff:1.2.3.4", "::ffff:1.2.3.4");
    try expect_display("::1.2.3.4", "::102:304");
    try expect_display("1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304");
    for ([_][]const u8{
        ":::",
        "1::2::3",
        "12345::",
        "1:2:3:4:5:6:7:8:9",
        "1.2.3.4::",
        ":1",
        "1:",
        "g::",
        "1:2:3:4:5:6:7:1.2.3.4",
        "::1.2.3",
    }) |text| try testing.expectError(error.InvalidIp, IpAddr.parse(text));
}

test "to_io carries the address bytes" {
    const ip = try IpAddr.parse("2001:db8::1");
    const io_ip = ip.to_io(9090);
    try testing.expectEqual(@as(u8, 0x20), io_ip.ip6.bytes[0]);
    try testing.expectEqual(@as(u8, 0x01), io_ip.ip6.bytes[15]);
    try testing.expect(ip.eql(try IpAddr.parse("2001:db8:0::1")));
    try testing.expect(!ip.eql(try IpAddr.parse("1.2.3.4")));
}
