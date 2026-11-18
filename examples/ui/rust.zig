//! The Rust standard library parsers whose results and error text the examples' `main`s
//! show: `str::parse::<uN>()`, `SocketAddr::from_str`, and strsim's `jaro` (clap's
//! did-you-mean).

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// Rust `IntErrorKind`.
pub const ParseIntError = error{ Empty, InvalidDigit, PosOverflow };

/// Rust `str::parse::<T>()` for an unsigned integer: an optional `+`, then decimal digits.
pub fn parse_unsigned(comptime T: type, text: []const u8) ParseIntError!T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    if (text.len == 0) return error.Empty;
    const digits = if (text[0] == '+' and text.len > 1) text[1..] else text;
    assert(digits.len > 0);
    var value: T = 0;
    for (digits) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDigit;
        const shifted = std.math.mul(T, value, 10) catch return error.PosOverflow;
        value = std.math.add(T, shifted, byte - '0') catch return error.PosOverflow;
    }
    return value;
}

/// `ParseIntError`'s `Display`, as clap prints it.
pub fn int_error_text(failure: ParseIntError) []const u8 {
    return switch (failure) {
        error.Empty => "cannot parse integer from empty string",
        error.InvalidDigit => "invalid digit found in string",
        error.PosOverflow => "number too large to fit in target type",
    };
}

/// `ParseIntError`'s `Debug`, as `expect` prints it.
pub fn int_error_debug(failure: ParseIntError) []const u8 {
    return switch (failure) {
        error.Empty => "ParseIntError { kind: Empty }",
        error.InvalidDigit => "ParseIntError { kind: InvalidDigit }",
        error.PosOverflow => "ParseIntError { kind: PosOverflow }",
    };
}

/// Rust's `SocketAddr::from_str`: `a.b.c.d:port` or `[ipv6]:port`.
pub fn parse_socket_address(text: []const u8) ?Io.net.IpAddress {
    const separator = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const port_text = text[separator + 1 ..];
    if (port_text.len == 0 or port_text.len > 5) return null;
    for (port_text) |byte| if (!std.ascii.isDigit(byte)) return null;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return null;
    const host = text[0..separator];
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return Io.net.IpAddress.parseIp6(host[1 .. host.len - 1], port) catch null;
    }
    if (std.mem.indexOfScalar(u8, host, ':') != null) return null;
    return Io.net.IpAddress.parseIp4(host, port) catch null;
}

/// Jaro similarity of two byte strings (strsim 0.11 `jaro`), over their first 64 bytes.
pub fn jaro(a_full: []const u8, b_full: []const u8) f64 {
    const a = a_full[0..@min(a_full.len, 64)];
    const b = b_full[0..@min(b_full.len, 64)];
    if (a.len == 0 and b.len == 0) return 1.0;
    if (a.len == 0 or b.len == 0) return 0.0;
    const search_range = (@max(a.len, b.len) / 2) -| 1;
    var a_flags: [64]bool = @splat(false);
    var b_flags: [64]bool = @splat(false);
    var matches: usize = 0;
    for (a, 0..) |a_byte, i| {
        const low = i -| search_range;
        const high = @max(low, @min(b.len, i + search_range + 1));
        for (low..high) |j| {
            if (a_byte == b[j] and !b_flags[j]) {
                a_flags[i] = true;
                b_flags[j] = true;
                matches += 1;
                break;
            }
        }
    }
    if (matches == 0) return 0.0;
    var transpositions: usize = 0;
    var j: usize = 0;
    for (a, 0..) |a_byte, i| {
        if (!a_flags[i]) continue;
        while (!b_flags[j]) j += 1;
        if (a_byte != b[j]) transpositions += 1;
        j += 1;
    }
    transpositions /= 2;
    assert(transpositions <= matches);
    const m: f64 = @floatFromInt(matches);
    const t: f64 = @floatFromInt(transpositions);
    const a_len: f64 = @floatFromInt(a.len);
    const b_len: f64 = @floatFromInt(b.len);
    return (m / a_len + m / b_len + (m - t) / m) / 3.0;
}

/// A failure commonware reports with a panic; the message is commonware's.
pub const Panic = struct {
    buffer: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(panic: *const Panic) []const u8 {
        return panic.buffer[0..panic.len];
    }

    pub fn fail(panic: *Panic, comptime format: []const u8, args: anytype) error{Panic} {
        var writer: Io.Writer = .fixed(&panic.buffer);
        writer.print(format, args) catch {}; // Truncated: the buffer is full.
        panic.len = writer.end;
        return error.Panic;
    }
};

/// A bootstrapper: its key seed and socket address.
pub const Bootstrapper = struct { key: u64, address: Io.net.IpAddress };

/// Each bootstrapper as `<key>@<ip>:<port>` (text after a second `@` is ignored).
pub fn parse_bootstrappers(
    gpa: Allocator,
    text: ?[]const u8,
    panic: *Panic,
) (Allocator.Error || error{Panic})![]const Bootstrapper {
    var bootstrappers: std.ArrayList(Bootstrapper) = .empty;
    errdefer bootstrappers.deinit(gpa);
    var entries = std.mem.splitScalar(u8, text orelse return &.{}, ',');
    while (entries.next()) |entry| {
        var fields = std.mem.splitScalar(u8, entry, '@');
        const key = parse_unsigned(u64, fields.first()) catch |failure| {
            const debug = int_error_debug(failure);
            return panic.fail("Bootstrapper key not well-formed: {s}", .{debug});
        };
        const address_text = fields.next() orelse return panic.fail(out_of_bounds, .{});
        const address = parse_socket_address(address_text) orelse return panic.fail(
            "Bootstrapper address not well-formed: AddrParseError(Socket)",
            .{},
        );
        try bootstrappers.append(gpa, .{ .key = key, .address = address });
    }
    assert(bootstrappers.items.len > 0);
    return bootstrappers.toOwnedSlice(gpa);
}

pub const out_of_bounds = "index out of bounds: the len is 1 but the index is 1";
