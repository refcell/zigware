//! A hostname validated against RFC 1035/1123 (commonware `utils/src/hostname.rs`).
//!
//! At most 253 characters; dot-separated labels of 1 to 63 ASCII letters, digits, and
//! hyphens that neither start nor end with a hyphen. Stored inline (no allocation). Encodes
//! as a `Vec<u8>`: varint length, then the bytes; decoding rejects lengths over 253,
//! invalid UTF-8, and invalid hostnames with `Invalid("Hostname", ...)`.

const std = @import("std");
const codec = @import("codec");
const rng = @import("rng.zig");
const fuzz = @import("fuzz.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Maximum length of a hostname (RFC 1035).
pub const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length of one label (RFC 1035).
pub const MAX_HOSTNAME_LABEL_LEN: usize = 63;

const HostnameError = error{
    Empty,
    TooLong,
    LabelTooLong,
    EmptyLabel,
    InvalidCharacter,
    LabelStartsWithHyphen,
    LabelEndsWithHyphen,
};

pub const Error = HostnameError;

pub const Hostname = struct {
    bytes: [len_max]u8,
    len: u8,

    pub const len_max = MAX_HOSTNAME_LEN;
    pub const label_len_max = MAX_HOSTNAME_LABEL_LEN;
    pub const max_encode_size: usize = codec.varint.max_size(u32) + len_max;
    pub const Error = HostnameError;

    comptime {
        assert(len_max <= std.math.maxInt(u8));
        assert(max_encode_size == 258);
    }

    /// Validates `text` and copies it into a hostname.
    pub fn init(text: []const u8) HostnameError!Hostname {
        try validate(text);
        var hostname: Hostname = .{ .bytes = undefined, .len = @intCast(text.len) };
        @memcpy(hostname.bytes[0..text.len], text);
        assert(hostname.len == text.len);
        return hostname;
    }

    /// commonware's `hostname!`: panics on an invalid hostname.
    pub fn literal(text: []const u8) Hostname {
        return init(text) catch @panic("invalid hostname");
    }

    fn validate(text: []const u8) HostnameError!void {
        if (text.len == 0) return error.Empty;
        if (text.len > len_max) return error.TooLong;
        var labels = std.mem.splitScalar(u8, text, '.');
        while (labels.next()) |label| try validate_label(label);
    }

    fn validate_label(label: []const u8) HostnameError!void {
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > label_len_max) return error.LabelTooLong;
        for (label) |char| {
            // Non-ASCII bytes (any UTF-8 sequence) are never alphanumeric ASCII.
            if (!std.ascii.isAlphanumeric(char) and char != '-') return error.InvalidCharacter;
        }
        if (label[0] == '-') return error.LabelStartsWithHyphen;
        if (label[label.len - 1] == '-') return error.LabelEndsWithHyphen;
    }

    pub fn as_str(hostname: *const Hostname) []const u8 {
        assert(hostname.len > 0 and hostname.len <= len_max);
        return hostname.bytes[0..hostname.len];
    }

    pub fn eql(a: Hostname, b: Hostname) bool {
        return std.mem.eql(u8, a.as_str(), b.as_str());
    }

    /// Rust `String` ordering: lexicographic by bytes.
    pub fn order(a: Hostname, b: Hostname) std.math.Order {
        return std.mem.order(u8, a.as_str(), b.as_str());
    }

    pub fn format(hostname: Hostname, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(hostname.as_str());
    }

    pub fn write(hostname: Hostname, writer: *codec.Writer) void {
        codec.write(usize, hostname.len, writer);
        writer.write_bytes(hostname.as_str());
    }

    pub fn encode_size(hostname: Hostname) usize {
        const size = codec.encode_size(usize, hostname.len) + hostname.len;
        assert(size <= max_encode_size);
        return size;
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Hostname {
        const len = try codec.read_usize(reader, .to_inclusive(len_max));
        const bytes = try reader.take(len);
        if (!std.unicode.utf8ValidateSlice(bytes)) {
            return reader.invalid("Hostname", "invalid UTF-8");
        }
        return init(bytes) catch reader.invalid("Hostname", "invalid hostname");
    }

    /// commonware's `Arbitrary`: 1 to 4 labels of 1 to 10 characters from a small alphabet,
    /// with no hyphen at either end of a label.
    pub fn arbitrary(
        _: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Hostname {
        const edge = "abcde123";
        const inner = "abcde123-";
        var hostname: Hostname = .{ .bytes = undefined, .len = 0 };
        const labels = u.int_in_range(u8, 1, 4);
        for (0..labels) |label_index| {
            if (label_index > 0) hostname.push('.');
            const label_len = u.int_in_range(u8, 1, 10);
            for (0..label_len) |index| {
                const choices = if (index == 0 or index == label_len - 1) edge else inner;
                hostname.push(choices[u.int_in_range(usize, 0, choices.len - 1)]);
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

const testing = std.testing;

fn repeat(comptime char: u8, comptime count: usize) [count]u8 {
    return @splat(char);
}

test "hostname: valid" {
    const valid = [_][]const u8{
        "localhost",           "example",              "a",                  "example.com",
        "sub.example.com",     "deep.sub.example.com", "my-host",            "my-example-host.com",
        "a-b-c.d-e-f.com",     "123",                  "123.456",            "host1.example2.com",
        "1host.2example.3com", "Example.COM",          "MyHost.Example.Com",
    };
    for (valid) |text| {
        const hostname = try Hostname.init(text);
        try testing.expectEqualStrings(text, hostname.as_str());
    }
}

test "hostname: invalid" {
    const Case = struct { []const u8, Error };
    const cases = [_]Case{
        .{ "", error.Empty },
        .{ ".example.com", error.EmptyLabel },
        .{ "example.com.", error.EmptyLabel },
        .{ "example..com", error.EmptyLabel },
        .{ "my_host.com", error.InvalidCharacter },
        .{ "my host.com", error.InvalidCharacter },
        .{ "host@example.com", error.InvalidCharacter },
        .{ "host!.com", error.InvalidCharacter },
        .{ "h\u{f4}st.com", error.InvalidCharacter },
        .{ "-example.com", error.LabelStartsWithHyphen },
        .{ "example.-sub.com", error.LabelStartsWithHyphen },
        .{ "example-.com", error.LabelEndsWithHyphen },
        .{ "example.sub-.com", error.LabelEndsWithHyphen },
        .{ "-", error.LabelStartsWithHyphen },
        .{ &repeat('a', 64), error.LabelTooLong },
    };
    for (cases) |case| try testing.expectError(case[1], Hostname.init(case[0]));
    _ = try Hostname.init(&repeat('a', 63));
}

test "hostname: length limit" {
    const label = repeat('a', 63);
    const too_long = label ++ "." ++ label ++ "." ++ label ++ "." ++ label;
    try testing.expectEqual(@as(usize, 255), too_long.len);
    try testing.expectError(error.TooLong, Hostname.init(too_long));
    const widest = label ++ "." ++ label ++ "." ++ label ++ "." ++ repeat('a', 61);
    try testing.expectEqual(MAX_HOSTNAME_LEN, widest.len);
    const hostname = try Hostname.init(widest);
    try testing.expectEqual(@as(usize, 258), Hostname.max_encode_size);
    try testing.expectEqual(@as(usize, 255), hostname.encode_size());
}

test "hostname: display, literal, order" {
    const hostname = Hostname.literal("example.com");
    var buffer: [32]u8 = undefined;
    const shown = try std.fmt.bufPrint(&buffer, "{f}", .{hostname});
    try testing.expectEqualStrings("example.com", shown);
    const a_b = Hostname.literal("a.b");
    try testing.expectEqual(std.math.Order.lt, a_b.order(Hostname.literal("a.c")));
    const ab = Hostname.literal("ab");
    try testing.expectEqual(std.math.Order.gt, ab.order(Hostname.literal("a")));
}

test "hostname: codec" {
    const hostname = Hostname.literal("example.com");
    var buffer: [Hostname.max_encode_size]u8 = undefined;
    const encoded = codec.encode_to(Hostname, hostname, &buffer);
    try testing.expectEqualSlices(u8, "\x0bexample.com", encoded);
    try testing.expect(hostname.eql(try codec.decode(Hostname, testing.allocator, encoded)));

    const Case = struct { []const u8, codec.Error };
    const cases = [_]Case{
        .{ "\x05ex..m", error.Invalid },
        .{ "\x02\xff\xfe", error.Invalid },
        .{ "\x00", error.Invalid },
        .{ "\x05abc", error.EndOfBuffer },
        .{ "\xfe\x01", error.InvalidLength },
    };
    for (cases) |case| {
        try testing.expectError(case[1], codec.decode(Hostname, testing.allocator, case[0]));
    }
    var reader = codec.Reader.init("\x02\xff\xfe");
    _ = codec.decode_reader(Hostname, testing.allocator, &reader, {}) catch {};
    try testing.expectEqualStrings("invalid UTF-8", reader.diagnostic.message);
}

/// Fuzz (commonware utils/fuzz): decoding never panics; anything decoded re-encodes to the
/// same bytes, and anything `init` accepts round-trips.
fn fuzz_hostname(_: void, generator: *rng.FuzzRng) !void {
    var input: [300]u8 = undefined;
    const len = rng.range_at_most(generator, usize, 0, input.len);
    const alphabet = "ab-.1\xff";
    for (input[0..len]) |*byte| {
        byte.* = alphabet[rng.range_less_than(generator, usize, 0, alphabet.len)];
    }
    if (Hostname.init(input[0..len])) |hostname| {
        try testing.expectEqualStrings(input[0..len], hostname.as_str());
        var buffer: [Hostname.max_encode_size]u8 = undefined;
        const encoded = codec.encode_to(Hostname, hostname, &buffer);
        try testing.expect(hostname.eql(try codec.decode(Hostname, testing.allocator, encoded)));
    } else |_| {}
    const decoded = codec.decode(Hostname, testing.allocator, input[0..len]) catch return;
    var buffer: [Hostname.max_encode_size]u8 = undefined;
    try testing.expectEqualSlices(u8, input[0..len], codec.encode_to(Hostname, decoded, &buffer));
}

test "fuzz hostname" {
    try fuzz.run({}, fuzz_hostname, 0x686f_7374, 2000);
}
