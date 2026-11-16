//! Tests for `yaml.zig`: serde_yaml 0.9.34's output for single strings, the reader's subset,
//! serde_yaml's typed scalar rules, and a seeded write/read round trip fuzz.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const utils = @import("utils");
const yaml = @import("yaml.zig");

/// `serde_yaml::to_string(&text)` without its trailing newline, generated with
/// serde_yaml 0.9.34.
const golden = [_]struct { []const u8, []const u8 }{
    .{ "plain", "plain" },
    .{ "", "''" },
    .{ "~", "'~'" },
    .{ "null", "'null'" },
    .{ "true", "'true'" },
    .{ "False", "'False'" },
    .{ "123", "'123'" },
    .{ "-7", "'-7'" },
    .{ "+5", "'+5'" },
    .{ "0x1F", "'0x1F'" },
    .{ "-0x10", "'-0x10'" },
    .{ "0o17", "'0o17'" },
    .{ "0b101", "'0b101'" },
    .{ "007", "'007'" },
    .{ "-007", "'-007'" },
    .{ "1.5", "'1.5'" },
    .{ "1e5", "'1e5'" },
    .{ ".5", "'.5'" },
    .{ "1.", "'1.'" },
    .{ "1e400", "1e400" },
    .{ ".inf", "'.inf'" },
    .{ "-.inf", "'-.inf'" },
    .{ ".nan", "'.nan'" },
    .{ "nan", "nan" },
    .{ "inf", "inf" },
    .{ "0.0.0.0/0", "0.0.0.0/0" },
    .{ "1.2.3.4", "1.2.3.4" },
    .{ "::1", "::1" },
    .{ "2001:db8::1", "2001:db8::1" },
    .{ "- x", "'- x'" },
    .{ "-x", "-x" },
    .{ "a: b", "'a: b'" },
    .{ "a:b", "a:b" },
    .{ "a #b", "'a #b'" },
    .{ "a#b", "a#b" },
    .{ "#a", "'#a'" },
    .{ " lead", "' lead'" },
    .{ "trail ", "'trail '" },
    .{ "x:", "'x:'" },
    .{ "?x", "?x" },
    .{ "? x", "'? x'" },
    .{ ":x", ":x" },
    .{ "---", "'---'" },
    .{ "...x", "'...x'" },
    .{ "a, b", "a, b" },
    .{ "a[b]", "a[b]" },
    .{ "'q'", "'''q'''" },
    .{ "\"q\"", "'\"q\"'" },
    .{ "it's", "it's" },
    .{ "tab\there", "\"tab\\there\"" },
    .{ "über", "über" },
    .{ "a\x7fb", "\"a\\x7Fb\"" },
    .{ "0x", "0x" },
    .{ "+", "+" },
    .{ "-", "'-'" },
    .{ "0xG", "0xG" },
    .{ "+0x5", "'+0x5'" },
    .{ "0x+5", "0x+5" },
    .{ "-0x-5", "-0x-5" },
    .{ "1_000", "1_000" },
    .{ "/path/to/x", "/path/to/x" },
    .{ "t4g.small", "t4g.small" },
    .{ "us-east-1", "us-east-1" },
    .{ "Yes", "Yes" },
    .{ "on", "on" },
    .{ "%x", "'%x'" },
    .{ "@x", "'@x'" },
    .{ "`x", "'`x'" },
    .{ "&x", "'&x'" },
    .{ "*x", "'*x'" },
    .{ "!x", "'!x'" },
    .{ "|x", "'|x'" },
    .{ ">x", "'>x'" },
    .{ "{x", "'{x'" },
    .{ "x}", "x}" },
    .{ "x,y", "x,y" },
    .{
        "12345678901234567890123456789012345678901",
        "'12345678901234567890123456789012345678901'",
    },
    .{
        "340282366920938463463374607431768211455",
        "'340282366920938463463374607431768211455'",
    },
    .{
        "340282366920938463463374607431768211456",
        "'340282366920938463463374607431768211456'",
    },
    .{
        "-170141183460469231731687303715884105728",
        "'-170141183460469231731687303715884105728'",
    },
    .{ "ffa638a0-991c-442c-8ec4-aa4e418213a5", "ffa638a0-991c-442c-8ec4-aa4e418213a5" },
};

test "strings are written as serde_yaml writes them" {
    var buffer: [128]u8 = undefined;
    for (golden) |entry| {
        const text, const expected = entry;
        var writer: Io.Writer = .fixed(&buffer);
        try yaml.write_string(&writer, text);
        testing.expectEqualStrings(expected, writer.buffered()) catch |err| {
            std.debug.print("string: {s}\n", .{text});
            return err;
        };
    }
}

test "strings with line breaks are rejected" {
    for ([_][]const u8{ "a\nb", "a\rb", "a\u{85}b", "a\u{2028}b", "a\u{2029}b" }) |text| {
        try testing.expectError(error.InvalidValue, yaml.style_of(text));
    }
    try testing.expectError(error.InvalidValue, yaml.style_of("\xff"));
}

test "unprintable characters are double-quoted with libyaml's escapes" {
    var buffer: [128]u8 = undefined;
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "\x00\x07\x1b", "\"\\0\\a\\e\"" },
        .{ "\u{feff}x", "\"\\uFEFFx\"" },
        .{ "a\u{9f}", "\"a\\x9F\"" },
        .{ "\\\x01", "\"\\\\\\x01\"" },
        .{ "\u{1F600}", "\u{1F600}" },
    };
    for (cases) |case| {
        var writer: Io.Writer = .fixed(&buffer);
        try yaml.write_string(&writer, case[0]);
        try testing.expectEqualStrings(case[1], writer.buffered());
    }
}

fn parse(arena: std.mem.Allocator, text: []const u8) !yaml.Map {
    const document = try yaml.Document.parse(arena, text);
    return document.root.as_map();
}

test "block mappings and sequences parse" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const map = try parse(arena.allocator(),
        \\# A comment.
        \\---
        \\tag: ffa638a0  # trailing comment
        \\monitoring:
        \\  instance_type: 't4g.small'
        \\  storage_size: 0x10
        \\
        \\  empty:
        \\  quoted: "a\tb\u00fc\x41"
        \\instances:
        \\- name: node1
        \\  profiling: true
        \\-   name: 'it''s'
        \\    profiling: False
        \\regions:
        \\  - us-east-1
        \\  - 'null'
        \\ports: []
        \\extra: {}
    );
    try testing.expectEqualStrings("ffa638a0", try (try map.get("tag")).string());
    const monitoring = try (try map.get("monitoring")).as_map();
    try testing.expectEqualStrings("t4g.small", try (try monitoring.get("instance_type")).string());
    try testing.expectEqual(@as(i32, 16), try (try monitoring.get("storage_size")).integer(i32));
    try testing.expect((try monitoring.get("empty")).is_null());
    try testing.expectEqualStrings("a\tbüA", try (try monitoring.get("quoted")).string());
    const instances = try (try map.get("instances")).as_list();
    try testing.expectEqual(@as(usize, 2), instances.len);
    const second = try instances[1].as_map();
    try testing.expectEqualStrings("it's", try (try second.get("name")).string());
    try testing.expect(!try (try second.get("profiling")).boolean());
    try testing.expect(try (try (try instances[0].as_map()).get("profiling")).boolean());
    const regions = try (try map.get("regions")).as_list();
    try testing.expectEqualStrings("null", try regions[1].string());
    try testing.expect(!regions[1].is_null());
    try testing.expectEqual(@as(usize, 0), (try (try map.get("ports")).as_list()).len);
    try testing.expectEqual(@as(usize, 0), (try (try map.get("extra")).as_map()).entries.len);
    try testing.expectError(error.MissingKey, map.get("absent"));
    try testing.expectEqual(@as(?yaml.Node, null), try map.find("absent"));
}

test "malformed and unsupported documents are rejected" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cases = [_][]const u8{
        "a: 'open",
        "a: \"open",
        "a: 'x' y",
        "a: &anchor x",
        "a: !tag x",
        "a: [x]",
        "a: {b: c}",
        "a: \"\\q\"",
        "a: b\n  c: d",
        "- a\nb: c",
        "a: b\n---\nc: d",
        "a:\n\t- b",
        "a:\n-\n  b: c",
    };
    for (cases) |text| {
        const result = yaml.Document.parse(arena.allocator(), text);
        testing.expectError(error.InvalidYaml, result) catch |err| {
            std.debug.print("document: {s}\n", .{text});
            return err;
        };
    }
    const duplicate = try parse(arena.allocator(), "a: 1\na: 2\n");
    try testing.expectError(error.DuplicateKey, duplicate.get("a"));
}

test "typed scalars follow serde_yaml" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const map = try parse(arena.allocator(),
        \\hex: 0x7fffffff
        \\octal: 0o17
        \\binary: -0b101
        \\positive: +12
        \\big: 2147483648
        \\negative: -2147483648
        \\zeros: 007
        \\quoted: '5'
        \\underscore: 1_000
        \\yes: Yes
        \\upper: TRUE
        \\tilde: ~
        \\null_quoted: '~'
    );
    try testing.expectEqual(@as(i32, 0x7fffffff), try (try map.get("hex")).integer(i32));
    try testing.expectEqual(@as(u16, 15), try (try map.get("octal")).integer(u16));
    try testing.expectEqual(@as(i32, -5), try (try map.get("binary")).integer(i32));
    try testing.expectEqual(@as(u64, 12), try (try map.get("positive")).integer(u64));
    try testing.expectError(error.InvalidValue, (try map.get("big")).integer(i32));
    try testing.expectEqual(@as(i32, -2147483648), try (try map.get("negative")).integer(i32));
    try testing.expectError(error.InvalidValue, (try map.get("negative")).integer(u64));
    try testing.expectError(error.InvalidValue, (try map.get("zeros")).integer(i32));
    try testing.expectError(error.InvalidValue, (try map.get("quoted")).integer(i32));
    try testing.expectError(error.InvalidValue, (try map.get("underscore")).integer(i32));
    try testing.expectError(error.InvalidValue, (try map.get("yes")).boolean());
    try testing.expect(try (try map.get("upper")).boolean());
    try testing.expectEqual(@as(?i32, null), try map.optional_integer("tilde", i32));
    try testing.expectEqual(@as(?i32, null), try map.optional_integer("absent", i32));
    try testing.expect(!(try map.get("null_quoted")).is_null());
    try testing.expectError(error.InvalidValue, map.optional_integer("null_quoted", i32));
}

test "the emitter lays out nested blocks as serde_yaml does" {
    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    var e: yaml.Emitter = .{ .writer = &writer };
    try e.string_field("tag", "007");
    try e.begin_map("monitoring");
    try e.int_field("storage_size", @as(i32, -1));
    try e.bool_field("on", true);
    e.end();
    try e.begin_list("instances", 2);
    e.begin_item();
    try e.string_field("name", "a");
    try e.begin_list("regions", 1);
    try e.string_item("us-east-1");
    e.end();
    e.end();
    e.begin_item();
    try e.string_field("name", "b");
    try e.begin_list("empty", 0);
    e.end();
    e.end();
    e.end();
    try testing.expectEqualStrings(
        \\tag: '007'
        \\monitoring:
        \\  storage_size: -1
        \\  on: true
        \\instances:
        \\- name: a
        \\  regions:
        \\  - us-east-1
        \\- name: b
        \\  empty: []
        \\
    , writer.buffered());
}

// --- Fuzz --------------------------------------------------------------------------------------

/// Pieces random strings are built from: indicators, number and keyword fragments, quotes,
/// escapes, whitespace, and multi-byte and unprintable characters.
const pieces = [_][]const u8{
    "a",
    "0",
    "1",
    "x",
    ".",
    "-",
    "+",
    ":",
    "#",
    " ",
    "'",
    "\"",
    "\\",
    "\t",
    "e",
    "~",
    "[",
    "]",
    "{",
    ",",
    "?",
    "&",
    "!",
    "|",
    ">",
    "%",
    "@",
    "`",
    "0x",
    "0o",
    "0b",
    "inf",
    ".nan",
    "nu",
    "ll",
    "tr",
    "ue",
    "ü",
    "\x00",
    "\x7f",
    "\u{85}",
    "\u{feff}",
    "\u{1F600}",
    "_",
};

fn random_string(random: *utils.rng.FuzzRng, buffer: []u8) []const u8 {
    const count = utils.rng.range_at_most(random, usize, 0, 8);
    var len: usize = 0;
    for (0..count) |_| {
        const piece = pieces[utils.rng.range_less_than(random, usize, 0, pieces.len)];
        if (len + piece.len > buffer.len) break;
        @memcpy(buffer[len..][0..piece.len], piece);
        len += piece.len;
    }
    assert(len <= buffer.len);
    return buffer[0..len];
}

fn round_trip(_: void, random: *utils.rng.FuzzRng) anyerror!void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var key_buffer: [48]u8 = undefined;
    var value_buffer: [48]u8 = undefined;
    var item_buffer: [48]u8 = undefined;
    const key_raw = random_string(random, &key_buffer);
    const key = if (key_raw.len == 0) "k" else key_raw;
    const value = random_string(random, &value_buffer);
    const item = random_string(random, &item_buffer);
    const style = yaml.style_of(value) catch |err| {
        // Only line breaks are refused, and the pieces hold one: NEL.
        try testing.expectEqual(error.InvalidValue, err);
        try testing.expect(std.mem.indexOf(u8, value, "\u{85}") != null);
        return;
    };
    if (yaml.style_of(key) catch null == null) return;
    if (yaml.style_of(item) catch null == null) return;

    var output: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&output);
    var e: yaml.Emitter = .{ .writer = &writer };
    try e.string_field(key, value);
    try e.begin_list("list", 1);
    try e.string_item(item);
    e.end();

    const map = try parse(arena.allocator(), writer.buffered());
    try testing.expectEqual(@as(usize, 2), map.entries.len);
    const node = try map.get(key);
    try testing.expectEqualStrings(value, try node.string());
    try testing.expectEqualStrings(item, try (try (try map.get("list")).as_list())[0].string());
    try testing.expectEqual(style, node.scalar.style);
    // A string written plain never reads back as another type.
    if (style == .plain) {
        try testing.expect(!node.is_null());
        try testing.expectError(error.InvalidValue, node.boolean());
        try testing.expectError(error.InvalidValue, node.integer(i64));
        try testing.expectError(error.InvalidValue, node.integer(u64));
    }
}

test "fuzz: written strings read back unchanged" {
    try utils.fuzz.run({}, round_trip, 0x7961_6d6c, 2_000);
}

fn parse_any(_: void, random: *utils.rng.FuzzRng) anyerror!void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const lines = [_][]const u8{
        "a: b", "  c: 1",       "- d",   "  - e", "-",   "f:", "  - g: h", "    i: 'j''k'", "# x",
        "",     "l: \"m\\tn\"", "o: []", "p: {}", "---", "q",  "    r: s", "t: u # v",
    };
    var text: [512]u8 = undefined;
    var len: usize = 0;
    const count = utils.rng.range_at_most(random, usize, 0, 12);
    for (0..count) |_| {
        const line = lines[utils.rng.range_less_than(random, usize, 0, lines.len)];
        if (len + line.len + 1 > text.len) break;
        @memcpy(text[len..][0..line.len], line);
        text[len + line.len] = '\n';
        len += line.len + 1;
    }
    // Any input either parses or is refused with an error; it never crashes or loops.
    const document = yaml.Document.parse(arena.allocator(), text[0..len]) catch |err| {
        try testing.expect(err == error.InvalidYaml);
        return;
    };
    _ = document.root;
}

test "fuzz: arbitrary line sequences parse or fail cleanly" {
    try utils.fuzz.run({}, parse_any, 0x7061_7273, 2_000);
}
