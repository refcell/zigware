//! Tests for the EC2 Query protocol body writer and XML response scanner.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const query = @import("query.zig");

const capacity_error =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<Response><Errors><Error><Code>InsufficientInstanceCapacity</Code><Message>capacity unavailable</Message></Error></Errors><RequestID>request-id</RequestID></Response>
;

test "query: bodies percent-encode names and values" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var body = try query.Body.init(arena_state.allocator(), "RunInstances", query.ec2_version);
    try body.add("BlockDeviceMapping.1.DeviceName", "/dev/sda1");
    try body.add_int("MinCount", -1);
    try body.add("TagSpecification.1.Tag.1.Value", "a b+c~");
    try testing.expectEqualStrings(
        "Action=RunInstances&Version=2016-11-15" ++
            "&BlockDeviceMapping.1.DeviceName=%2Fdev%2Fsda1&MinCount=-1" ++
            "&TagSpecification.1.Tag.1.Value=a%20b%2Bc~",
        body.written(),
    );
}

test "query: service errors read code and message" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const parsed = try query.service_error(arena_state.allocator(), capacity_error);
    try testing.expectEqualStrings("InsufficientInstanceCapacity", parsed.code.?);
    try testing.expectEqualStrings("capacity unavailable", parsed.message.?);
    const empty = try query.service_error(arena_state.allocator(), "<Response/>");
    try testing.expectEqual(@as(?[]const u8, null), empty.code);
}

fn collect(list: *std.ArrayList([]const u8), text: []const u8) bool {
    list.appendBounded(text) catch return false;
    return true;
}

test "query: scan matches whole paths only" {
    const xml =
        \\<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
        \\  <!-- a <comment> -->
        \\  <instancesSet>
        \\    <item><instanceId>i-1</instanceId><groupSet><item><instanceId>no</instanceId>
        \\    </item></groupSet></item>
        \\    <item><instanceId>i-2</instanceId><empty/></item>
        \\  </instancesSet>
        \\  <instanceId>no</instanceId>
        \\</RunInstancesResponse>
    ;
    var buffer: [4][]const u8 = undefined;
    var list: std.ArrayList([]const u8) = .initBuffer(&buffer);
    const path = [_][]const u8{ "RunInstancesResponse", "instancesSet", "item", "instanceId" };
    try query.scan(xml, &path, &list, collect);
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expectEqualStrings("i-1", list.items[0]);
    try testing.expectEqualStrings("i-2", list.items[1]);
}

test "query: malformed documents are rejected" {
    const path = [_][]const u8{ "a", "b" };
    for ([_][]const u8{ "<a><b>x</a>", "<a><b>x</b>", "</a>", "<a", "<>", "<a><b>x" }) |xml| {
        try testing.expectError(error.MalformedXml, query.first_text(xml, &path));
    }
    try testing.expectEqualStrings("x", (try query.first_text("<a><b >x</b ></a>", &path)).?);
}

test "query: entities decode" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqualStrings(
        "<a> & \"b\" 'c' \t é 😀",
        try query.decode_text(
            arena,
            "&lt;a&gt; &amp; &quot;b&quot; &apos;c&apos; &#9; &#xE9; &#128512;",
        ),
    );
    try testing.expectError(error.MalformedXml, query.decode_text(arena, "&bogus;"));
    try testing.expectError(error.MalformedXml, query.decode_text(arena, "&#xD800;"));
    try testing.expectError(error.MalformedXml, query.decode_text(arena, "&amp"));
}

fn count(total: *usize, _: []const u8) bool {
    total.* += 1;
    return true;
}

fn scan_any(_: void, random: *utils.rng.FuzzRng) anyerror!void {
    const pieces = [_][]const u8{
        "<a>",         "</a>",     "<b>",        "</b>",  "<b/>", "x", "&amp;",
        "&#x41;",      "&",        "<!-- c -->", "<?x?>", "<",    ">", "</ b>",
        "<a k=\"v\">", "&#xD800;",
    };
    var buffer: [256]u8 = undefined;
    var length: usize = 0;
    const pieces_count = utils.rng.range_at_most(random, usize, 0, 16);
    for (0..pieces_count) |_| {
        const piece = pieces[utils.rng.range_less_than(random, usize, 0, pieces.len)];
        @memcpy(buffer[length..][0..piece.len], piece);
        length += piece.len;
    }
    const xml = buffer[0..length];
    var total: usize = 0;
    query.scan(xml, &.{ "a", "b" }, &total, count) catch |err| {
        try testing.expectEqual(error.MalformedXml, err);
        return;
    };
    try testing.expect(total <= pieces_count);
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const decoded = query.decode_text(arena_state.allocator(), xml) catch return;
    try testing.expect(decoded.len <= xml.len);
}

test "query: fuzz scan and decode never panic" {
    try utils.fuzz.run({}, scan_any, 0x786d_6c21, 4_000);
}

test "query: elements and texts read nested items" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const xml =
        \\<R><set><item><id>a&amp;1</id><tags><item><id>no</id></item></tags></item>
        \\<item><id>b</id></item><item/></set></R>
    ;
    const items = try query.elements(arena, xml, &.{ "R", "set", "item" });
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expectEqualStrings("a&amp;1", (try query.first_text(items[0], &.{"id"})).?);
    try testing.expectEqualStrings("a&1", (try query.decoded_text(arena, items[0], &.{"id"})).?);
    try testing.expectEqualStrings("", items[2]);
    const ids = try query.texts(arena, xml, &.{ "R", "set", "item", "id" });
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("a&1", ids[0]);
    try testing.expectEqualStrings("b", ids[1]);
    const bad = query.texts(arena, "<R><x>&bad;</x></R>", &.{ "R", "x" });
    try testing.expectError(error.MalformedXml, bad);
}
