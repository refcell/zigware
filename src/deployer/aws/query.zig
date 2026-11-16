//! The AWS Query protocol EC2 speaks: `application/x-www-form-urlencoded` request bodies
//! (`Action=RunInstances&Version=2016-11-15&...`, list members numbered from 1) and XML
//! responses, read with a small bounded scanner that finds elements by their path from the root.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const sigv4 = @import("sigv4.zig");

/// The EC2 API version every request names.
pub const ec2_version = "2016-11-15";
pub const content_type = "application/x-www-form-urlencoded; charset=utf-8";

/// A Query request body under construction.
pub const Body = struct {
    out: Io.Writer.Allocating,

    pub fn init(arena: Allocator, action: []const u8, version: []const u8) !Body {
        assert(action.len > 0);
        assert(version.len > 0);
        var body: Body = .{ .out = .init(arena) };
        try body.out.writer.writeAll("Action=");
        try sigv4.write_uri_encoded(&body.out.writer, action, false);
        try body.out.writer.writeAll("&Version=");
        try sigv4.write_uri_encoded(&body.out.writer, version, false);
        return body;
    }

    /// Appends `&name=value`, percent-encoding both as the SDK's query writer does.
    pub fn add(body: *Body, name: []const u8, value: []const u8) !void {
        assert(name.len > 0);
        const before = body.out.written().len;
        try body.out.writer.writeByte('&');
        try sigv4.write_uri_encoded(&body.out.writer, name, false);
        try body.out.writer.writeByte('=');
        try sigv4.write_uri_encoded(&body.out.writer, value, false);
        assert(body.out.written().len > before + name.len);
    }

    pub fn add_int(body: *Body, name: []const u8, value: i64) !void {
        var buffer: [24]u8 = undefined;
        // Proof: every i64 prints in at most 20 bytes.
        const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable;
        try body.add(name, text);
    }

    pub fn written(body: *Body) []const u8 {
        return body.out.written();
    }
};

/// Element nesting deeper than this is malformed for every EC2 response.
pub const depth_max = 32;

pub const ScanError = error{MalformedXml};

/// The text of each element whose path from the root is `path`, in document order, passed to
/// `visit` still entity-encoded, until `visit` returns false. The whole document is checked for
/// well-formed nesting either way.
pub fn scan(
    xml: []const u8,
    path: []const []const u8,
    context: anytype,
    comptime visit: fn (@TypeOf(context), []const u8) bool,
) ScanError!void {
    assert(path.len > 0 and path.len <= depth_max);
    var stack: [depth_max][]const u8 = undefined;
    var depth: usize = 0;
    var index: usize = 0;
    var visiting = true;
    while (std.mem.indexOfScalarPos(u8, xml, index, '<')) |open| {
        assert(depth <= depth_max);
        const close = std.mem.indexOfScalarPos(u8, xml, open, '>') orelse return error.MalformedXml;
        const tag = xml[open + 1 .. close];
        index = close + 1;
        if (tag.len == 0) return error.MalformedXml;
        switch (tag[0]) {
            // Declarations, processing instructions, and comments carry no elements.
            '?', '!' => if (std.mem.startsWith(u8, tag, "!--")) {
                const end = std.mem.indexOfPos(u8, xml, open, "-->") orelse
                    return error.MalformedXml;
                index = end + 3;
            },
            '/' => {
                if (depth == 0) return error.MalformedXml;
                depth -= 1;
                if (!std.mem.eql(u8, std.mem.trimEnd(u8, tag[1..], " \t\r\n"), stack[depth])) {
                    return error.MalformedXml;
                }
            },
            else => {
                const self_closing = tag[tag.len - 1] == '/';
                const name_end = std.mem.indexOfAny(u8, tag, " \t\r\n/") orelse tag.len;
                if (name_end == 0) return error.MalformedXml;
                if (depth == depth_max) return error.MalformedXml;
                stack[depth] = tag[0..name_end];
                const matches = visiting and depth + 1 == path.len and
                    matches_path(stack[0 .. depth + 1], path);
                if (self_closing) {
                    if (matches) visiting = visit(context, "");
                    continue;
                }
                depth += 1;
                if (matches) {
                    const end = std.mem.indexOfScalarPos(u8, xml, index, '<') orelse
                        return error.MalformedXml;
                    visiting = visit(context, xml[index..end]);
                }
            },
        }
    }
    if (depth != 0) return error.MalformedXml;
}

fn matches_path(stack: []const []const u8, path: []const []const u8) bool {
    assert(stack.len == path.len);
    assert(stack.len > 0);
    for (stack, path) |name, wanted| {
        if (!std.mem.eql(u8, name, wanted)) return false;
    }
    return true;
}

/// The (still entity-encoded) text of the first element at `path`, or null.
pub fn first_text(xml: []const u8, path: []const []const u8) ScanError!?[]const u8 {
    var found: ?[]const u8 = null;
    try scan(xml, path, &found, struct {
        fn visit(slot: *?[]const u8, text: []const u8) bool {
            slot.* = text;
            return false;
        }
    }.visit);
    return found;
}

/// Decodes the five predefined entities and numeric character references (allocates from
/// `arena` only when `text` holds an entity).
pub fn decode_text(arena: Allocator, text: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, text, '&') == null) return text;
    var out: std.ArrayList(u8) = try .initCapacity(arena, text.len);
    var index: usize = 0;
    while (index < text.len) {
        assert(out.items.len <= text.len);
        if (text[index] != '&') {
            out.appendAssumeCapacity(text[index]);
            index += 1;
            continue;
        }
        const end = std.mem.indexOfScalarPos(u8, text, index, ';') orelse return error.MalformedXml;
        const entity = text[index + 1 .. end];
        index = end + 1;
        if (entity_byte(entity)) |byte| {
            out.appendAssumeCapacity(byte);
            continue;
        }
        if (entity.len < 2 or entity[0] != '#') return error.MalformedXml;
        const hex = entity[1] == 'x';
        const digits = if (hex) entity[2..] else entity[1..];
        const code = std.fmt.parseInt(u21, digits, if (hex) 16 else 10) catch
            return error.MalformedXml;
        var buffer: [4]u8 = undefined;
        const count = std.unicode.utf8Encode(code, &buffer) catch return error.MalformedXml;
        // Proof: a reference is at least four bytes (`&#N;`) and encodes to at most four.
        out.appendSliceAssumeCapacity(buffer[0..count]);
    }
    return out.items;
}

fn entity_byte(entity: []const u8) ?u8 {
    const names = [_]struct { []const u8, u8 }{
        .{ "lt", '<' }, .{ "gt", '>' }, .{ "amp", '&' }, .{ "quot", '"' }, .{ "apos", '\'' },
    };
    for (names) |entry| if (std.mem.eql(u8, entity, entry[0])) return entry[1];
    return null;
}

/// The code and message of an EC2 error response (`<Response><Errors><Error>`).
pub const ServiceError = struct { code: ?[]const u8, message: ?[]const u8 };

pub fn service_error(arena: Allocator, xml: []const u8) !ServiceError {
    const prefix = [_][]const u8{ "Response", "Errors", "Error" };
    const code = try first_text(xml, &(prefix ++ .{"Code"}));
    const message = try first_text(xml, &(prefix ++ .{"Message"}));
    return .{
        .code = if (code) |text| try decode_text(arena, text) else null,
        .message = if (message) |text| try decode_text(arena, text) else null,
    };
}

/// Writes `text` with `&`, `<`, `>`, `"`, and `'` as entities.
pub fn write_escaped(writer: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    for (text) |byte| switch (byte) {
        '&' => try writer.writeAll("&amp;"),
        '<' => try writer.writeAll("&lt;"),
        '>' => try writer.writeAll("&gt;"),
        '"' => try writer.writeAll("&quot;"),
        '\'' => try writer.writeAll("&apos;"),
        else => try writer.writeByte(byte),
    };
}

/// The code and message of a REST-XML (S3) error response (`<Error>`).
pub fn rest_error(arena: Allocator, xml: []const u8) !ServiceError {
    const code = try first_text(xml, &.{ "Error", "Code" });
    const message = try first_text(xml, &.{ "Error", "Message" });
    return .{
        .code = if (code) |text| try decode_text(arena, text) else null,
        .message = if (message) |text| try decode_text(arena, text) else null,
    };
}

test {
    _ = @import("query_test.zig");
}
