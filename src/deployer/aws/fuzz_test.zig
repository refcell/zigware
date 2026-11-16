//! Seeded fuzz targets for SigV4 canonicalization and configuration handling, each checked
//! against an independent oracle written here rather than against the code under test.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const utils = @import("utils");
const aws = @import("mod.zig");
const create = @import("create.zig");
const sigv4 = @import("sigv4.zig");

const FuzzRng = utils.rng.FuzzRng;

/// Bytes that stress encoding: unreserved, reserved, space, `/`, `%`, and UTF-8.
const alphabet = "aZ09-_.~ +=&/%?!*'()é\x00\xff";

fn draw_text(random: *FuzzRng, buffer: []u8) []const u8 {
    const len = utils.rng.range_at_most(random, usize, 0, buffer.len);
    for (buffer[0..len]) |*byte| {
        byte.* = alphabet[utils.rng.range_less_than(random, usize, 0, alphabet.len)];
    }
    return buffer[0..len];
}

fn is_unreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "-_.~", byte) != null;
}

/// Decodes RFC 3986 percent-encoding as SigV4 requires it: only unreserved bytes (and `/`
/// when kept) appear raw, and escapes use uppercase hex.
fn decode(out: []u8, encoded: []const u8, keep_slash: bool) ![]const u8 {
    var len: usize = 0;
    var index: usize = 0;
    while (index < encoded.len) : (len += 1) {
        const byte = encoded[index];
        if (byte == '%') {
            try testing.expect(index + 3 <= encoded.len);
            const hex = encoded[index + 1 ..][0..2];
            for (hex) |digit| try testing.expect(std.ascii.isDigit(digit) or
                (digit >= 'A' and digit <= 'F'));
            out[len] = try std.fmt.parseInt(u8, hex, 16);
            // Unreserved bytes (and a kept `/`) must not be escaped.
            try testing.expect(!is_unreserved(out[len]) and !(keep_slash and out[len] == '/'));
            index += 3;
        } else {
            try testing.expect(is_unreserved(byte) or (keep_slash and byte == '/'));
            out[len] = byte;
            index += 1;
        }
    }
    return out[0..len];
}

fn uri_round_trip(_: void, random: *FuzzRng) anyerror!void {
    var text_buffer: [24]u8 = undefined;
    const text = draw_text(random, &text_buffer);
    const keep_slash = utils.rng.boolean(random);
    var encoded_buffer: [24 * 3]u8 = undefined;
    var writer: Io.Writer = .fixed(&encoded_buffer);
    try sigv4.write_uri_encoded(&writer, text, keep_slash);
    var decoded_buffer: [24]u8 = undefined;
    const decoded = try decode(&decoded_buffer, writer.buffered(), keep_slash);
    try testing.expectEqualSlices(u8, text, decoded);
}

test "fuzz: SigV4 URI encoding decodes back and leaves only unreserved bytes raw" {
    try utils.fuzz.run({}, uri_round_trip, 0x7572_6921, 4_000);
}

const pairs_max = 6;

fn draw_pairs(
    random: *FuzzRng,
    texts: *[pairs_max * 2][8]u8,
    pairs: *[pairs_max]sigv4.Pair,
) []sigv4.Pair {
    const count = utils.rng.range_at_most(random, usize, 0, pairs_max);
    for (pairs[0..count], 0..) |*pair, index| {
        pair.* = .{
            .name = draw_text(random, &texts[index * 2]),
            .value = draw_text(random, &texts[index * 2 + 1]),
        };
    }
    return pairs[0..count];
}

fn canonical_query(arena: std.mem.Allocator, pairs: []const sigv4.Pair) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try sigv4.write_canonical_query(arena, &out.writer, pairs);
    return out.written();
}

fn query_properties(_: void, random: *FuzzRng) anyerror!void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var texts: [pairs_max * 2][8]u8 = undefined;
    var storage: [pairs_max]sigv4.Pair = undefined;
    const pairs = draw_pairs(random, &texts, &storage);
    const query = try canonical_query(arena, pairs);
    if (pairs.len == 0) return testing.expectEqualStrings("", query);
    // One `name=value` per pair, sorted by encoded name then value, each decoding to an input.
    var used: [pairs_max]bool = @splat(false);
    var previous: ?[2][]const u8 = null;
    var parts = std.mem.splitScalar(u8, query, '&');
    var count: usize = 0;
    while (parts.next()) |part| : (count += 1) {
        const equals = std.mem.indexOfScalar(u8, part, '=').?;
        const name = part[0..equals];
        const value = part[equals + 1 ..];
        try testing.expect(std.mem.indexOfScalar(u8, value, '=') == null);
        if (previous) |last| {
            const order = std.mem.order(u8, last[0], name);
            try testing.expect(order == .lt or
                (order == .eq and std.mem.order(u8, last[1], value) != .gt));
        }
        previous = .{ name, value };
        var name_buffer: [8]u8 = undefined;
        var value_buffer: [8]u8 = undefined;
        const raw_name = try decode(&name_buffer, name, false);
        const raw_value = try decode(&value_buffer, value, false);
        const match = for (pairs, used[0..pairs.len]) |pair, *taken| {
            if (taken.*) continue;
            if (std.mem.eql(u8, pair.name, raw_name) and std.mem.eql(u8, pair.value, raw_value)) {
                taken.* = true;
                break true;
            }
        } else false;
        try testing.expect(match);
    }
    try testing.expectEqual(pairs.len, count);
    // The input order does not matter.
    std.mem.reverse(sigv4.Pair, pairs);
    try testing.expectEqualStrings(query, try canonical_query(arena, pairs));
}

test "fuzz: SigV4 canonical queries are sorted, complete, and order-independent" {
    try utils.fuzz.run({}, query_properties, 0x7175_6572, 4_000);
}

fn signature_properties(_: void, random: *FuzzRng) anyerror!void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var texts: [pairs_max * 2][8]u8 = undefined;
    var storage: [pairs_max]sigv4.Pair = undefined;
    const query = draw_pairs(random, &texts, &storage);
    // Distinct header names in mixed case, with values of words and runs of spaces.
    const names = [_][]const u8{ "X-Amz-Meta-A", "content-type", "X-Custom", "range" };
    var headers: [names.len]sigv4.Pair = undefined;
    var value_buffers: [names.len][12]u8 = undefined;
    const header_count = utils.rng.range_at_most(random, usize, 0, names.len);
    const buffers = value_buffers[0..header_count];
    for (headers[0..header_count], names[0..header_count], buffers) |*header, name, *buffer| {
        const len = utils.rng.range_at_most(random, usize, 1, buffer.len);
        for (buffer[0..len]) |*byte| {
            byte.* = "ab  1"[utils.rng.range_less_than(random, usize, 0, 5)];
        }
        header.* = .{ .name = name, .value = buffer[0..len] };
    }
    var request: sigv4.Request = .{
        .method = if (utils.rng.boolean(random)) "GET" else "POST",
        .host = "ec2.us-east-1.amazonaws.com",
        .path = "/",
        .query = query,
        .headers = headers[0..header_count],
        .payload_hash = "UNSIGNED-PAYLOAD",
    };
    const credentials: sigv4.Credentials = .{
        .access_key_id = "id",
        .secret_access_key = "secret",
    };
    const scope: sigv4.Scope = .{
        .region = "us-east-1",
        .service = "ec2",
        .time_s = 1_440_938_160,
    };
    const first = try sigv4.sign(arena, &request, credentials, scope);
    std.mem.reverse(sigv4.Pair, query);
    std.mem.reverse(sigv4.Pair, headers[0..header_count]);
    const reordered = try sigv4.sign(arena, &request, credentials, scope);
    try testing.expectEqualStrings(first.authorization, reordered.authorization);
    // Any change to a signed value changes the signature.
    if (header_count == 0) return;
    const changed = try std.fmt.allocPrint(arena, "{s}x", .{headers[0].value});
    headers[0].value = changed;
    const altered = try sigv4.sign(arena, &request, credentials, scope);
    try testing.expect(!std.mem.eql(u8, first.authorization, altered.authorization));
}

test "fuzz: SigV4 signatures ignore header and query order but not their values" {
    try utils.fuzz.run({}, signature_properties, 0x7369_6776, 2_000);
}

// --- Configuration -----------------------------------------------------------------------------

const name_choices = [_][]const u8{
    "a", "A", "node-0", "node_1", "monitoring", "Monitoring", "", "bad name", "x.y",
};
const classes = [_][]const u8{ "gp3", "io2", "gp2", "bogus" };

/// The failure `validate_names` must report, derived from the rules directly.
fn expected_name_failure(config: *const aws.Config) ?struct { kind: []const u8, name: []const u8 } {
    const valid = struct {
        fn f(name: []const u8) bool {
            if (name.len == 0) return false;
            for (name) |byte| {
                const ok = (byte >= 'a' and byte <= 'z') or (byte >= 'A' and byte <= 'Z') or
                    (byte >= '0' and byte <= '9') or byte == '-' or byte == '_';
                if (!ok) return false;
            }
            return true;
        }
    }.f;
    if (!valid(config.tag)) return .{ .kind = "invalid_tag", .name = config.tag };
    for (config.instances, 0..) |instance, index| {
        if (!valid(instance.name) or std.mem.eql(u8, instance.name, "monitoring")) {
            return .{ .kind = "invalid_instance_name", .name = instance.name };
        }
        for (config.instances[0..index]) |earlier| {
            if (std.ascii.eqlIgnoreCase(earlier.name, instance.name)) {
                return .{ .kind = "duplicate_instance_name", .name = instance.name };
            }
        }
    }
    return null;
}

fn draw_config(random: *FuzzRng, instances: []aws.InstanceConfig) aws.Config {
    const pick = struct {
        fn f(r: *FuzzRng, choices: []const []const u8) []const u8 {
            return choices[utils.rng.range_less_than(r, usize, 0, choices.len)];
        }
    }.f;
    const count = utils.rng.range_at_most(random, usize, 0, instances.len);
    for (instances[0..count]) |*instance| {
        const iops_drawn: i32 = @intCast(utils.rng.range_at_most(random, u32, 0, 70_000));
        const iops: ?i32 = if (utils.rng.boolean(random)) iops_drawn else null;
        instance.* = .{
            .name = pick(random, &name_choices),
            .region = pick(random, &.{ "us-east-1", "eu-west-1" }),
            .instance_type = "c7g.medium",
            .storage_size = @intCast(utils.rng.range_at_most(random, u32, 1, 20_000)),
            .storage_class = pick(random, &classes),
            .storage_iops = iops,
            .binary = "bin",
            .config = "conf",
            .profiling = utils.rng.boolean(random),
        };
    }
    return .{
        .tag = pick(random, &name_choices),
        .monitoring = .{
            .instance_type = "c7g.medium",
            .storage_size = 10,
            .storage_class = pick(random, &classes),
            .dashboard = "dashboard.json",
        },
        .instances = instances[0..count],
        .ports = &.{},
    };
}

fn config_properties(_: void, random: *FuzzRng) anyerror!void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var instances: [4]aws.InstanceConfig = undefined;
    const config = draw_config(random, &instances);
    // Written configurations read back field for field.
    var out: Io.Writer.Allocating = .init(arena);
    try config.write(&out.writer);
    const parsed = try aws.Config.parse(arena, out.written());
    try testing.expectEqualStrings(config.tag, parsed.tag);
    const class = parsed.monitoring.storage_class;
    try testing.expectEqualStrings(config.monitoring.storage_class, class);
    try testing.expectEqual(config.instances.len, parsed.instances.len);
    for (config.instances, parsed.instances) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.region, got.region);
        try testing.expectEqualStrings(want.storage_class, got.storage_class);
        try testing.expectEqual(want.storage_size, got.storage_size);
        try testing.expectEqual(want.storage_iops, got.storage_iops);
        try testing.expectEqual(want.profiling, got.profiling);
    }
    // Name validation reports the first rule broken, in commonware's order.
    const expected = expected_name_failure(&parsed);
    const failure = create.validate_names(&parsed);
    if (expected) |want| {
        const got = failure orelse return error.TestExpectedFailure;
        try testing.expectEqualStrings(want.kind, @tagName(got));
        const name = switch (got) {
            .invalid_tag, .invalid_instance_name, .duplicate_instance_name => |name| name,
            else => unreachable,
        };
        try testing.expectEqualStrings(want.name, name);
    } else try testing.expect(failure == null);
    // Storage validation never crashes; an unknown class is always refused.
    const storage = create.validate_storage_config(&parsed);
    if (std.mem.eql(u8, class, "bogus")) try testing.expect(storage != null);
}

test "fuzz: configurations round-trip through YAML and validate names by the rules" {
    try utils.fuzz.run({}, config_properties, 0x636f_6e66, 2_000);
}
