//! Tests of the tracker, ported from commonware's `bench/src/bin/tests.rs` with its fixtures,
//! plus tests of the TOML subset.

const std = @import("std");
const testing = std.testing;
const toml = @import("toml.zig");
const config = @import("config.zig");

const Diagnostic = toml.Diagnostic;

/// commonware's `.github/benchmark-tracking.toml`.
pub const config_fixture = @embedFile("testdata/benchmark-tracking.toml");

fn expect_invalid(input: []const u8, needle: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    const result = config.load_config(arena.allocator(), input, &diagnostic);
    try testing.expectError(error.Invalid, result);
    if (std.mem.indexOf(u8, diagnostic.message(), needle) == null) {
        std.debug.print("message `{s}` lacks `{s}`\n", .{ diagnostic.message(), needle });
        return error.TestUnexpectedResult;
    }
}

test "toml parses tables, arrays of tables, inline values, and comments" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    const input =
        \\# comment
        \\top = 1_000 # trailing
        \\"quoted key" = 'lit\eral'
        \\list = [
        \\  1, 2.5, -inf,
        \\  "a\"b\u00e9",
        \\]
        \\inline = { a = true, b = [ { c = 3 } ] }
        \\[[items]]
        \\name = "first"
        \\[items.sub]
        \\x = 1
        \\[[items]]
        \\name = "second"
        \\[plain]
        \\dotted.key = false
    ;
    const root = try toml.parse(arena.allocator(), input, &diagnostic);
    try testing.expectEqual(@as(i64, 1000), root.get("top").?.integer);
    try testing.expectEqualStrings("lit\\eral", root.get("quoted key").?.string);
    const list = root.get("list").?.array.items.items;
    try testing.expectEqual(@as(usize, 4), list.len);
    try testing.expectEqual(@as(f64, 2.5), list[1].float);
    try testing.expect(std.math.isNegativeInf(list[2].float));
    try testing.expectEqualStrings("a\"b\xc3\xa9", list[3].string);
    const inline_table = root.get("inline").?.table;
    try testing.expect(inline_table.get("a").?.boolean);
    const inner = inline_table.get("b").?.array.items.items[0].table;
    try testing.expectEqual(@as(i64, 3), inner.get("c").?.integer);
    const items = root.get("items").?.array.items.items;
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("first", items[0].table.get("name").?.string);
    try testing.expectEqual(@as(i64, 1), items[0].table.get("sub").?.table.get("x").?.integer);
    try testing.expectEqualStrings("second", items[1].table.get("name").?.string);
    const plain = root.get("plain").?.table;
    try testing.expect(!plain.get("dotted").?.table.get("key").?.boolean);
}

/// `a = ` and `depth` nested empty arrays.
fn nested(comptime depth: usize) []const u8 {
    const open: [depth]u8 = @splat('[');
    const close: [depth]u8 = @splat(']');
    return "a = " ++ open ++ close;
}

test "toml rejects duplicates, bad values, and runaway nesting" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cases = [_][]const u8{
        "a = 1\na = 2",
        "a = ",
        "a = \"open",
        "a = 1 b = 2",
        "a = [1 2]",
        "a = { b = 1, b = 2 }",
        "[a]\nb = 1\n[[a]]",
        "a = 0x",
        nested(toml.depth_max + 1),
    };
    for (cases) |input| {
        var diagnostic: Diagnostic = .{};
        try testing.expectError(error.Invalid, toml.parse(arena.allocator(), input, &diagnostic));
        try testing.expect(diagnostic.message().len > 0);
    }
    var diagnostic: Diagnostic = .{};
    _ = try toml.parse(arena.allocator(), nested(toml.depth_max), &diagnostic);
}

test "toml writes strings and floats it reads back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.writeAll("s = ");
    try toml.write_string(&writer, "q\"\\\n\x01");
    try writer.writeAll("\nf = ");
    try toml.write_float(&writer, 10.0);
    try writer.writeAll("\ng = ");
    try toml.write_float(&writer, -0.125);
    try writer.writeAll("\nh = ");
    try toml.write_float(&writer, std.math.inf(f64));
    try writer.writeAll("\n");
    try toml.write_key(&writer, "needs quoting");
    try writer.writeAll(" = 1\n");
    try testing.expectEqualStrings(
        "s = \"q\\\"\\\\\\n\\u0001\"\nf = 10.0\ng = -0.125\nh = inf\n\"needs quoting\" = 1\n",
        writer.buffered(),
    );
    var diagnostic: Diagnostic = .{};
    const root = try toml.parse(arena.allocator(), writer.buffered(), &diagnostic);
    try testing.expectEqualStrings("q\"\\\n\x01", root.get("s").?.string);
    try testing.expectEqual(@as(f64, 10.0), root.get("f").?.float);
    try testing.expectEqual(@as(f64, -0.125), root.get("g").?.float);
    try testing.expect(std.math.isPositiveInf(root.get("h").?.float));
}

test "loads commonware's tracking config with inherited gates" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    const benchmarks = try config.load_config(arena.allocator(), config_fixture, &diagnostic);
    try testing.expectEqual(@as(usize, 2), benchmarks.len);
    const first = benchmarks[0];
    try testing.expectEqualStrings("commonware-storage", first.package);
    try testing.expectEqualStrings("commonware-storage", first.baseline_suite);
    try testing.expectEqualStrings("qmdb_gungraun", first.target);
    try testing.expectEqualStrings(
        "qmdb::merkleize/v=any::unordered::fixed::mmr k=10000 ch=false s=true cc=true",
        first.name,
    );
    try testing.expectEqualStrings("*::bench_merkleize::any_unordered_fixed_mmr", first.filter);
    try testing.expectEqual(@as(usize, 2), first.cargo_flags.len);
    try testing.expectEqualStrings("--features", first.cargo_flags[0]);
    try testing.expectEqual(@as(usize, 2), first.gates.len);
    try testing.expectEqualStrings("blob_reads", first.gates[1].metric);
    try testing.expectEqual(config.Direction.down, first.gates[1].direction);
    const labels = try config.tracked_labels(arena.allocator(), benchmarks);
    try testing.expectEqual(@as(usize, 7), labels.len);
    try testing.expectEqualStrings("blob_reads", labels[6]);
}

test "gates default, describe themselves, and fail past their tolerance" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    const input =
        \\[[packages]]
        \\name = "p"
        \\[[packages.benchmarks]]
        \\name = "t"
        \\[[packages.benchmarks.variants]]
        \\name = "v"
        \\filter = "*"
        \\[[packages.benchmarks.variants]]
        \\name = "w"
        \\filter = "*"
        \\gates = [{ metric = "x", direction = "up", threshold_percent = 5 }]
    ;
    const benchmarks = try config.load_config(arena.allocator(), input, &diagnostic);
    try testing.expectEqualStrings("EstimatedCycles", benchmarks[0].gates[0].metric);
    const up = benchmarks[1].gates[0];
    try testing.expectEqual(@as(f64, 5), up.threshold_percent);
    try testing.expect(up.failed(-5.01) and !up.failed(-5) and !up.failed(100));
    try testing.expect(config.Gate.default.failed(10.01) and !config.Gate.default.failed(10));
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try config.Gate.default.write_description(&writer);
    try testing.expectEqualStrings(
        "EstimatedCycles should decrease; tolerance 10.00%",
        writer.buffered(),
    );
    const duplicate = "\n[[packages.benchmarks.variants]]\nname = \"v\"\nfilter = \"x\"";
    try expect_invalid(input ++ duplicate, "duplicate benchmark `v`");
}

test "rejects invalid config fields while deserializing" {
    const empty_gate =
        \\packages = [
        \\  { name = "commonware-storage", benchmarks = [
        \\    { name = "qmdb_gungraun", variants = [
        \\      { name = "qmdb::merkleize/variant=empty", filter = "*", gates = [] }
        \\    ] }
        \\  ] }
        \\]
    ;
    try expect_invalid(empty_gate, "must be a non-empty array");
    const negative_threshold =
        \\[[packages]]
        \\name = "commonware-storage"
        \\
        \\[[packages.benchmarks]]
        \\name = "qmdb_gungraun"
        \\
        \\[[packages.benchmarks.variants]]
        \\name = "qmdb::merkleize/variant=negative"
        \\filter = "*"
        \\gates = [{ metric = "EstimatedCycles", direction = "down", threshold_percent = -1 }]
    ;
    try expect_invalid(negative_threshold, "must be non-negative");
    try expect_invalid(
        "[[packages]]\nname = \"\"\n[[packages.benchmarks]]\nname = \"t\"\n" ++
            "[[packages.benchmarks.variants]]\nname = \"v\"\nfilter = \"*\"",
        "must be a non-empty string",
    );
}

test "rejects unknown config fields while deserializing" {
    const package = "[[packages]]\nname = \"commonware-storage\"\n";
    const target = "[[packages.benchmarks]]\nname = \"qmdb_gungraun\"\n";
    const variant = "[[packages.benchmarks.variants]]\n" ++
        "name = \"qmdb::merkleize/variant=extra\"\nfilter = \"*\"\n";
    const extra = "extra = true\n";
    const inputs = [_][]const u8{
        extra ++ "\n" ++ package ++ target ++ variant,
        package ++ extra ++ target ++ variant,
        package ++ target ++ extra ++ variant,
        package ++ target ++ variant ++ extra,
    };
    for (inputs) |input| try expect_invalid(input, "unknown field");
}

/// Feeds `input` to every tracker parser: each must succeed or fail with `error.Invalid` and
/// a message, never crash. A string written with `write_string` must read back unchanged.
fn fuzz_parsers(input: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const output = @import("output.zig");
    var diagnostic: Diagnostic = .{};
    if (toml.parse(gpa, input, &diagnostic)) |_| {} else |err| {
        try testing.expectEqual(error.Invalid, err);
        try testing.expect(diagnostic.message().len > 0);
    }
    if (config.load_config(gpa, input, &diagnostic)) |_| {} else |err| {
        try testing.expectEqual(error.Invalid, err);
    }
    if (output.parse_lines(gpa, &diagnostic, input, "fuzz")) |lines| {
        if (output.custom_metrics(gpa, &diagnostic, lines, "x")) |_| {} else |err| {
            try testing.expectEqual(error.Invalid, err);
        }
    } else |err| try testing.expectEqual(error.Invalid, err);
    const half = input.len / 2;
    _ = output.glob(input[0..half], input[half..]);

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    try buffer.writer.writeAll("s = ");
    try toml.write_string(&buffer.writer, input);
    const root = try toml.parse(gpa, buffer.written(), &diagnostic);
    try testing.expectEqualStrings(input, root.get("s").?.string);
}

/// Mutates commonware's config fixture with `random` so most inputs reach deep parser states.
fn fuzz_mutated(random: std.Random, scratch: []u8) ![]const u8 {
    const len = @min(scratch.len, config_fixture.len);
    @memcpy(scratch[0..len], config_fixture[0..len]);
    const edits = random.uintAtMost(usize, 8);
    const alphabet = "[]{}=,.\"'#\n -_0123456789abcxyz\\";
    for (0..edits) |_| {
        const at = random.uintLessThan(usize, len);
        scratch[at] = alphabet[random.uintLessThan(usize, alphabet.len)];
    }
    return scratch[0..random.uintAtMost(usize, len)];
}

test "fuzz tracker parsers seeded" {
    const build_options = @import("build_options");
    const iterations: u64 = 256 * @as(u64, build_options.fuzz_soak);
    var prng: std.Random.DefaultPrng = .init(0x7472_6163 ^ build_options.fuzz_seed);
    const random = prng.random();
    var scratch: [config_fixture.len]u8 = undefined;
    for (0..iterations) |_| try fuzz_parsers(try fuzz_mutated(random, &scratch));
}

test "fuzz tracker parsers" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [512]u8 = undefined;
            smith.bytes(&bytes);
            const len = std.mem.readInt(u16, bytes[0..2], .little) % (bytes.len - 2);
            try fuzz_parsers(bytes[2..][0..len]);
        }
    }.run, .{});
}
