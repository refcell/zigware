//! Chat tests: key decoding against crossterm's parser, log lines against commonware's
//! logger.rs over tracing-subscriber 0.3.23's JSON, the CLI against clap's text, frames
//! against ratatui 0.30.2 (`testdata/ratatui_screens.txt`, drawn by ratatui's TestBackend
//! from the same states), and the handler chatting over p2p's simulated network.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const build_options = @import("build_options");
const keys = @import("keys.zig");
const clock = @import("clock.zig");
const logger = @import("logger.zig");
const tui = @import("tui.zig");
const handler = @import("handler.zig");
const cli = @import("cli.zig");
const terminal = @import("terminal.zig");
const chat = @import("main.zig");

const p2p = zigware.p2p;
const traces = zigware.runtime.telemetry.traces;
const metrics = zigware.runtime.telemetry.metrics;
const ed25519 = zigware.cryptography.ed25519;
const Key = ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);

test "the real terminal compiles" {
    testing.refAllDecls(terminal.Terminal);
}

fn expect_keys(input: []const []const u8, expected: []const keys.Key) !void {
    var parser: keys.Parser = .{};
    var parsed: std.ArrayList(keys.Key) = .empty;
    defer parsed.deinit(testing.allocator);
    for (input, 0..) |chunk, index| {
        var out: [keys.sequence_size_max]keys.Key = undefined;
        const more = index + 1 < input.len;
        const count = parser.advance(chunk, more, out[0..chunk.len]);
        try parsed.appendSlice(testing.allocator, out[0..count]);
    }
    try testing.expectEqualSlices(keys.Key, expected, parsed.items);
}

test "keys decode as crossterm parses them" {
    try expect_keys(&.{"aZ\r\t\x7f"}, &.{
        .{ .char = 'a' }, .{ .char = 'Z' }, .enter, .tab, .backspace,
    });
    // Raw mode: `\n` is Ctrl+J and Ctrl+C is a `c`, which chat types like any character.
    try expect_keys(&.{"\n\x03\x00\x1c"}, &.{
        .{ .char = 'j' }, .{ .char = 'c' }, .{ .char = ' ' }, .{ .char = '4' },
    });
    try expect_keys(&.{"\x1b"}, &.{.esc});
    try expect_keys(&.{"\x1b\x1b"}, &.{.esc});
    try expect_keys(&.{"\x1b[A\x1b[B\x1bOC\x1bOD"}, &.{ .up, .down, .right, .left });
    // Modified arrows and keys chat ignores.
    const ignored = "\x1b[1;5C\x1b[3~\x1b[H\x1bOP\x1b[<0;3;4M";
    try expect_keys(&.{ignored}, &.{ .right, .other, .other, .other, .other });
    // Sequences split across reads wait for their rest.
    try expect_keys(&.{ "\x1b", "[", "D" }, &.{.left});
    try expect_keys(&.{ "\xc3", "\xa9" }, &.{.{ .char = 0xe9 }});
    // Alt+key is the key.
    try expect_keys(&.{"\x1bx"}, &.{.{ .char = 'x' }});
    // Invalid sequences are dropped and parsing resumes.
    try expect_keys(&.{"\x1b[Xa\x80b\x1bOZc"}, &.{
        .{ .char = 'a' }, .{ .char = 'b' }, .{ .char = 'c' },
    });
    // `x` ends `ESC [ 1 ;` as an invalid sequence, so `A` is typed.
    try expect_keys(&.{"\x1b[1;xA"}, &.{.{ .char = 'A' }});
}

test "fuzz keys (seeded)" {
    var rng = zigware.utils.TestRng.init(0xc4a7 ^ build_options.fuzz_seed);
    const alphabet = "\x1b[O;1~5<Mm?uABCDaZ\r\t\x7f\xc3\xa9\xe4\xb8\x96\x80\xff";
    var input: [64]u8 = undefined;
    for (0..5000 * @as(u64, build_options.fuzz_soak)) |_| {
        const len = zigware.utils.rng.range_at_most(&rng, usize, 1, input.len);
        for (input[0..len]) |*byte| {
            byte.* = alphabet[zigware.utils.rng.range_less_than(&rng, usize, 0, alphabet.len)];
        }
        fuzz_keys(input[0..len]);
    }
}

test "fuzz keys" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [512]u8 = undefined;
            fuzz_keys(bytes[0..smith.slice(&bytes)]);
        }
    }.run, .{});
}

/// Feeding bytes one at a time or all together yields the same keys.
fn fuzz_keys(input: []const u8) void {
    var whole: keys.Parser = .{};
    var whole_keys: [512]keys.Key = undefined;
    const whole_count = whole.advance(input, false, whole_keys[0..input.len]);
    var single: keys.Parser = .{};
    var single_keys: [512]keys.Key = undefined;
    var single_count: usize = 0;
    for (input, 0..) |byte, index| {
        const more = index + 1 < input.len;
        single_count += single.advance(&.{byte}, more, single_keys[single_count..][0..1]);
    }
    std.debug.assert(whole_count == single_count);
    for (whole_keys[0..whole_count], single_keys[0..single_count]) |a, b| {
        std.debug.assert(std.meta.eql(a, b));
    }
}

test "stamps format as chrono's %m/%d %H:%M:%S" {
    try testing.expectEqualStrings("11/13 17:43:41", &clock.stamp(1794591821));
    try testing.expectEqualStrings("01/01 00:00:00", &clock.stamp(0));
    try testing.expectEqualStrings("12/31 23:59:59", &clock.stamp(-1));
    try testing.expectEqualStrings("02/29 12:00:00", &clock.stamp(1709208000));
}

test "POSIX TZ rules switch at the transitions zoneinfo gives" {
    // Offsets from Python's zoneinfo for America/New_York and Australia/Sydney in 2026.
    const new_york = try clock.parse_rule("EST5EDT,M3.2.0,M11.1.0");
    try testing.expectEqual(@as(i32, -18000), new_york.offset_at(1772953199));
    try testing.expectEqual(@as(i32, -14400), new_york.offset_at(1772953200));
    try testing.expectEqual(@as(i32, -14400), new_york.offset_at(1793512799));
    try testing.expectEqual(@as(i32, -18000), new_york.offset_at(1793512800));
    const sydney = try clock.parse_rule("AEST-10AEDT,M10.1.0,M4.1.0/3");
    try testing.expectEqual(@as(i32, 39600), sydney.offset_at(1775318399));
    try testing.expectEqual(@as(i32, 36000), sydney.offset_at(1775318400));
    try testing.expectEqual(@as(i32, 36000), sydney.offset_at(1791043199));
    try testing.expectEqual(@as(i32, 39600), sydney.offset_at(1791043200));
    const fixed = try clock.parse_rule("<+0530>-5:30");
    try testing.expectEqual(@as(i32, 19800), fixed.offset_at(0));
    try testing.expect(fixed.dst == null);
    const bad_rules = [_][]const u8{
        "", "E5", "EST", "EST5EDT,M3.2.0", "EST5EDT,M13.1.0,M1.1.0", "EST5x",
    };
    for (bad_rules) |bad| {
        try testing.expectError(error.InvalidRule, clock.parse_rule(bad));
    }
    const zone: clock.Zone = .{ .rule = new_york };
    try testing.expectEqualStrings("11/13 12:43:41", &zone.local_stamp(1794591821));
}

test "zones load from zoneinfo or fall back to UTC" {
    var missing = clock.Zone.load(testing.allocator, testing.io, "Nowhere/Nothing");
    defer missing.deinit();
    try testing.expectEqual(@as(i32, 0), missing.offset_at(1794591821));
    var zone = clock.Zone.load(testing.allocator, testing.io, ":America/New_York");
    defer zone.deinit();
    if (zone.tz == null) return; // No zoneinfo on this machine.
    try testing.expectEqual(@as(i32, -18000), zone.offset_at(1772953199));
    try testing.expectEqual(@as(i32, -14400), zone.offset_at(1772953200));
    try testing.expectEqual(@as(i32, -18000), zone.offset_at(4102444800)); // 2100, past the table.
    try testing.expectEqual(@as(i32, -14400), zone.offset_at(4118083200));
}

test "log lines match commonware's logger over tracing's JSON" {
    // Lines printed by commonware's logger.rs (tracing 0.1.44, tracing-subscriber 0.3.23,
    // serde_json 1.0.150) for the same events, at 2026-11-13T17:43:41Z.
    const gpa = testing.allocator;
    var collector: traces.Collector = .init(gpa, .{});
    defer collector.deinit();
    const tracer = collector.tracer("cl");
    tracer.event(.info, "no fields", .{});
    tracer.event(.info, "loaded port", .{ .port = @as(u16, 3001) });
    tracer.event(.info, "loaded signer", .{ .key = "Key(7)" });
    tracer.event(.debug, "sent message", .{ .friends = "[a,b]", .input = "hi \"there\"\\" });
    tracer.event(.warn, "dropped message", .{ .input = "x" });
    tracer.event(.@"error", "mixed", .{ .ok = true, .ratio = 0.5, .neg = @as(i64, -3) });
    tracer.event(.info, "ordering", .{ .zebra = 1, .apple = 2, .mango = "m" });
    tracer.event(.info, "near names", .{ .message_x = 1, .level_y = "l" });
    collector.tracer("commonware_p2p::authenticated").event(.info, "dialed", .{ .peer = "abcd" });
    tracer.event(.info, "escapes", .{ .s = "tab\there\nnl \u{e9} \x01" });
    const outer = tracer.span("outer", .{ .partition = "log", .n = 2 });
    outer.event(.info, "in span", .{ .a = 1 });
    const inner = outer.child("inner", .{});
    inner.event(.info, "nested", .{});
    const expected = [_][]const u8{
        "[11/13 17:43:41|INFO] cl => no fields",
        "[11/13 17:43:41|INFO] cl => loaded port (port=3001)",
        "[11/13 17:43:41|INFO] cl => loaded signer (key=\"Key(7)\")",
        "[11/13 17:43:41|DEBUG] cl => sent message (friends=\"[a,b]\" " ++
            "input=\"hi \\\"there\\\"\\\\\")",
        "[11/13 17:43:41|WARN] cl => dropped message (input=\"x\")",
        "[11/13 17:43:41|ERROR] cl => mixed (neg=-3 ok=true ratio=0.5)",
        "[11/13 17:43:41|INFO] cl => ordering (apple=2 mango=\"m\" zebra=1)",
        "[11/13 17:43:41|INFO] cl => near names (level_y=\"l\" message_x=1)",
        "[11/13 17:43:41|INFO] commonware_p2p::authenticated => dialed (peer=\"abcd\")",
        "[11/13 17:43:41|INFO] cl => escapes (s=\"tab\\there\\nnl \u{e9} \\u0001\")",
        "[11/13 17:43:41|INFO] cl => in span (a=1 n=2 name=\"outer\" partition=\"log\" " ++
            "spans=[{\"n\":2,\"name\":\"outer\",\"partition\":\"log\"}])",
        "[11/13 17:43:41|INFO] cl => nested (name=\"inner\" " ++
            "spans=[{\"n\":2,\"name\":\"outer\",\"partition\":\"log\"},{\"name\":\"inner\"}])",
    };
    try testing.expectEqual(expected.len, collector.events.items.len);
    for (expected, collector.events.items) |line, event| {
        const formatted = try logger.format(gpa, 1794591821, event);
        defer gpa.free(formatted);
        try testing.expectEqualStrings(line, formatted);
    }
}

test "JSON literals" {
    for ([_][]const u8{ "0", "-3", "3001", "0.5", "1e5", "-1.5E-3", "true", "false" }) |text| {
        try testing.expect(logger.is_json_literal(text));
    }
    for ([_][]const u8{ "", "-", "01", "1.", ".5", "1e", "abc", "True", "1 ", "NaN" }) |text| {
        try testing.expect(!logger.is_json_literal(text));
    }
}

const ParseResult = struct {
    outcome: cli.Outcome,
    err: []const u8,
    panic: ?[]const u8,
};

fn parse_args(arena: Allocator, args: []const []const u8) !ParseResult {
    var err: Io.Writer.Allocating = .init(arena);
    var panic: cli.Panic = .{};
    const outcome = cli.parse(arena, args, "commonware-chat", &err.writer, &panic) catch |failure| {
        if (failure != error.Panic) return failure;
        const message = try arena.dupe(u8, panic.message());
        return .{ .outcome = .usage_error, .err = "", .panic = message };
    };
    return .{ .outcome = outcome, .err = err.written(), .panic = null };
}

fn expect_usage(args: []const []const u8, expected: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const result = try parse_args(arena.allocator(), args);
    try testing.expect(result.outcome == .usage_error);
    try testing.expectEqualStrings(expected, result.err);
}

fn expect_panic(args: []const []const u8, expected: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const result = try parse_args(arena.allocator(), args);
    try testing.expectEqualStrings(expected, result.panic.?);
}

test "the CLI prints clap's help and errors" {
    var help: Io.Writer.Allocating = .init(testing.allocator);
    defer help.deinit();
    try cli.write_help(&help.writer, "commonware-chat");
    try testing.expectEqualStrings("send encrypted messages to a group of friends\n\n" ++
        "Usage: commonware-chat [OPTIONS] --me <me> --friends <friends>\n\n" ++
        "Options:\n" ++
        "      --me <me>                        \n" ++
        "      --friends <friends>              \n" ++
        "      --bootstrappers <bootstrappers>  \n" ++
        "  -h, --help                           Print help\n", help.written());
    const more = "For more information, try '--help'.\n";
    const full = "Usage: commonware-chat [OPTIONS] --me <me> --friends <friends>\n\n";
    const smart = "Usage: commonware-chat --me <me> --friends <friends>";
    try expect_usage(&.{}, "error: the following required arguments were not provided:\n" ++
        "  --me <me>\n  --friends <friends>\n\n" ++ smart ++ "\n\n" ++ more);
    try expect_usage(&.{"--me=1@3001"}, "error: the following required arguments were not " ++
        "provided:\n  --friends <friends>\n\n" ++ smart ++ "\n\n" ++ more);
    try expect_usage(&.{ "--me=1@3001", "--friends=a" }, "error: invalid value 'a' for " ++
        "'--friends <friends>': invalid digit found in string\n\n" ++ more);
    try expect_usage(&.{ "--me=1@1", "--friends=1,,2" }, "error: invalid value '' for " ++
        "'--friends <friends>': cannot parse integer from empty string\n\n" ++ more);
    try expect_usage(&.{ "--me=1@3001", "--friends=1", "--friends=2" }, "error: the argument " ++
        "'--friends <friends>' cannot be used multiple times\n\n" ++ full ++ more);
    try expect_usage(&.{ "--me", "1@3001", "--me", "2@3" }, "error: the argument '--me <me>' " ++
        "cannot be used multiple times\n\n" ++ full ++ more);
    try expect_usage(&.{ "--me=1@1", "--me=" }, "error: the argument '--me <me>' " ++
        "cannot be used multiple times\n\n" ++ full ++ more);
    const unexpected = "error: unexpected argument ";
    try expect_usage(&.{"--bogus"}, unexpected ++ "'--bogus' found\n\n" ++ full ++ more);
    try expect_usage(&.{ "--me=1@1", "-x" }, unexpected ++ "'-x' found\n\n" ++ full ++ more);
    try expect_usage(&.{"pos"}, "error: unexpected argument 'pos' found\n\n" ++ full ++ more);
    try expect_usage(&.{ "--me=1@1", "--friend=1" }, "error: unexpected argument '--friend' " ++
        "found\n\n  tip: a similar argument exists: '--friends'\n\n" ++ smart ++ "\n\n" ++ more);
    try expect_usage(&.{ "--me=1@1", "--friends=1", "--bootstrapers=1" }, "error: unexpected " ++
        "argument '--bootstrapers' found\n\n  tip: a similar argument exists: " ++
        "'--bootstrappers'\n\n" ++ smart ++ " --bootstrappers <bootstrappers>\n\n" ++ more);
    const no_value = "error: a value is required for '--me <me>' but none was supplied\n\n";
    try expect_usage(&.{ "--me=1@1", "--me" }, no_value ++ more);
    try expect_usage(&.{ "--me", "--friends=1" }, no_value ++ more);
    try expect_usage(&.{ "--me", "-h" }, no_value ++ more);
    try expect_usage(&.{ "--friends", "1", "--bootstrappers" }, "error: a value is required " ++
        "for '--bootstrappers <bootstrappers>' but none was supplied\n\n" ++ more);
    try expect_usage(&.{ "--bootstrappers=x", "--help=2" }, "error: unexpected value '2' for " ++
        "'--help' found; no more were expected\n\n" ++ smart ++
        " --bootstrappers <bootstrappers> --help\n\n" ++ more);
    try expect_usage(&.{"--bootstrappers=x"}, "error: the following required arguments were " ++
        "not provided:\n  --me <me>\n  --friends <friends>\n\n" ++ smart ++
        " --bootstrappers <bootstrappers>\n\n" ++ more);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const short_help = try parse_args(arena.allocator(), &.{ "--me=1@1", "-h" });
    try testing.expect(short_help.outcome == .help);
    try testing.expect((try parse_args(arena.allocator(), &.{"--help"})).outcome == .help);
}

test "the CLI panics where commonware's main does" {
    const cases = [_]struct { args: []const []const u8, message: []const u8 }{
        .{
            .args = &.{ "--me=x@1", "--friends=1" },
            .message = "Key not well-formed: ParseIntError { kind: InvalidDigit }",
        },
        .{
            .args = &.{ "--me=1", "--friends=1" },
            .message = "index out of bounds: the len is 1 but the index is 1",
        },
        .{
            .args = &.{ "--me=1@70000", "--friends=1" },
            .message = "Port not well-formed: ParseIntError { kind: PosOverflow }",
        },
        .{
            .args = &.{ "--me=1@1", "--friends=1,1" },
            .message = "public keys are unique: DuplicateKey",
        },
        .{
            .args = &.{ "--me=1@1", "--friends=1", "--bootstrappers=2@nope" },
            .message = "Bootstrapper address not well-formed: AddrParseError(Socket)",
        },
        .{
            .args = &.{ "--me=1@1", "--friends=1", "--bootstrappers=" },
            .message = "Bootstrapper key not well-formed: ParseIntError { kind: Empty }",
        },
    };
    for (cases) |case| try expect_panic(case.args, case.message);
}

test "the CLI parses a friend's arguments" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const result = try parse_args(arena.allocator(), &.{
        "--me=2@3002", "--friends=1,2,3,4", "--bootstrappers", "1@127.0.0.1:3001,3@[::1]:3003",
    });
    const arguments = result.outcome.run;
    try testing.expectEqual(@as(u64, 2), arguments.key);
    try testing.expectEqual(@as(u16, 3002), arguments.port);
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, arguments.friends);
    try testing.expectEqual(@as(usize, 2), arguments.bootstrappers.len);
    try testing.expectEqual(@as(u64, 3), arguments.bootstrappers[1].key);
    try testing.expectEqual(@as(u16, 3001), arguments.bootstrappers[0].address.getPort());
    try testing.expect(cli.parse_socket_address("127.0.0.1") == null);
    try testing.expect(cli.parse_socket_address("::1:80") == null);
    try testing.expect(cli.parse_socket_address("1.2.3.4:65536") == null);
}

test "the peer-set limit sizes the local identity without adding it as a recipient" {
    // commonware `sizes_local_identity_without_adding_recipient`.
    var collector: traces.Collector = .init(testing.allocator, .{});
    defer collector.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const configured = try chat.setup(arena.allocator(), .{
        .key = 1,
        .port = 3001,
        .friends = &.{2},
        .bootstrappers = &.{},
    }, collector.tracer(chat.target));
    try testing.expectEqual(@as(usize, 2), configured.max_peers_per_set);
    try testing.expectEqual(@as(usize, 1), configured.recipients.len);
    const local = ed25519.PrivateKey.from_seed(1).public_key();
    const friend = ed25519.PrivateKey.from_seed(2).public_key();
    try testing.expect(Key.order(configured.recipients[0], local) != .eq);
    try testing.expect(Key.order(configured.recipients[0], friend) == .eq);
    try collector.get_all().expect_message_exact("loaded signer");
    try collector.get_all().expect_message_exact("registered authorized key");
}

const ScreenCase = struct {
    name: []const u8,
    width: u16,
    height: u16,
    focus: handler.Focus,
    cursor: bool,
    input: []const u8,
    logs_scroll: handler.Scroll = .{},
    metrics_scroll: handler.Scroll = .{},
    messages_scroll: handler.Scroll = .{},
    messages: usize = 0,
    logs: usize = 0,
    /// Metric families in the metrics text; null for an empty text.
    metrics: ?usize = null,
    unicode: bool = false,
};

const screen_cases = [_]ScreenCase{
    .{
        .name = "input",
        .width = 80,
        .height = 24,
        .focus = .input,
        .cursor = true,
        .input = "hello",
        .messages = 3,
        .logs = 12,
        .metrics = 15,
    },
    .{
        .name = "logs",
        .width = 80,
        .height = 24,
        .focus = .logs,
        .cursor = false,
        .input = "",
        .logs_scroll = .{ .y = 2, .x = 3 },
        .messages = 40,
        .logs = 12,
        .metrics = 15,
    },
    .{
        .name = "metrics",
        .width = 80,
        .height = 24,
        .focus = .metrics,
        .cursor = true,
        .input = "typing",
        .metrics_scroll = .{ .y = 3, .x = 5 },
        .messages = 5,
        .logs = 2,
        .metrics = 15,
    },
    .{
        .name = "messages",
        .width = 80,
        .height = 24,
        .focus = .messages,
        .cursor = false,
        .input = "x",
        .messages_scroll = .{ .y = 1, .x = 4 },
        .messages = 20,
        .logs = 0,
        .metrics = 1,
    },
    .{
        .name = "messages_past_end",
        .width = 80,
        .height = 24,
        .focus = .messages,
        .cursor = true,
        .input = "",
        .messages_scroll = .{ .y = 19, .x = 200 },
        .messages = 20,
        .logs = 1,
    },
    .{
        .name = "large",
        .width = 120,
        .height = 40,
        .focus = .input,
        .cursor = true,
        .input = "a long input line that will not fit inside the input pane " ++
            "at all because it is long",
        .messages = 100,
        .logs = 50,
        .metrics = 40,
    },
    .{
        .name = "odd",
        .width = 41,
        .height = 13,
        .focus = .input,
        .cursor = false,
        .input = "hi",
        .messages = 7,
        .logs = 7,
        .metrics = 3,
    },
    .{
        .name = "unicode",
        .width = 80,
        .height = 24,
        .focus = .messages,
        .cursor = true,
        .input = "h\u{e9}llo \u{4e16}\u{754c}",
        .messages_scroll = .{ .x = 1 },
        .unicode = true,
    },
    .{
        .name = "tiny",
        .width = 12,
        .height = 7,
        .focus = .logs,
        .cursor = true,
        .input = "abc",
        .messages = 2,
        .logs = 3,
        .metrics = 1,
    },
};

fn fill_state(arena: Allocator, state: *handler.State, case: ScreenCase) ![]const u8 {
    state.focus = case.focus;
    state.cursor_visible = case.cursor;
    try state.input.appendSlice(state.gpa, case.input);
    state.logs_scroll = case.logs_scroll;
    state.metrics_scroll = case.metrics_scroll;
    state.messages_scroll = case.messages_scroll;
    if (case.unicode) {
        try state.push_message("[11/13 17:00:00] aaaa**bbbb: h\u{e9}llo \u{4e16}\u{754c} " ++
            "e\u{301}x tab\there bell\x07! cr\r\nlf", .yellow);
        try state.push_message("\u{4e16}\u{754c}\u{4e16}\u{754c}", null);
        try state.push_log("caf\u{e9} \u{1f600} end");
        return "a\tb\n\u{4e16}x\n";
    }
    for (0..case.messages) |i| {
        const mine = i % 3 == 0;
        var text: std.ArrayList(u8) = .empty;
        try text.print(arena, "[11/13 17:{d:0>2}:{d:0>2}] {s}: message {d}", .{
            i / 60 % 60, i % 60, if (mine) "aaaa**bbbb" else "cccc**dddd", i,
        });
        for (0..i % 5) |_| try text.appendSlice(arena, " lorem ipsum");
        try state.push_message(text.items, if (mine) .yellow else null);
    }
    for (0..case.logs) |i| {
        var text: std.ArrayList(u8) = .empty;
        try text.print(arena, "[11/13 17:00:{d:0>2}|INFO] commonware_p2p::authenticated => " ++
            "event {d} (peer=\"p{d}\")", .{ i % 60, i, i });
        for (0..i % 4) |_| try text.appendSlice(arena, " more");
        try state.push_log(text.items);
    }
    var text: std.ArrayList(u8) = .empty;
    const families = case.metrics orelse return "";
    for (0..families) |i| {
        try text.print(arena, "# HELP metric_{d} Description of metric number {d}.\n" ++
            "metric_{d}_total {d}\n", .{ i, i, i, i * 7 });
    }
    try text.appendSlice(arena, "# EOF\n");
    return text.items;
}

/// Replays the escape sequences a frame wrote onto a blank grid, as ratatui's TestBackend
/// applies the cells its backend draws.
fn replay(arena: Allocator, output: []const u8, area: tui.Rect) ![]tui.Cell {
    const cells = try arena.alloc(tui.Cell, @as(usize, area.width) * area.height);
    @memset(cells, .empty);
    var x: usize = 0;
    var y: usize = 0;
    var fg: tui.Color = .reset;
    var index: usize = 0;
    while (index < output.len) {
        if (output[index] == 0x1b) {
            try testing.expectEqual(@as(u8, '['), output[index + 1]);
            var end = index + 2;
            while (output[end] < 0x40 or output[end] > 0x7e) end += 1;
            const parameters = output[index + 2 .. end];
            switch (output[end]) {
                'H' => {
                    var fields = std.mem.splitScalar(u8, parameters, ';');
                    y = try std.fmt.parseInt(usize, fields.first(), 10) - 1;
                    x = try std.fmt.parseInt(usize, fields.next().?, 10) - 1;
                },
                'm' => if (std.mem.endsWith(u8, parameters, ";49")) {
                    fg = try parse_color(parameters[0 .. parameters.len - 3]);
                },
                'l', 'h', 'J' => {},
                else => return error.UnknownSequence,
            }
            index = end + 1;
            continue;
        }
        const run_end = std.mem.indexOfScalarPos(u8, output, index, 0x1b) orelse output.len;
        var graphemes: tui.Graphemes = .{ .text = output[index..run_end] };
        while (graphemes.next()) |grapheme| {
            const cell = &cells[y * area.width + x];
            cell.set_symbol(grapheme);
            cell.fg = fg;
            x += tui.grapheme_width(grapheme);
        }
        index = run_end;
    }
    return cells;
}

fn parse_color(sgr: []const u8) !tui.Color {
    for ([_]tui.Color{ .reset, .red, .yellow, .cyan }) |color| {
        const expected = switch (color) {
            .reset => "39",
            .red => "38;5;1",
            .yellow => "38;5;3",
            .cyan => "38;5;6",
        };
        if (std.mem.eql(u8, sgr, expected)) return color;
    }
    return error.UnknownColor;
}

fn expect_screen(case: ScreenCase, expected_file: []const u8) !void {
    const gpa = testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var state: handler.State = .init(gpa);
    defer state.deinit();
    const metrics_text = try fill_state(arena, &state, case);
    const area: tui.Rect = .{ .width = case.width, .height = case.height };
    var screen: tui.Screen = try .init(gpa, area);
    defer screen.deinit(gpa);
    try state.draw(arena, &screen.current, metrics_text);
    var out: Io.Writer.Allocating = .init(arena);
    try screen.flush(&out.writer);
    const frame_end = "\x1b[39m\x1b[49m\x1b[59m\x1b[0m\x1b[?25l";
    try testing.expect(std.mem.endsWith(u8, out.written(), frame_end));
    const cells = try replay(arena, out.written(), area);

    const header = try std.fmt.allocPrint(arena, "case {s} {d} {d}\n", .{
        case.name,
        case.width,
        case.height,
    });
    const found = std.mem.indexOf(u8, expected_file, header) orelse return error.MissingCase;
    const start = found + header.len;
    var lines = std.mem.splitScalar(u8, expected_file[start..], '\n');
    for (0..case.height) |row| {
        var symbols: std.ArrayList(u8) = .empty;
        for (cells[row * case.width ..][0..case.width]) |*cell| {
            try symbols.appendSlice(arena, cell.symbol());
        }
        try testing.expectEqualStrings(lines.next().?, symbols.items);
    }
    for (0..case.height) |row| {
        var colors: std.ArrayList(u8) = .empty;
        for (cells[row * case.width ..][0..case.width]) |cell| {
            try colors.append(arena, switch (cell.fg) {
                .reset => '.',
                .red => 'r',
                .yellow => 'y',
                .cyan => 'c',
            });
        }
        try testing.expectEqualStrings(lines.next().?, colors.items);
    }
}

test "frames match ratatui's" {
    const expected = @embedFile("testdata/ratatui_screens.txt");
    for (screen_cases) |case| {
        expect_screen(case, expected) catch |err| {
            std.debug.print("case {s}\n", .{case.name});
            return err;
        };
    }
}

test "keys edit the input and move the focus and scroll" {
    var state: handler.State = .init(testing.allocator);
    defer state.deinit();
    try testing.expect(try state.handle_key(.{ .char = 'h' }) == null);
    try testing.expect(try state.handle_key(.{ .char = 0x4e16 }) == null);
    try testing.expectEqualStrings("h\u{4e16}", state.input.items);
    _ = try state.handle_key(.backspace);
    try testing.expectEqualStrings("h", state.input.items);
    try testing.expectEqual(keys.Key.enter, (try state.handle_key(.enter)).?);
    _ = try state.handle_key(.backspace);
    try testing.expect(try state.handle_key(.enter) == null); // An empty input sends nothing.
    _ = try state.handle_key(.up); // The input pane does not scroll.
    try testing.expectEqual(handler.Scroll{}, state.logs_scroll);
    _ = try state.handle_key(.tab);
    try testing.expectEqual(handler.Focus.logs, state.focus);
    _ = try state.handle_key(.up);
    _ = try state.handle_key(.right);
    _ = try state.handle_key(.right);
    _ = try state.handle_key(.left);
    try testing.expectEqual(handler.Scroll{ .y = 0, .x = 1 }, state.logs_scroll);
    _ = try state.handle_key(.tab);
    _ = try state.handle_key(.down);
    try testing.expectEqual(handler.Scroll{ .y = 1, .x = 0 }, state.metrics_scroll);
    _ = try state.handle_key(.tab);
    _ = try state.handle_key(.tab);
    try testing.expectEqual(handler.Focus.input, state.focus);
    try testing.expectEqual(keys.Key.esc, (try state.handle_key(.esc)).?);
}

/// A keyboard that types `steps` one per 100 ms; an empty step is a tick.
const Script = struct {
    steps: []const []const u8,
    index: usize = 0,

    fn read(context: *anyopaque, io: Io, buffer: []u8) anyerror!?usize {
        const script: *Script = @ptrCast(@alignCast(context));
        try io.sleep(.fromMilliseconds(100), .awake);
        if (script.index == script.steps.len) return error.EndOfStream;
        const step = script.steps[script.index];
        script.index += 1;
        if (step.len == 0) return null;
        @memcpy(buffer[0..step.len], step);
        return step.len;
    }

    fn size(_: *anyopaque) tui.Rect {
        return .{ .width = 80, .height = 24 };
    }
};

fn chat_root(io: Io) !void {
    const gpa = testing.allocator;
    const me = ed25519.PrivateKey.from_seed(1).public_key();
    const friend = ed25519.PrivateKey.from_seed(2).public_key();
    var sorted = [_]Key{ me, friend };
    std.sort.pdq(Key, &sorted, {}, Key.less_than);
    const network = try Net.init_with_peers(gpa, io, .{
        .max_size = chat.message_size_max,
        .max_peers_per_set = 2,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    }, .init_primary(.init(&sorted)));
    defer network.deinit();
    var run = try io.concurrent(Net.run, .{network});
    defer {
        network.close();
        run.await(io) catch {};
    }
    const oracle = network.oracle();
    for ([2][2]Key{ .{ me, friend }, .{ friend, me } }) |pair| {
        try oracle.add_link(pair[0], pair[1], .{
            .latency = .from_millis(10),
            .jitter = .from_millis(0),
            .success_rate = 1.0,
        });
    }
    const quota = p2p.Quota.per_second(chat.message_rate_per_second);
    var mine = try oracle.control(me).register(handler.channel, quota);
    defer mine.deinit();
    var theirs = try oracle.control(friend).register(handler.channel, quota);
    defer theirs.deinit();
    gpa.free(try theirs.sender.send(.all, &.{"hello \xff"}, false));
    try chat_with(io, me, friend, &mine, &theirs);
}

/// Runs the UI for `me` while `friend` has sent one message, then checks both sides.
fn chat_with(io: Io, me: Key, friend: Key, mine: *Net.Registered, theirs: *Net.Registered) !void {
    const gpa = testing.allocator;
    var collector: traces.Collector = .init(gpa, .{});
    defer collector.deinit();
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry);
    var state: handler.State = .init(gpa);
    defer state.deinit();
    var script: Script = .{ .steps = &.{ "", "", "hi", "\r", "", "\x1b" } };
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var me_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&me_hex, "{f}", .{me});
    try handler.run(.{
        .gpa = gpa,
        .io = io,
        .me = &me_hex,
        .state = &state,
        .collector = &collector,
        .scope = &scope,
        .zone = &clock.Zone.utc,
        .terminal = .{
            .out = &out.writer,
            .context = &script,
            .size = Script.size,
            .keyboard = .{ .context = &script, .read = Script.read },
        },
    }, &mine.sender, &mine.receiver);

    var friend_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&friend_hex, "{f}", .{friend});
    try testing.expectEqual(@as(usize, 2), state.messages.items.len);
    const received = state.messages.items[0];
    const friend_name = handler.short_name(&friend_hex);
    const received_suffix = "] " ++ friend_name ++ ": hello \u{fffd}";
    try testing.expect(std.mem.endsWith(u8, received.text, received_suffix));
    try testing.expect(received.fg == null);
    const sent = state.messages.items[1];
    const my_name = handler.short_name(&me_hex);
    try testing.expect(std.mem.endsWith(u8, sent.text, "] " ++ my_name ++ ": hi"));
    try testing.expectEqual(@as(?tui.Color, .yellow), sent.fg);
    try testing.expectEqual(@as(usize, 0), state.input.items.len);
    const expected_friends = "[" ++ friend_hex ++ "]";
    try collector.get_all().expect_message_exact("sent message");
    const event = collector.events.items[0];
    try testing.expectEqualStrings(expected_friends, event.metadata.fields[0].value);
    try testing.expectEqual(@as(usize, 1), state.logs.items.len);
    try testing.expect(std.mem.indexOf(u8, state.logs.items[0].text, "|DEBUG] " ++
        handler.target ++ " => sent message (friends=\"[") != null);

    var delivered = try theirs.receiver.recv();
    defer delivered.deinit();
    try testing.expectEqualStrings("hi", delivered.payload);
    try testing.expect(Key.order(delivered.peer, me) == .eq);
    try testing.expect(std.mem.indexOf(u8, out.written(), "Messages") != null);
}

test "friends chat over the simulated network" {
    var runner = try zigware.runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start(chat_root, .{runner.io()}));
}
