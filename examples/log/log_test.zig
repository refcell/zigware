//! Log tests: the CLI against clap's text (`testdata/clap_cases.txt`, printed by commonware's
//! `commonware-log` for each argument list), its panics against commonware's `main`, GUI
//! lines against gui.rs's `Writer` over tracing-subscriber 0.3.23's JSON, and the
//! application and reporter driving four simplex validators to finalization over
//! `p2p.simulated` in the deterministic runtime.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const build_options = @import("build_options");
const ui = @import("ui");
const cli = @import("cli.zig");
const application = @import("application.zig");
const gui = @import("gui.zig");

const p2p = zigware.p2p;
const simplex = zigware.consensus.simplex;
const traces = zigware.runtime.telemetry.traces;
const runtime = zigware.runtime;
const Sha256 = zigware.cryptography.Sha256;
const Digest = Sha256.Digest;
const Key = zigware.cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);

const Parsed = struct { outcome: ?cli.Outcome, text: []const u8, panic: ?[]const u8 };

/// Parses `args` as `main` does, collecting what it would print.
fn parse_args(arena: Allocator, args: []const []const u8) !Parsed {
    var out: Io.Writer.Allocating = .init(arena);
    var panic: cli.Panic = .{};
    const outcome = cli.parse(arena, args, "commonware-log", &out.writer, &panic) catch |err|
        switch (err) {
            error.Panic => return .{ .outcome = null, .text = "", .panic = panic.message() },
            else => |other| return other,
        };
    if (outcome == .help) try cli.write_help(&out.writer, "commonware-log");
    return .{ .outcome = outcome, .text = out.written(), .panic = null };
}

test "the CLI prints clap's help and errors" {
    const cases = @embedFile("testdata/clap_cases.txt");
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var records = std.mem.splitSequence(u8, cases[4..], "\n### ");
    var count: usize = 0;
    while (records.next()) |record| : (count += 1) {
        const args_end = std.mem.indexOfScalar(u8, record, '\n').?;
        var args: std.ArrayList([]const u8) = .empty;
        var words = std.mem.tokenizeScalar(u8, record[0..args_end], ' ');
        while (words.next()) |word| try args.append(arena, word);
        const rest = record[args_end + 1 ..];
        const exit_end = std.mem.indexOfScalar(u8, rest, '\n').?;
        const expected_exit = try std.fmt.parseInt(u8, rest["exit=".len..exit_end], 10);
        const expected = std.mem.trimEnd(u8, rest[exit_end + 1 ..], "\n");
        const parsed = try parse_args(arena, args.items);
        errdefer std.debug.print("case: {s}\n", .{record[0..args_end]});
        try testing.expectEqual(@as(?[]const u8, null), parsed.panic);
        const exit: u8 = if (parsed.outcome.? == .help) 0 else 2;
        try testing.expect(parsed.outcome.? != .run);
        try testing.expectEqual(expected_exit, exit);
        try testing.expectEqualStrings(expected, std.mem.trimEnd(u8, parsed.text, "\n"));
    }
    try testing.expectEqual(@as(usize, 52), count);
}

test "the CLI panics where commonware's main does" {
    const cases = [_]struct { me: []const u8, extra: []const []const u8, message: []const u8 }{
        .{ .me = "1", .extra = &.{}, .message = "Identity not well-formed" },
        .{ .me = "0@3000@1", .extra = &.{}, .message = "Identity not well-formed" },
        .{
            .me = "x@1",
            .extra = &.{},
            .message = "Key not well-formed: ParseIntError { kind: InvalidDigit }",
        },
        .{
            .me = "1@70000",
            .extra = &.{},
            .message = "Port not well-formed: ParseIntError { kind: PosOverflow }",
        },
        .{
            .me = "1@1",
            .extra = &.{"--participants=1,1"},
            .message = "public keys are unique: DuplicateKey",
        },
        .{
            .me = "1@1",
            .extra = &.{"--bootstrappers=1"},
            .message = "index out of bounds: the len is 1 but the index is 1",
        },
        .{
            .me = "1@1",
            .extra = &.{"--bootstrappers=1@x"},
            .message = "Bootstrapper address not well-formed: AddrParseError(Socket)",
        },
        .{
            .me = "1@1",
            .extra = &.{"--bootstrappers="},
            .message = "Bootstrapper key not well-formed: ParseIntError { kind: Empty }",
        },
    };
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (cases) |case| {
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(arena, &.{ "--storage-dir=/tmp/q", "--me", case.me });
        try args.appendSlice(arena, case.extra);
        if (case.extra.len == 0 or !std.mem.startsWith(u8, case.extra[0], "--participants")) {
            try args.append(arena, "--participants=1");
        }
        const parsed = try parse_args(arena, args.items);
        try testing.expectEqualStrings(case.message, parsed.panic.?);
    }
}

test "the CLI parses a participant's arguments" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const parsed = try parse_args(arena.allocator(), &.{
        "--bootstrappers", "0@127.0.0.1:3000,2@1.2.3.4:5@6",
        "--me",            "1@3001",
        "--participants",  "0,1,2,3",
        "--storage-dir",   "/tmp/zigware-log/1",
    });
    const arguments = parsed.outcome.?.run;
    try testing.expectEqual(@as(u64, 1), arguments.key);
    try testing.expectEqual(@as(u16, 3001), arguments.port);
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3 }, arguments.participants);
    try testing.expectEqualStrings("/tmp/zigware-log/1", arguments.storage_directory);
    try testing.expectEqual(@as(usize, 2), arguments.bootstrappers.len);
    try testing.expectEqual(@as(u64, 2), arguments.bootstrappers[1].key);
    try testing.expectEqual(@as(u16, 5), arguments.bootstrappers[1].address.getPort());
}

/// Arguments drawn from options, values, and junk: the parser always finishes, and help is
/// the only outcome without a message.
fn fuzz_cli(seed: u64, iterations: u64) !void {
    var rng_state = zigware.utils.rng.TestRng.init(seed);
    const random = zigware.utils.rng.random(&rng_state);
    const tokens = [_][]const u8{
        "--me",
        "--participants",
        "--storage-dir",
        "--bootstrappers",
        "--help",
        "-h",
        "--",
        "-",
        "--mee",
        "1@2",
        "0,1,2",
        "x",
        "",
        "-x",
        "1,,2",
        "--help=1",
        "--me=1@2",
        "--participants=1,1",
        "--storage-dir=/tmp/q",
        "--bootstrappers=1@127.0.0.1:1",
        "18446744073709551616",
    };
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    for (0..iterations) |_| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        var args: [8][]const u8 = undefined;
        const len = random.uintAtMost(usize, args.len);
        for (args[0..len]) |*arg| arg.* = tokens[random.uintLessThan(usize, tokens.len)];
        const parsed = try parse_args(arena, args[0..len]);
        if (parsed.panic) |message| {
            try testing.expect(message.len > 0);
            continue;
        }
        switch (parsed.outcome.?) {
            .help => try testing.expect(std.mem.startsWith(u8, parsed.text, cli.about)),
            .usage_error => {
                try testing.expect(std.mem.startsWith(u8, parsed.text, "error: "));
                try testing.expect(std.mem.endsWith(u8, parsed.text, "try '--help'.\n"));
            },
            .run => |arguments| try testing.expect(arguments.participants.len > 0),
        }
    }
}

test "fuzz the CLI (seeded)" {
    try fuzz_cli(build_options.fuzz_seed ^ 0x6c6f67, 2_000 * build_options.fuzz_soak);
}

test "GUI lines match gui.rs's Writer over tracing's JSON" {
    // Lines printed by gui.rs's Writer (tracing 0.1.44, tracing-subscriber 0.3.23, serde_json
    // 1.0.150, chrono 0.4.45) for the same events, at 2026-11-16T06:07:54 local time. The
    // application records `%view`, `?payload`, and `hex(..)`, which serialize as strings.
    const gpa = testing.allocator;
    var collector: traces.Collector = .init(gpa, .{});
    defer collector.deinit();
    const app = collector.tracer(application.target ++ "::actor");
    app.event(.info, "proposed", .{ .msg = "00ff", .payload = "01020304" });
    app.event(.info, "notarized", .{ .view = @as(u64, 7), .payload = "ab000001" });
    app.event(.info, "nullified", .{ .view = @as(u64, 7) });
    app.event(.info, "finalized", .{ .view = @as(u64, 7), .payload = "09090909" });
    const other = collector.tracer("lg");
    other.event(.info, "loaded port", .{ .port = @as(u16, 3000) });
    other.event(.debug, "plain number", .{ .view = @as(u64, 3) });
    const expected = [_][]const u8{
        "[2026-11-16T06:07:54] => proposed (msg=\"00ff\" payload=\"01020304\")",
        "[2026-11-16T06:07:54] => notarized (payload=\"ab000001\" view=\"7\")",
        "[2026-11-16T06:07:54] => nullified (view=\"7\")",
        "[2026-11-16T06:07:54] => finalized (payload=\"09090909\" view=\"7\")",
        "[2026-11-16T06:07:54|INFO] lg => loaded port (port=3000)",
        "[2026-11-16T06:07:54|DEBUG] lg => plain number (view=3)",
    };
    const stamp = ui.clock.iso_stamp(1794809274);
    try testing.expectEqualStrings("2026-11-16T06:07:54", &stamp);
    for (expected, collector.events.items) |line, event| {
        const formatted = try gui.format_line(gpa, &stamp, event);
        defer gpa.free(formatted);
        try testing.expectEqualStrings(line, formatted);
    }
    try testing.expectEqual(@as(?ui.tui.Color, .blue), gui.progress_color(expected[0]));
    try testing.expectEqual(@as(?ui.tui.Color, null), gui.progress_color(expected[1]));
    try testing.expectEqual(@as(?ui.tui.Color, .green), gui.progress_color(expected[3]));
    try testing.expectEqual(@as(?ui.tui.Color, .yellow), gui.progress_color("x prepared"));
}

test "GUI lines carry the time each event was recorded, not the draw's" {
    // gui.rs stamps a line with tracing's event timestamp. Here the draw comes long after
    // (its time is the epoch), and the line must still show when the event was recorded.
    const gpa = testing.allocator;
    var collector: traces.Collector = .init(gpa, .{ .clock = testing.io });
    defer collector.deinit();
    const before_ns = Io.Clock.real.now(testing.io).nanoseconds;
    collector.tracer(application.target).event(.info, "finalized", .{ .view = @as(u64, 1) });
    const after_ns = Io.Clock.real.now(testing.io).nanoseconds;
    const recorded_ns = collector.events.items[0].time_ns.?;
    try testing.expect(before_ns <= recorded_ns and recorded_ns <= after_ns);
    var state: gui.State = .init(gpa);
    defer state.deinit();
    const zone: ui.clock.Zone = .{ .rule = try ui.clock.parse_rule("UTC0") };
    try state.collect(&collector, &zone, 0);
    const stamp = ui.clock.iso_stamp(@intCast(@divFloor(recorded_ns, std.time.ns_per_s)));
    const line = state.progress.items[0].text;
    try testing.expect(std.mem.startsWith(u8, line[1..], &stamp));
}

test "ISO stamps format as chrono's %Y-%m-%dT%H:%M:%S" {
    try testing.expectEqualStrings("1970-01-01T00:00:00", &ui.clock.iso_stamp(0));
    try testing.expectEqualStrings("1969-12-31T23:59:59", &ui.clock.iso_stamp(-1));
    try testing.expectEqualStrings("2024-02-29T12:00:00", &ui.clock.iso_stamp(1709208000));
    const zone: ui.clock.Zone = .{ .rule = try ui.clock.parse_rule("<+0530>-5:30") };
    try testing.expectEqualStrings("1970-01-01T05:30:00", &zone.local_iso_stamp(0));
}

test "the GUI splits Activity and Logs, and TAB moves the red border" {
    const gpa = testing.allocator;
    var state: gui.State = .init(gpa);
    defer state.deinit();
    var buffer: ui.tui.Buffer = try .init(gpa, .{ .width = 40, .height = 10 });
    defer buffer.deinit(gpa);
    state.draw(&buffer);
    // 60% of 10 rows is 6: Activity takes rows 0 to 5, Logs rows 6 to 9.
    try testing.expectEqualStrings("A", buffer.at(1, 0).symbol());
    try testing.expectEqualStrings("L", buffer.at(1, 6).symbol());
    try testing.expectEqual(ui.tui.Color.red, buffer.at(0, 0).fg);
    try testing.expectEqual(ui.tui.Color.reset, buffer.at(0, 6).fg);
    try testing.expect(state.handle_key(.tab));
    buffer.reset();
    state.draw(&buffer);
    try testing.expectEqual(ui.tui.Color.reset, buffer.at(0, 0).fg);
    try testing.expectEqual(ui.tui.Color.red, buffer.at(0, 6).fg);
    try testing.expect(!state.handle_key(.esc));
}

// Four validators running log's application and reporter on the simplex engine.

const MockReporter = simplex.mocks.reporter.Reporter(application.Scheme(Digest), Digest);
const LogReporter = application.Reporter(Digest);
const LogApplication = application.Application(Sha256);

/// Log's reporter, plus the mock reporter that verifies activity and waits for views.
const TestReporter = struct {
    pub const Activity = LogReporter.Activity;
    log: LogReporter,
    mock: MockReporter,

    pub fn report(self: *TestReporter, activity: Activity) zigware.actor.Feedback {
        _ = self.log.report(activity);
        return self.mock.report(activity);
    }
};

const Params = struct {
    pub const Context = runtime.deterministic.Context;
    pub const Scheme = application.Scheme(Sha256.Digest);
    pub const Elector = simplex.elector.RoundRobinElector;
    pub const Blocker = Net.Control;
    pub const Digest = Sha256.Digest;
    pub const Automaton = *LogApplication;
    pub const Relay = *LogApplication;
    pub const Reporter = *TestReporter;
    pub const Strategy = zigware.parallel.Sequential;
    pub const Sender = Net.Sender;
    pub const Receiver = Net.Receiver;
};
const Engine = simplex.Engine(Params);
const Channel = simplex.engine.Channel(Params);

/// One validator. Must not move once started.
const Validator = struct {
    app: LogApplication,
    reporter: TestReporter,
    page_cache: runtime.buffer.paged.CacheRef,
    elector: simplex.elector.RoundRobinElector,
    engine: Engine,
    partition: [16]u8,
    handle: ?runtime.context.Handle(Engine.RunResult) = null,
};

fn start(
    ctx: Params.Context,
    validator: *Validator,
    collector: *traces.Collector,
    fixture: anytype,
    oracle: Net.Oracle,
    index: usize,
) !void {
    const gpa = testing.allocator;
    const key = fixture.participants[index];
    validator.* = undefined;
    validator.handle = null;
    validator.app = .init(collector.tracer(application.target));
    validator.reporter = .{
        .log = .init(collector.tracer(application.target)),
        .mock = .init(gpa, ctx.io(), &fixture.verifier),
    };
    validator.page_cache = try .init(gpa, 1024, 10);
    const n: u32 = @intCast(fixture.participants.len);
    validator.elector = try simplex.elector.RoundRobin(Sha256).default().build(gpa, n);
    validator.partition = @splat(0);
    _ = try std.fmt.bufPrint(&validator.partition, "log-{d}", .{index});
    try validator.engine.init(ctx, config(validator, fixture.schemes[index], oracle.control(key)));
    var channels: [3]Channel = undefined;
    for (&channels, 0..) |*channel, channel_index| {
        const quota = p2p.Quota.per_second(1024);
        const registered = try oracle.control(key).register(channel_index, quota);
        channel.* = .{ .sender = registered.sender, .receiver = registered.receiver };
    }
    validator.handle = try ctx.child("engine").spawn(Engine.run, .{
        &validator.engine, channels[0], channels[1], channels[2],
    });
}

/// log's configuration (`main.zig`), with a small page cache.
fn config(validator: *Validator, scheme: Params.Scheme, blocker: Net.Control) Engine.Config {
    return .{
        .scheme = scheme,
        .elector = validator.elector,
        .blocker = blocker,
        .automaton = &validator.app,
        .relay = &validator.app,
        .reporter = &validator.reporter,
        .partition = std.mem.sliceTo(&validator.partition, 0),
        .mailbox_size = 1024,
        .epoch = .zero(),
        .floor = .{ .genesis = application.genesis(Sha256) },
        .replay_buffer = 1024 * 1024,
        .write_buffer = 1024 * 1024,
        .leader_timeout = .from_secs(1),
        .certification_timeout = .from_secs(2),
        .timeout_retry = .from_secs(10),
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .view_retention = .new(10),
        .skip = .{ .enabled = .{ .timeout = .from_secs(11), .budget = .participants } },
        .page_cache = &validator.page_cache,
        .strategy = zigware.parallel.sequential,
        .forward = .disabled,
        .track_historical_votes = false,
    };
}

fn stop(validator: *Validator) void {
    const gpa = testing.allocator;
    if (validator.handle) |handle| {
        if (handle.abort()) |result| {
            result catch |err| std.debug.panic("engine failed: {t}", .{err});
        } else |_| {}
    }
    validator.engine.deinit();
    validator.elector.deinit(gpa);
    validator.page_cache.deinit();
    validator.reporter.mock.deinit();
}

fn finalize(ctx: Params.Context, collector: *traces.Collector, required: u64) !void {
    const gpa = testing.allocator;
    const io = ctx.io();
    var rng = zigware.utils.rng.test_rng();
    const n = 4;
    var fixture = try simplex.scheme.ed25519.fixture(Digest, gpa, &rng, "log", n);
    defer fixture.deinit(gpa);
    const network = try Net.init(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = n + 1,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    });
    defer network.deinit();
    var network_task = try io.concurrent(Net.run, .{network});
    defer {
        network.close();
        network_task.await(io) catch {};
    }
    const oracle = network.oracle();
    _ = oracle.manager().track(0, .init_primary(.init(fixture.participants)));
    for (fixture.participants) |from| for (fixture.participants) |to| {
        if (from.order(to) == .eq) continue;
        try oracle.add_link(from, to, .{
            .latency = .from_millis(10),
            .jitter = .from_millis(1),
            .success_rate = 1.0,
        });
    };
    var validators: [n]Validator = undefined;
    var started: usize = 0;
    defer for (validators[0..started]) |*validator| stop(validator);
    for (&validators, 0..) |*validator, index| {
        try start(ctx, validator, collector, &fixture, oracle, index);
        started += 1;
    }
    for (&validators) |*validator| try validator.reporter.mock.wait_for_finalized(.new(required));
    for (&validators) |*validator| {
        validator.reporter.mock.assert_no_faults();
        validator.reporter.mock.assert_no_invalid();
    }
    // Every validator finalized the same payload at each view both saw finalized.
    for (1..required + 1) |view| {
        var expected: ?Digest = null;
        for (&validators) |*validator| {
            const payload = validator.reporter.mock.finalized(.new(view)) orelse continue;
            if (expected) |digest| try testing.expect(digest.order(payload) == .eq);
            expected = payload;
        }
    }
}

test "four validators running log finalize and log their activity" {
    const gpa = testing.allocator;
    var collector: traces.Collector = .init(gpa, .{});
    defer collector.deinit();
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = 0 });
    defer runner.deinit();
    try (try runner.start_context(finalize, .{ &collector, 10 }));
    var proposed: usize = 0;
    var finalized: usize = 0;
    for (collector.events.items) |event| {
        try testing.expectEqualStrings(application.target, event.target);
        const message = event.metadata.content;
        if (std.mem.eql(u8, message, "proposed")) proposed += 1;
        if (std.mem.eql(u8, message, "finalized")) finalized += 1;
    }
    try testing.expect(proposed >= 10);
    try testing.expect(finalized >= 4 * 10);
    // A proposal's line shows its 16-byte secret in hex and the digest proposed.
    const first = collector.get_all().get(0).?;
    try first.metadata.expect_content_exact("proposed");
    const line = try gui.format_line(gpa, &ui.clock.iso_stamp(0), first);
    defer gpa.free(line);
    const empty = "[1970-01-01T00:00:00] => proposed (msg=\"\" payload=\"\")";
    const hex_size = 2 * application.message_size + 2 * Digest.fixed_size;
    try testing.expectEqual(empty.len + hex_size, line.len);
}
