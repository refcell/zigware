//! The dkg CLI against commonware's `commonware-dkg` binary (`testdata/cli_clap_cases.txt`,
//! printed by it, run as `dkg`, for the same arguments), and the values it parses.

const std = @import("std");
const testing = std.testing;
const Writer = std.Io.Writer;
const ui = @import("ui");
const cli = @import("cli.zig");

fn run_cli(gpa: std.mem.Allocator, args: []const []const u8, out: *Writer) !u8 {
    _ = gpa;
    return switch (try cli.parse(args, "dkg", out, out)) {
        .exit => |status| status,
        .run => unreachable, // Proof: every recorded case exits in clap.
    };
}

test "dkg: the CLI prints clap's help and errors" {
    try ui.clap.expect_cases(@embedFile("testdata/cli_clap_cases.txt"), 176, run_cli);
}

fn parse_ok(args: []const []const u8) !cli.Cli {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const outcome = try cli.parse(args, "dkg", &out.writer, &out.writer);
    try testing.expectEqualStrings("", out.written());
    return outcome.run;
}

test "dkg: the CLI parses commonware's defaults and values" {
    const defaults = try parse_ok(&.{"setup"});
    try testing.expectEqual(.info, defaults.log_level);
    try testing.expectEqual(3, defaults.worker_threads);
    const options = defaults.command.setup;
    try testing.expectEqualStrings("./data", options.node_dir);
    try testing.expectEqual(6, options.peers);
    try testing.expectEqual(4, options.committee_size);
    try testing.expectEqual(3000, options.base_port);
    try testing.expect(options.host.v4[0] == 127 and options.host.v4[3] == 1);

    const parsed = try parse_ok(&.{
        "--log-level",
        "+4",
        "--worker-threads=7",
        "setup",
        "--node-dir",
        "out",
        "--peers=5",
        "--committee-size",
        "3",
        "--base-port=+4000",
        "--host",
        "::1",
    });
    try testing.expectEqual(.debug, parsed.log_level);
    try testing.expectEqual(7, parsed.worker_threads);
    try testing.expectEqualStrings("out", parsed.command.setup.node_dir);
    try testing.expectEqual(5, parsed.command.setup.peers);
    try testing.expectEqual(3, parsed.command.setup.committee_size);
    try testing.expectEqual(4000, parsed.command.setup.base_port);
    try testing.expect(parsed.command.setup.host == .v6);

    const validator = try parse_ok(&.{ "--log-level", "TRACE", "validator", "--state-sync" });
    try testing.expectEqual(.trace, validator.log_level);
    try testing.expectEqualStrings(cli.default_node_dir, validator.command.validator.node_dir);
    try testing.expect(validator.command.validator.state_sync);

    const bootstrap = try parse_ok(&.{ "bootstrap", "--node-dir=nodes/validator-2" });
    try testing.expectEqualStrings("nodes/validator-2", bootstrap.command.bootstrap.node_dir);
    try testing.expect(!(try parse_ok(&.{"validator"})).command.validator.state_sync);
}
