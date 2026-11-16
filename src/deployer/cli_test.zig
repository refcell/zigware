//! Tests for the `deployer` command line, against the clap definition in commonware
//! `deployer/src/main.rs`.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const cli = @import("cli.zig");

fn ok(args: []const []const u8) !cli.Parsed {
    return switch (cli.parse(args)) {
        .ok => |parsed| parsed,
        .failure => |failure| {
            std.debug.print("unexpected failure: {any}\n", .{failure});
            return error.TestUnexpectedResult;
        },
    };
}

fn expect_failure(args: []const []const u8, kind: cli.Failure.Kind, argument: []const u8) !void {
    switch (cli.parse(args)) {
        .ok => return error.TestUnexpectedResult,
        .failure => |failure| {
            try testing.expectEqual(kind, failure.kind);
            try testing.expectEqualStrings(argument, failure.argument);
        },
    }
}

test "cli: create and update take a config and default concurrency 128" {
    const create = try ok(&.{ "aws", "create", "--config", "c.yaml" });
    try testing.expect(!create.verbose);
    try testing.expectEqualStrings("c.yaml", create.command.aws.create.config);
    try testing.expectEqual(@as(u64, 128), create.command.aws.create.concurrency);

    const update = try ok(&.{ "-v", "aws", "update", "--concurrency=7", "--config=u.yaml" });
    try testing.expect(update.verbose);
    try testing.expectEqualStrings("u.yaml", update.command.aws.update.config);
    try testing.expectEqual(@as(u64, 7), update.command.aws.update.concurrency);

    const plus = try ok(&.{ "--verbose", "aws", "create", "--config", "c", "--concurrency", "+1" });
    try testing.expect(plus.verbose);
    try testing.expectEqual(@as(u64, 1), plus.command.aws.create.concurrency);
}

test "cli: concurrency is a u64 of at least 1" {
    const create = [_][]const u8{ "aws", "create", "--config", "c", "--concurrency" };
    try expect_failure(&(create ++ .{"0"}), .invalid_value, "concurrency");
    try expect_failure(&(create ++ .{"1_0"}), .invalid_value, "concurrency");
    try expect_failure(&(create ++ .{"+"}), .invalid_value, "concurrency");
    try expect_failure(&(create ++ .{""}), .invalid_value, "concurrency");
    try expect_failure(&(create ++ .{"18446744073709551616"}), .invalid_value, "concurrency");
    const max = try ok(&(create ++ .{"18446744073709551615"}));
    try testing.expectEqual(std.math.maxInt(u64), max.command.aws.create.concurrency);
    // A flag is not taken as a value.
    try expect_failure(&(create ++ .{"-1"}), .missing_value, "concurrency");
    try expect_failure(&.{ "aws", "update", "--concurrency", "4" }, .missing_required, "config");
    try expect_failure(&.{ "aws", "update", "--config" }, .missing_value, "config");
    try expect_failure(&.{ "aws", "update", "--config=" }, .invalid_value, "config");
}

test "cli: an option given twice, an unknown option, and a stray value fail" {
    try expect_failure(
        &.{ "aws", "create", "--config", "a", "--config=b" },
        .repeated,
        "config",
    );
    try expect_failure(&.{ "-v", "--verbose", "aws", "list" }, .repeated, "verbose");
    const tag = [_][]const u8{ "aws", "create", "--config", "a", "--tag", "t" };
    try expect_failure(&tag, .unexpected_argument, "--tag");
    try expect_failure(&.{ "aws", "create", "c.yaml" }, .unexpected_argument, "c.yaml");
    try expect_failure(&.{ "aws", "list", "extra" }, .unexpected_argument, "extra");
    try expect_failure(&.{ "gcp", "list" }, .unexpected_argument, "gcp");
    try expect_failure(&.{ "aws", "launch" }, .unexpected_argument, "launch");
    // `-v` is an option of `deployer`, not of its subcommands.
    try expect_failure(&.{ "aws", "list", "-v" }, .unexpected_argument, "-v");
}

test "cli: authorize takes an optional ip" {
    const without = try ok(&.{ "aws", "authorize", "--config", "c" });
    try testing.expectEqualStrings("c", without.command.aws.authorize.config);
    try testing.expectEqual(@as(?[]const u8, null), without.command.aws.authorize.ip);
    const with = try ok(&.{ "aws", "authorize", "--ip", "1.2.3.4", "--config", "c" });
    try testing.expectEqualStrings("1.2.3.4", with.command.aws.authorize.ip.?);
    try expect_failure(&.{ "aws", "authorize", "--ip", "1.2.3.4" }, .missing_required, "config");
}

test "cli: destroy takes exactly one of --config and --tag" {
    const by_config = try ok(&.{ "aws", "destroy", "--config", "c.yaml" });
    try testing.expectEqualStrings("c.yaml", by_config.command.aws.destroy.config);
    const by_tag = try ok(&.{ "aws", "destroy", "--tag", "abc" });
    try testing.expectEqualStrings("abc", by_tag.command.aws.destroy.tag);
    try expect_failure(&.{ "aws", "destroy" }, .missing_required, "config|tag");
    try expect_failure(&.{ "aws", "destroy", "--tag", "t", "--config", "c" }, .conflict, "tag");
}

test "cli: profile requires config, instance, and binary; duration defaults to 30" {
    const parsed = try ok(&.{
        "aws", "profile", "--binary", "b", "--instance", "node0", "--config", "c",
    });
    const profile = parsed.command.aws.profile;
    try testing.expectEqualStrings("c", profile.config);
    try testing.expectEqualStrings("node0", profile.instance);
    try testing.expectEqualStrings("b", profile.binary);
    try testing.expectEqual(@as(u64, 30), profile.duration_s);

    const zero = try ok(&.{
        "aws", "profile", "--config", "c", "--instance", "i", "--binary", "b", "--duration", "0",
    });
    try testing.expectEqual(@as(u64, 0), zero.command.aws.profile.duration_s);
    try expect_failure(
        &.{ "aws", "profile", "--config", "c", "--binary", "b" },
        .missing_required,
        "instance",
    );
    try expect_failure(
        &.{ "aws", "profile", "--config", "c", "--instance", "i" },
        .missing_required,
        "binary",
    );
}

test "cli: attach takes one positional ip" {
    const parsed = try ok(&.{ "aws", "attach", "10.0.0.1" });
    try testing.expectEqualStrings("10.0.0.1", parsed.command.aws.attach.ip);
    try expect_failure(&.{ "aws", "attach" }, .missing_required, "ip");
    try expect_failure(&.{ "aws", "attach", "a", "b" }, .unexpected_argument, "b");
    try expect_failure(&.{ "aws", "attach", "--ip", "a" }, .unexpected_argument, "--ip");
}

test "cli: list, clean, help, version, and no subcommand" {
    try testing.expectEqual(cli.Aws.list, (try ok(&.{ "aws", "list" })).command.aws);
    try testing.expectEqual(cli.Aws.clean, (try ok(&.{ "aws", "clean" })).command.aws);
    try testing.expectEqual(cli.Command.none, (try ok(&.{})).command);
    try testing.expectEqual(cli.Command.none, (try ok(&.{ "-v", "aws" })).command);
    try testing.expectEqual(cli.Command.help, (try ok(&.{"--help"})).command);
    try testing.expectEqual(cli.Command.help, (try ok(&.{ "aws", "-h" })).command);
    try testing.expectEqual(cli.Command.version, (try ok(&.{"-V"})).command);
    try testing.expectEqualStrings("2026.10.0", cli.version);
}

const words = [_][]const u8{
    "aws",  "create",    "update",        "destroy", "list",      "attach",     "profile",
    "-v",   "-h",        "--config",      "--tag",   "--config=", "x",          "--concurrency",
    "0",    "+3",        "--concurrency", "-",       "--binary",  "--instance", "clean",
    "--ip", "authorize", "--duration",
};

fn parse_any(_: void, random: *utils.rng.FuzzRng) anyerror!void {
    var args: [8][]const u8 = undefined;
    const count = utils.rng.range_at_most(random, usize, 0, args.len);
    for (args[0..count]) |*arg| {
        arg.* = words[utils.rng.range_less_than(random, usize, 0, words.len)];
    }
    switch (cli.parse(args[0..count])) {
        .failure => |failure| try testing.expect(failure.argument.len > 0),
        .ok => |parsed| if (parsed.command == .aws) switch (parsed.command.aws) {
            .create, .update => |rollout| {
                try testing.expect(rollout.concurrency >= 1);
                try testing.expect(rollout.config.len > 0);
            },
            .profile => |profile| try testing.expect(profile.binary.len > 0),
            else => {},
        },
    }
}

test "cli: fuzz parse never panics and accepts only well-formed commands" {
    try utils.fuzz.run({}, parse_any, 0x636c_6921, 4_000);
}
