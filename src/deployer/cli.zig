//! The `deployer` command line (commonware `deployer/src/main.rs`, a clap `Command`): parsing
//! of `deployer [-v] aws <command> [options]` into a `Command`, with clap's rules for the
//! options it uses: `--name value` or `--name=value`, required options, defaults, value
//! parsing, an option given twice, and `destroy`'s `--config`/`--tag` group (exactly one).

const std = @import("std");
const assert = std.debug.assert;
const aws = @import("aws/mod.zig");

pub const version = @import("aws/services.zig").deployer_version;

pub const Aws = union(enum) {
    create: Rollout,
    update: Rollout,
    authorize: struct { config: []const u8, ip: ?[]const u8 },
    destroy: union(enum) { config: []const u8, tag: []const u8 },
    list,
    clean,
    profile: struct {
        config: []const u8,
        instance: []const u8,
        duration_s: u64,
        binary: []const u8,
    },
    attach: struct { ip: []const u8 },

    /// `create` and `update`: a config and how many instances to handle at once (>= 1).
    pub const Rollout = struct { config: []const u8, concurrency: u64 };
};

pub const Command = union(enum) {
    help,
    version,
    /// `deployer` or `deployer aws` without a subcommand: commonware logs "no subcommand
    /// provided" and fails.
    none,
    aws: Aws,
};

pub const Parsed = struct { verbose: bool, command: Command };

/// Why parsing failed; `argument` names the offending argument or option.
pub const Failure = struct {
    kind: Kind,
    argument: []const u8,

    pub const Kind = enum {
        unexpected_argument,
        missing_required,
        missing_value,
        invalid_value,
        repeated,
        conflict,
    };
};

pub const ParseResult = union(enum) { ok: Parsed, failure: Failure };

const Option = struct {
    name: []const u8,
    value: ?[]const u8 = null,
};

/// The values of a subcommand's options, by name.
fn Options(comptime names: []const []const u8) type {
    return struct {
        const Self = @This();
        values: [names.len]?[]const u8 = @splat(null),

        fn get(self: *const Self, comptime name: []const u8) ?[]const u8 {
            inline for (names, 0..) |candidate, index| {
                if (comptime std.mem.eql(u8, candidate, name)) return self.values[index];
            }
            @compileError("unknown option " ++ name);
        }

        /// Reads `--name value` and `--name=value` options from `args`.
        fn parse(self: *Self, args: []const []const u8) ?Failure {
            var index: usize = 0;
            while (index < args.len) : (index += 1) {
                const arg = args[index];
                if (is_help(arg)) return .{ .kind = .unexpected_argument, .argument = arg };
                if (!std.mem.startsWith(u8, arg, "--")) {
                    return .{ .kind = .unexpected_argument, .argument = arg };
                }
                const body = arg[2..];
                const equals = std.mem.indexOfScalar(u8, body, '=');
                const name = if (equals) |at| body[0..at] else body;
                const value = self.slot(name) orelse {
                    return .{ .kind = .unexpected_argument, .argument = arg };
                };
                if (value.* != null) return .{ .kind = .repeated, .argument = name };
                if (equals) |at| {
                    value.* = body[at + 1 ..];
                } else {
                    // clap does not take a flag-like argument as a value (`-` alone is a value).
                    if (index + 1 == args.len or is_flag(args[index + 1])) {
                        return .{ .kind = .missing_value, .argument = name };
                    }
                    index += 1;
                    value.* = args[index];
                }
            }
            return null;
        }

        fn slot(self: *Self, name: []const u8) ?*?[]const u8 {
            for (names, 0..) |candidate, index| {
                if (std.mem.eql(u8, candidate, name)) return &self.values[index];
            }
            return null;
        }
    };
}

fn is_flag(arg: []const u8) bool {
    return arg.len > 1 and arg[0] == '-';
}

fn is_help(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help");
}

/// Parses `args` (without the program name).
pub fn parse(args: []const []const u8) ParseResult {
    var verbose = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            if (verbose) return .{ .failure = .{ .kind = .repeated, .argument = "verbose" } };
            verbose = true;
        } else if (is_help(arg)) {
            return .{ .ok = .{ .verbose = verbose, .command = .help } };
        } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
            return .{ .ok = .{ .verbose = verbose, .command = .version } };
        } else break;
    }
    if (index == args.len) return .{ .ok = .{ .verbose = verbose, .command = .none } };
    if (!std.mem.eql(u8, args[index], aws.cmd)) {
        return .{ .failure = .{ .kind = .unexpected_argument, .argument = args[index] } };
    }
    const rest = args[index + 1 ..];
    if (rest.len == 0) return .{ .ok = .{ .verbose = verbose, .command = .none } };
    if (is_help(rest[0])) return .{ .ok = .{ .verbose = verbose, .command = .help } };
    return switch (parse_aws(rest[0], rest[1..])) {
        .ok => |command| .{ .ok = .{ .verbose = verbose, .command = .{ .aws = command } } },
        .failure => |failure| .{ .failure = failure },
    };
}

const AwsResult = union(enum) { ok: Aws, failure: Failure };

fn parse_aws(name: []const u8, args: []const []const u8) AwsResult {
    assert(name.len > 0);
    if (std.mem.eql(u8, name, aws.create_cmd)) return rollout(args, .create);
    if (std.mem.eql(u8, name, aws.update_cmd)) return rollout(args, .update);
    if (std.mem.eql(u8, name, aws.authorize_cmd)) return authorize(args);
    if (std.mem.eql(u8, name, aws.destroy_cmd)) return destroy(args);
    if (std.mem.eql(u8, name, aws.profile_cmd)) return profile(args);
    if (std.mem.eql(u8, name, aws.attach_cmd)) return attach(args);
    inline for (.{ .{ aws.list_cmd, Aws.list }, .{ aws.clean_cmd, Aws.clean } }) |entry| {
        if (std.mem.eql(u8, name, entry[0])) {
            if (args.len > 0) return fail(.unexpected_argument, args[0]);
            return .{ .ok = entry[1] };
        }
    }
    return fail(.unexpected_argument, name);
}

fn fail(kind: Failure.Kind, argument: []const u8) AwsResult {
    return .{ .failure = .{ .kind = kind, .argument = argument } };
}

/// Like clap's `RangedU64ValueParser` from `minimum`, which parses with Rust's
/// `u64::from_str`: an optional `+`, then decimal digits (no `_`, unlike `std.fmt.parseInt`).
fn parse_u64(text: []const u8, minimum: u64) ?u64 {
    const digits = if (std.mem.startsWith(u8, text, "+")) text[1..] else text;
    if (digits.len == 0) return null;
    for (digits) |byte| if (!std.ascii.isDigit(byte)) return null;
    const value = std.fmt.parseInt(u64, digits, 10) catch return null;
    assert(digits.len <= text.len);
    return if (value >= minimum) value else null;
}

fn rollout(args: []const []const u8, comptime tag: std.meta.Tag(Aws)) AwsResult {
    var options: Options(&.{ "config", "concurrency" }) = .{};
    if (options.parse(args)) |failure| return .{ .failure = failure };
    const config = options.get("config") orelse return fail(.missing_required, "config");
    if (config.len == 0) return fail(.invalid_value, "config");
    const text = options.get("concurrency") orelse aws.default_concurrency;
    const concurrency = parse_u64(text, 1) orelse return fail(.invalid_value, "concurrency");
    assert(concurrency >= 1);
    const value: Aws.Rollout = .{ .config = config, .concurrency = concurrency };
    return .{ .ok = @unionInit(Aws, @tagName(tag), value) };
}

fn authorize(args: []const []const u8) AwsResult {
    var options: Options(&.{ "config", "ip" }) = .{};
    if (options.parse(args)) |failure| return .{ .failure = failure };
    const config = options.get("config") orelse return fail(.missing_required, "config");
    if (config.len == 0) return fail(.invalid_value, "config");
    return .{ .ok = .{ .authorize = .{ .config = config, .ip = options.get("ip") } } };
}

fn destroy(args: []const []const u8) AwsResult {
    var options: Options(&.{ "config", "tag" }) = .{};
    if (options.parse(args)) |failure| return .{ .failure = failure };
    const config = options.get("config");
    const tag = options.get("tag");
    if (config != null and tag != null) return fail(.conflict, "tag");
    if (config) |path| {
        if (path.len == 0) return fail(.invalid_value, "config");
        return .{ .ok = .{ .destroy = .{ .config = path } } };
    }
    if (tag) |name| return .{ .ok = .{ .destroy = .{ .tag = name } } };
    return fail(.missing_required, "config|tag");
}

fn profile(args: []const []const u8) AwsResult {
    var options: Options(&.{ "config", "instance", "duration", "binary" }) = .{};
    if (options.parse(args)) |failure| return .{ .failure = failure };
    const config = options.get("config") orelse return fail(.missing_required, "config");
    if (config.len == 0) return fail(.invalid_value, "config");
    const instance = options.get("instance") orelse return fail(.missing_required, "instance");
    const binary = options.get("binary") orelse return fail(.missing_required, "binary");
    if (binary.len == 0) return fail(.invalid_value, "binary");
    const text = options.get("duration") orelse "30";
    const duration_s = parse_u64(text, 0) orelse return fail(.invalid_value, "duration");
    return .{ .ok = .{ .profile = .{
        .config = config,
        .instance = instance,
        .duration_s = duration_s,
        .binary = binary,
    } } };
}

fn attach(args: []const []const u8) AwsResult {
    if (args.len == 0) return fail(.missing_required, "ip");
    if (is_flag(args[0])) return fail(.unexpected_argument, args[0]);
    if (args.len > 1) return fail(.unexpected_argument, args[1]);
    return .{ .ok = .{ .attach = .{ .ip = args[0] } } };
}

pub const usage =
    \\Deploy infrastructure across cloud providers.
    \\
    \\Usage: deployer [OPTIONS] [COMMAND]
    \\
    \\Commands:
    \\  aws  Deploy a custom binary (and configuration) to any number of EC2 instances
    \\       across multiple regions. Collect metrics and logs from all instances via a
    \\       private network.
    \\
    \\aws commands:
    \\  create     --config <PATH> [--concurrency <N>]
    \\  update     --config <PATH> [--concurrency <N>]
    \\  authorize  --config <PATH> [--ip <IP>]
    \\  destroy    --config <PATH> | --tag <TAG>
    \\  list
    \\  clean
    \\  profile    --config <PATH> --instance <NAME> --binary <PATH> [--duration <SECONDS>]
    \\  attach     <IP>
    \\
    \\Options:
    \\  -v, --verbose
    \\  -h, --help     Print help
    \\  -V, --version  Print version
    \\
;

test {
    _ = @import("cli_test.zig");
}
