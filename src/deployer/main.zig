//! The `deployer` command (commonware `deployer/src/main.rs`): parses the command line and runs
//! the `aws` command over HTTPS, `ssh`/`scp`, and local processes. Credentials come from the
//! environment or the shared credentials file.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const deployer = @import("deployer");
const cli = deployer.cli;
const aws = deployer.aws;

const log = std.log.scoped(.deployer);

/// `-v` enables debug logs; info and above always print (commonware's tracing levels).
var verbose = false;

pub const std_options: std.Options = .{ .log_level = .debug, .logFn = log_fn };

fn log_fn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (level == .debug and !verbose) return;
    std.log.defaultLog(level, scope, format, args);
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    assert(args.len >= 1);
    var buffer: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &buffer);
    const parsed = switch (cli.parse(args[1..])) {
        .ok => |parsed| parsed,
        .failure => |failure| {
            log.err("invalid arguments: {t}: {s}", .{ failure.kind, failure.argument });
            try stdout.interface.writeAll(cli.usage);
            try stdout.interface.flush();
            return 2;
        },
    };
    verbose = parsed.verbose;
    const command = switch (parsed.command) {
        .help => {
            try stdout.interface.writeAll(cli.usage);
            try stdout.interface.flush();
            return 0;
        },
        .version => {
            try stdout.interface.print("deployer {s}\n", .{cli.version});
            try stdout.interface.flush();
            return 0;
        },
        .none => {
            log.err("no subcommand provided", .{});
            return 1;
        },
        .aws => |command| command,
    };
    return run(init, command);
}

fn run(init: std.process.Init, command: cli.Aws) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const home = init.environ_map.get("HOME") orelse {
        log.err("{s}: HOME is not set", .{aws.commands.failure_message(command)});
        return 1;
    };
    assert(home.len > 0);
    var http: aws.client.HttpTransport = .init(init.gpa, io);
    defer http.deinit();
    var ssh: aws.session.Ssh = .{ .gpa = init.gpa, .io = io };
    var processes: aws.session.Processes = .{ .io = io };
    var session: aws.session.Session = .{
        .io = io,
        .gpa = init.gpa,
        .arena = arena,
        .home = home,
        // `list` and `attach` never sign a request.
        .credentials = .{ .access_key_id = "", .secret_access_key = "" },
        .transport = http.transport(),
        .remote = ssh.remote(),
        .local = processes.local(),
    };
    if (aws.commands.needs_credentials(command)) {
        const loaded = try aws.credentials.load(io, arena, init.environ_map, home);
        session.credentials = loaded orelse {
            const failure: aws.Failure = .no_credentials;
            log.err("{s}: error={f}", .{ aws.commands.failure_message(command), failure });
            return 1;
        };
    }
    aws.commands.run(&session, command) catch |err| {
        const message = aws.commands.failure_message(command);
        if (err == error.Failed) {
            log.err("{s}: error={f}", .{ message, session.failure.? });
        } else {
            log.err("{s}: error={t}", .{ message, err });
        }
        return 1;
    };
    return 0;
}
