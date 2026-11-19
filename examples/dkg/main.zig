//! Generate and reshare a threshold secret over an epoched log (commonware `examples/dkg`).
//!
//! Committees rotate deterministically: for epoch `E`, the committee starts at offset
//! `E % participants.len()` and takes `committee_size` consecutive participants with
//! wraparound. Genesis carries the epoch-0 `EpochInfo`.
//!
//!     zig build run-dkg -- setup --node-dir ./data --peers 6 --committee-size 4 \
//!         --base-port 3000
//!
//! `setup` creates every `validator-*` directory with node and network config, then prints the
//! `mprocs` commands that run the epoch-0 bootstrap players and the validators. `bootstrap`
//! runs the epoch-0 ceremony; `validator` runs DKG and resharing over epochs. Node commands
//! keep their runtime storage in `<node-dir>/runtime`.

const std = @import("std");
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const cli = @import("cli.zig");
const setup = @import("setup.zig");
const bootstrap = @import("bootstrap.zig");
const validator = @import("validator.zig");

const production = zigware.runtime.production;

const log = std.log.scoped(.dkg);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var out_buffer: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &out_buffer);
    var err_buffer: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &err_buffer);
    const bin = if (args.len > 0) std.fs.path.basename(args[0]) else "dkg";
    const rest = args[@min(args.len, 1)..];
    const outcome = try cli.parse(rest, bin, &stdout.interface, &stderr.interface);
    try stdout.interface.flush();
    try stderr.interface.flush();
    const parsed = switch (outcome) {
        .exit => |status| return status,
        .run => |parsed| parsed,
    };
    switch (parsed.command) {
        .setup => |options| {
            setup.run(io, arena, &options, &stdout.interface) catch |err| {
                log.err("setup failed: {t}", .{err});
                return 1;
            };
            try stdout.interface.flush();
            return 0;
        },
        .bootstrap => |node| {
            var fmt: ui.fmt.Fmt = .{
                .io = io,
                .out = &stdout.interface,
                .ansi = ui.fmt.ansi_enabled(init.environ_map.get("NO_COLOR")),
                .level = parsed.log_level,
            };
            const runtime_dir = try std.fs.path.join(arena, &.{ node.node_dir, "runtime" });
            var runner: production.Runner = undefined;
            try runner.init(init.gpa, .{
                .storage_directory = runtime_dir,
                .subscriber = fmt.subscriber(),
            });
            defer runner.deinit();
            try (try runner.start_context(bootstrap.run, .{ arena, node.node_dir }));
            return 0;
        },
        .validator => |node| {
            var fmt: ui.fmt.Fmt = .{
                .io = io,
                .out = &stdout.interface,
                .ansi = ui.fmt.ansi_enabled(init.environ_map.get("NO_COLOR")),
                .level = parsed.log_level,
            };
            const runtime_dir = try std.fs.path.join(arena, &.{ node.node_dir, "runtime" });
            var runner: production.Runner = undefined;
            try runner.init(init.gpa, .{
                .storage_directory = runtime_dir,
                .subscriber = fmt.subscriber(),
            });
            defer runner.deinit();
            const run_args = .{ arena, node.node_dir, node.state_sync };
            try (try runner.start_context(validator.run, run_args));
            return 0;
        },
    }
}

test {
    _ = @import("application_test.zig");
    _ = @import("bootstrap_test.zig");
    _ = @import("cli_test.zig");
    _ = @import("config_test.zig");
    _ = @import("provider_test.zig");
    _ = @import("setup_test.zig");
    _ = @import("types_test.zig");
    _ = @import("validator_test.zig");
}
