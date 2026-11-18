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
//! and `validator` follow as glue's DKG actor lands (docs/lanes/examples-dkg.md).

const std = @import("std");
const Io = std.Io;
const cli = @import("cli.zig");
const setup = @import("setup.zig");

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
        .bootstrap, .validator => {
            log.err("bootstrap and validator wait on glue.dkg's reshare actor " ++
                "(docs/lanes/examples-dkg.md)", .{});
            return 1;
        },
    }
}

test {
    _ = @import("cli_test.zig");
    _ = @import("config_test.zig");
    _ = @import("setup_test.zig");
    _ = @import("types_test.zig");
}
