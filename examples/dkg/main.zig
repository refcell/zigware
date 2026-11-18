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
const setup = @import("setup.zig");

const log = std.log.scoped(.dkg);

const usage =
    \\usage: dkg <command> [options]
    \\
    \\commands:
    \\  setup      generate validator directories and network config
    \\             [--node-dir ./data] [--peers 6] [--committee-size 4] [--base-port 3000]
    \\             [--host 127.0.0.1]
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var err_buffer: [1024]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &err_buffer);
    if (args.len < 2) return fail_usage(&stderr.interface);
    if (std.mem.eql(u8, args[1], "setup")) {
        const options = setup.parse_options(args[2..]) orelse
            return fail_usage(&stderr.interface);
        var out_buffer: [4096]u8 = undefined;
        var stdout = Io.File.stdout().writer(io, &out_buffer);
        setup.run(io, arena, &options, &stdout.interface) catch |err| {
            log.err("setup failed: {t}", .{err});
            return 1;
        };
        try stdout.interface.flush();
        return 0;
    }
    return fail_usage(&stderr.interface);
}

fn fail_usage(stderr: *Io.Writer) !u8 {
    try stderr.writeAll(usage);
    try stderr.flush();
    return 2;
}

test {
    _ = @import("config_test.zig");
    _ = @import("setup_test.zig");
    _ = @import("types_test.zig");
}
