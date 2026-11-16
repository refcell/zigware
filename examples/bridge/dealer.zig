//! Generate a threshold secret for one bridge network (commonware `examples/bridge`'s
//! `dealer` binary).
//!
//! ```sh
//! zig build run-bridge-dealer -- --seed 1 --participants 1,2,3,4
//! ```
//!
//! Deals a BLS12-381 (MinSig) threshold polynomial from `rand`'s `StdRng::seed_from_u64(seed)`
//! and prints the public polynomial, its constant term (the network's identity), and each
//! participant's share, byte for byte as commonware prints them. Participants are ed25519
//! keys from `u64` seeds, and shares go to them in public-key order.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");

const codec = zigware.codec;
const ed25519 = zigware.cryptography.ed25519;
const bls12381 = zigware.cryptography.bls12381;
const MinSig = bls12381.primitives.MinSig;
const deal_anonymous = bls12381.dkg.feldman_desmedt.deal_anonymous;

pub const about = "generate threshold secret";

pub const Clap = ui.clap.Parser(.{ .about = about, .args = &.{
    .{ .long = "seed", .required = true, .integer = true },
    .{
        .long = "participants",
        .required = true,
        .delimited = true,
        .integer = true,
        .help = "All participants (arbiter and contributors)",
    },
} });

/// Prints the dealing for `participants` (key seeds, as given) from RNG seed `seed`.
pub fn deal(gpa: Allocator, out: *Io.Writer, seed: u64, participants: []const u64) !void {
    assert(participants.len > 0);
    const Validator = struct { seed: u64, key: ed25519.PublicKey };
    const validators = try gpa.alloc(Validator, participants.len);
    defer gpa.free(validators);
    for (validators, participants) |*validator, participant| {
        validator.* = .{
            .seed = participant,
            .key = ed25519.PrivateKey.from_seed(participant).public_key(),
        };
    }
    // `sort_by` is stable: equal keys (repeated seeds) keep their order.
    std.sort.insertion(Validator, validators, {}, struct {
        fn less(_: void, a: Validator, b: Validator) bool {
            return a.key.order(b.key) == .lt;
        }
    }.less);
    var rng = zigware.utils.rng.TestRng.init(seed);
    const n: u32 = @intCast(participants.len);
    var dealing = try deal_anonymous(MinSig, zigware.utils.N3f1, gpa, &rng, .non_zero_counter, n);
    defer dealing.deinit(gpa);
    const polynomial = try codec.encode(@TypeOf(dealing.sharing), gpa, dealing.sharing);
    defer gpa.free(polynomial);
    try out.print("polynomial: {x}\n", .{polynomial});
    try out.print("public: {f}\n", .{dealing.sharing.public()});
    for (dealing.shares) |share| {
        const index = share.index.get();
        assert(index < validators.len);
        var bytes: [64]u8 = undefined;
        var writer: codec.Writer = .init(&bytes);
        share.write(&writer);
        try out.print("share (index={d} validator={d}): {x}\n", .{
            index,
            validators[index].seed,
            writer.written(),
        });
    }
}

/// Runs the dealer on `args` (without argv[0]); returns the exit status.
pub fn run(
    gpa: Allocator,
    args: []const []const u8,
    bin_name: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    const values = switch (try Clap.parse(args, bin_name, stderr)) {
        .help => {
            try Clap.write_help(stdout, bin_name);
            return 0;
        },
        .usage_error => return 2,
        .run => |values| values,
    };
    // Proof: clap checked both values.
    const seed = ui.rust.parse_unsigned(u64, values[0].?) catch unreachable;
    var participants: std.ArrayList(u64) = .empty;
    defer participants.deinit(gpa);
    var pieces = std.mem.splitScalar(u8, values[1].?, ',');
    while (pieces.next()) |piece| {
        try participants.append(gpa, ui.rust.parse_unsigned(u64, piece) catch unreachable);
    }
    assert(participants.items.len > 0);
    try deal(gpa, stdout, seed, participants.items);
    return 0;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buffer);
    defer stdout_writer.interface.flush() catch {};
    defer stderr_writer.interface.flush() catch {};
    const bin_name = if (args.len > 0) std.fs.path.basename(args[0]) else "dealer";
    const given = args[@min(args.len, 1)..];
    return run(init.gpa, given, bin_name, &stdout_writer.interface, &stderr_writer.interface);
}

test {
    _ = @import("bridge_test.zig");
    _ = @import("lib.zig");
}
