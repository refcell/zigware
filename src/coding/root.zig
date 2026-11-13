//! coding: Encode data to enable recovery from a subset of fragments.
//!
//! Zig port of commonware's `commonware-coding` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/coding).
//!
//! A coding scheme turns data into `minimum_shards + extra_shards` shards and a commitment to
//! them. Each participant checks its shard against the commitment, and any `minimum_shards`
//! checked shards decode to the same data.
//!
//! # Scheme
//!
//! Rust's `Scheme` trait is a comptime interface (`assert_scheme`). A scheme `S` provides:
//!
//! - `S.Commitment`: a digest attesting to the shards;
//! - `S.Shard`: a shard for one participant, decoded with cfg `.{ config, maximum_data_bytes }`;
//! - `S.CheckedShard`: a shard checked against a commitment;
//! - `S.Error`: the errors of encoding, checking, and decoding;
//! - `S.max_shard_size(config, data_bytes)`: the largest encoded shard of `data_bytes` bytes;
//! - `S.encode(gpa, config, data, strategy)`: the commitment and `total_shards` shards;
//! - `S.check(config, commitment, index, *shard, strategy)`: a checked shard;
//! - `S.check_many(gpa, config, commitment, shards, out, strategy)`: one result per input,
//!   each equal to `check` of that input;
//! - `S.decode(gpa, config, commitment, checked_shards, strategy)`: the data.
//!
//! ## Guarantees
//!
//! Check agreement: if two honest parties both check their own shards successfully, each
//! accepts the other's shard too. Unique commitments: `encode` is deterministic, and for a
//! given config and data the only commitment `decode` accepts is the one `encode` produced.
//! Decoding with the same commitment and any set (or order) of at least `minimum_shards`
//! checked shards returns the same data or fails; shards checked against a different
//! commitment are rejected.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");

/// Configuration common to all encoding schemes.
///
/// Both counts are non-zero (commonware's `NonZeroU16`). Specifying `extra_shards` rather
/// than a total avoids having to check that `minimum_shards` does not exceed it.
pub const Config = struct {
    /// The minimum number of shards needed to decode the data.
    minimum_shards: u16,
    /// Shards beyond the minimum.
    extra_shards: u16,

    /// Encoded size: two big-endian `NonZeroU16`s.
    pub const fixed_size: usize = 2 * NonZeroU16.fixed_size;

    const NonZeroU16 = codec.NonZero(u16);

    /// The total number of shards a scheme produces under this configuration.
    pub fn total_shards(self: Config) u32 {
        assert(self.minimum_shards > 0 and self.extra_shards > 0);
        const total = @as(u32, self.minimum_shards) + self.extra_shards;
        assert(total <= 2 * @as(u32, std.math.maxInt(u16)));
        return total;
    }

    pub fn write(self: Config, writer: *codec.Writer) void {
        codec.write(NonZeroU16, NonZeroU16.init(self.minimum_shards).?, writer);
        codec.write(NonZeroU16, NonZeroU16.init(self.extra_shards).?, writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: void) codec.Error!Config {
        _ = cfg;
        const minimum = try codec.read(NonZeroU16, gpa, reader);
        const extra = try codec.read(NonZeroU16, gpa, reader);
        assert(minimum.value > 0 and extra.value > 0);
        return .{ .minimum_shards = minimum.value, .extra_shards = extra.value };
    }

    pub fn eql(a: Config, b: Config) bool {
        return a.minimum_shards == b.minimum_shards and a.extra_shards == b.extra_shards;
    }

    /// Orders by `minimum_shards`, then `extra_shards` (the derived Rust `Ord`).
    pub fn order(a: Config, b: Config) std.math.Order {
        const first = std.math.order(a.minimum_shards, b.minimum_shards);
        if (first != .eq) return first;
        return std.math.order(a.extra_shards, b.extra_shards);
    }
};

/// Asserts at compile time that `S` implements the coding scheme interface.
pub fn assert_scheme(comptime S: type) void {
    comptime {
        for ([_][]const u8{
            "Commitment", "Shard", "CheckedShard", "Error",  "max_shard_size",
            "encode",     "check", "check_many",   "decode",
        }) |decl| {
            if (!@hasDecl(S, decl)) @compileError(@typeName(S) ++ " lacks Scheme." ++ decl);
        }
        assert(@hasDecl(S.Commitment, "fixed_size"));
        assert(@hasDecl(S.Shard, "Cfg"));
    }
}

test {
    _ = @import("config_test.zig");
}
