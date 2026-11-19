//! commonware `coding/src/reed_solomon.rs`'s `#[should_panic]` tests, as death tests
//! (`utils.death.expect_panic`): invalid encode parameters and `max_shard_size` limits.

const std = @import("std");
const death = @import("utils").death;
const mod = @import("mod.zig");
const t = @import("tests.zig");

// commonware `test_invalid_total` ("assertion failed: total > min").
test "reed solomon encode rejects total at most min" {
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            const data = "Test parameter validation";
            var encoding = try mod.encode(t.Sha256, t.gpa, 3, 3, data, t.seq);
            encoding.deinit(t.gpa);
        }
    }.body);
}

// commonware `test_invalid_min` ("assertion failed: min > 0").
test "reed solomon encode rejects zero min" {
    try death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            const data = "Test parameter validation";
            var encoding = try mod.encode(t.Sha256, t.gpa, 5, 0, data, t.seq);
            encoding.deinit(t.gpa);
        }
    }.body);
}

// commonware `test_max_shard_size_unsupported_counts`: with 16385 original shards the backend
// supports at most 32768 recovery shards.
test "reed solomon max shard size rejects unsupported counts" {
    try death.expect_panic(@src(), "backend must support the shard counts", struct {
        fn body() !void {
            const config: t.Config = .{ .minimum_shards = 16385, .extra_shards = 32769 };
            std.mem.doNotOptimizeAway(t.RS.max_shard_size(config, 0));
        }
    }.body);
}

// commonware `test_max_shard_size_too_many_shards`: 65535 original shards and one recovery
// shard exceed `u16::MAX` in total.
test "reed solomon max shard size rejects too many shards" {
    try death.expect_panic(@src(), "total shards must fit in u16", struct {
        fn body() !void {
            const config: t.Config = .{ .minimum_shards = std.math.maxInt(u16), .extra_shards = 1 };
            std.mem.doNotOptimizeAway(t.RS.max_shard_size(config, 0));
        }
    }.body);
}

// commonware `test_max_shard_size_data_beyond_prefix`: one byte above `u32::MAX` does not fit
// the payload's length prefix.
test "reed solomon max shard size rejects data beyond the prefix" {
    try death.expect_panic(@src(), "data must fit the u32 length prefix", struct {
        fn body() !void {
            const config: t.Config = .{ .minimum_shards = 2, .extra_shards = 1 };
            const max: usize = std.math.maxInt(u32);
            std.mem.doNotOptimizeAway(t.RS.max_shard_size(config, max + 1));
        }
    }.body);
}

// commonware `test_max_shard_size_shard_beyond_prefix`: a single original shard of the
// largest payload is too wide for its length prefix.
test "reed solomon max shard size rejects a shard beyond the prefix" {
    try death.expect_panic(@src(), "len must fit the u32 length prefix", struct {
        fn body() !void {
            const config: t.Config = .{ .minimum_shards = 1, .extra_shards = 1 };
            const max: usize = std.math.maxInt(u32);
            std.mem.doNotOptimizeAway(t.RS.max_shard_size(config, max));
        }
    }.body);
}
