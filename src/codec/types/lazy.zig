//! A value decoded on first use (codec/src/types/lazy.rs).
//!
//! `Lazy(T)` holds either a value or the encoded bytes of one (a view into the input) plus
//! the config to decode them with. `get` decodes once and caches the result. Writing a
//! deferred value copies its bytes unchanged, so re-encoding never pays for decoding.
//! Reading requires a fixed-size `T`: it takes exactly `fixed_size(T)` bytes and defers them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("../buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("../error.zig").Error;
const codec = @import("../codec.zig");

pub fn Lazy(comptime T: type) type {
    return struct {
        const Self = @This();
        const ValueCfg = codec.Cfg(T);

        /// Encoded bytes still to decode, or null when built from a value.
        pending: ?[]const u8,
        pending_cfg: ValueCfg,
        state: State,

        const State = union(enum) { undecoded, decoded: T, invalid };

        pub const Cfg = ValueCfg;
        pub const fixed_size = codec.fixed_size(T);

        /// A lazy value that is already decoded.
        pub fn init(value: T) Self {
            return .{ .pending = null, .pending_cfg = undefined, .state = .{ .decoded = value } };
        }

        /// Defers decoding `bytes` (which must outlive the result) with `cfg`.
        pub fn deferred(bytes: []const u8, cfg: ValueCfg) Self {
            return .{ .pending = bytes, .pending_cfg = cfg, .state = .undecoded };
        }

        /// Decodes on first call and caches the result; null when decoding fails. The value
        /// lives in `self` (commonware returns `Option<&T>` too), so `get` never copies it.
        pub fn get(self: *Self, gpa: Allocator) ?*const T {
            if (self.state == .undecoded) {
                const bytes = self.pending.?;
                // Decode straight into the cache, so a large `T` is not copied through a
                // temporary union.
                self.state = .{ .decoded = undefined };
                self.state.decoded = codec.decode_cfg(T, gpa, bytes, self.pending_cfg) catch {
                    self.state = .invalid;
                    return null;
                };
            }
            assert(self.state != .undecoded);
            return switch (self.state) {
                .decoded => |*value| value,
                .invalid => null,
                .undecoded => unreachable, // Proof: decoded just above.
            };
        }

        /// Decodes without caching; `T` must not allocate.
        fn peek(self: Self) ?T {
            comptime assert(!codec.owns_memory(T));
            return switch (self.state) {
                .decoded => |value| value,
                .invalid => null,
                .undecoded => codec.decode_cfg(
                    T,
                    Allocator.failing,
                    self.pending.?,
                    self.pending_cfg,
                ) catch null,
            };
        }

        pub fn write(self: Self, writer: *Writer) void {
            if (self.pending) |bytes| return writer.write_bytes(bytes);
            codec.write(T, self.state.decoded, writer);
        }

        pub fn encode_size(self: Self) usize {
            if (self.pending) |bytes| return bytes.len;
            return codec.encode_size(T, self.state.decoded);
        }

        pub fn read(_: Allocator, reader: *Reader, cfg: ValueCfg) Error!Self {
            const size = comptime codec.fixed_size(T) orelse
                @compileError("codec: Lazy can only read fixed-size types: " ++ @typeName(T));
            const bytes = try reader.take(size);
            assert(bytes.len == size);
            return deferred(bytes, cfg);
        }

        /// Equal deferred bytes are equal without decoding (compare values deferred with the
        /// same config); otherwise compares decoded values, with failures equal to each other.
        pub fn eql(a: Self, b: Self) bool {
            if (a.pending != null and b.pending != null) {
                if (std.mem.eql(u8, a.pending.?, b.pending.?)) return true;
            }
            return order(a, b) == .eq;
        }

        /// Rust's `Option<&T>` order: a value that fails to decode sorts first.
        pub fn order(a: Self, b: Self) std.math.Order {
            return codec.order(?T, a.peek(), b.peek());
        }

        /// Frees a decoded value that owns memory.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.state == .decoded) codec.free(T, gpa, self.state.decoded);
            self.* = undefined;
        }
    };
}

const testing = std.testing;
const Bytes = @import("bytes.zig").Bytes;
const test_gpa = testing.allocator;

/// A byte that is always at most 100, like commonware's test `Small`.
const Small = struct {
    value: u8,
    pub const fixed_size = 1;

    pub fn write(self: Small, writer: *Writer) void {
        writer.write_byte(self.value);
    }

    pub fn read(_: Allocator, reader: *Reader, _: void) Error!Small {
        const byte = try reader.read_byte();
        if (byte > 100) return reader.invalid("Small", "value > 100");
        return .{ .value = byte };
    }

    pub fn order(a: Small, b: Small) std.math.Order {
        return std.math.order(a.value, b.value);
    }
};

test "lazy matches direct encoding and decoding for every byte" {
    for (0..256) |raw| {
        const byte: u8 = @intCast(raw);
        const encoded = [_]u8{byte};
        const direct: ?Small = codec.decode(Small, test_gpa, &encoded) catch null;
        var via_lazy = try codec.decode(Lazy(Small), test_gpa, &encoded);
        const lazy_value = via_lazy.get(test_gpa);
        try testing.expectEqual(direct, if (lazy_value) |value| value.* else null);
        // A second `get` returns the cached value in place.
        try testing.expectEqual(lazy_value, via_lazy.get(test_gpa));
        if (direct) |small| {
            const from_new = Lazy(Small).init(small);
            try testing.expect(from_new.eql(Lazy(Small).deferred(&encoded, {})));
            var out: [1]u8 = undefined;
            const new_bytes = codec.encode_to(Lazy(Small), from_new, &out);
            try testing.expectEqualSlices(u8, &encoded, new_bytes);
            const deferred_bytes = codec.encode_to(Lazy(Small), via_lazy, &out);
            try testing.expectEqualSlices(u8, &encoded, deferred_bytes);
        }
    }
    try testing.expectError(error.EndOfBuffer, codec.decode(Lazy(Small), test_gpa, &.{}));
}

test "lazy order and equality match the values" {
    for (0..256) |raw_a| {
        for ([_]u8{ 0, 7, 100, 101, 255 }) |b| {
            const a: u8 = @intCast(raw_a);
            const direct_a: ?Small = codec.decode(Small, test_gpa, &.{a}) catch null;
            const direct_b: ?Small = codec.decode(Small, test_gpa, &.{b}) catch null;
            const lazy_a = Lazy(Small).deferred(&.{a}, {});
            const lazy_b = Lazy(Small).deferred(&.{b}, {});
            const direct_order = codec.order(?Small, direct_a, direct_b);
            try testing.expectEqual(direct_order, lazy_a.order(lazy_b));
            try testing.expectEqual(direct_order == .eq, lazy_a.eql(lazy_b));
        }
    }
}

test "lazy equal bytes skip decoding" {
    const a = Lazy(Small).deferred(&.{7}, {});
    const b = Lazy(Small).deferred(&.{7}, {});
    try testing.expect(a.eql(b));
    try testing.expect(a.state == .undecoded and b.state == .undecoded);
    try testing.expect(!a.eql(Lazy(Small).deferred(&.{8}, {})));
}

test "lazy elements decode as views of the input" {
    var values: [64]Lazy(Small) = undefined;
    for (&values, 0..) |*value, index| value.* = .init(.{ .value = @intCast(index) });
    const source = try codec.encode([]const Lazy(Small), test_gpa, &values);
    defer test_gpa.free(source);
    const decoded = try codec.decode_range([]const Lazy(Small), test_gpa, source, .full());
    defer test_gpa.free(decoded);
    const start = @intFromPtr(source.ptr);
    for (decoded, values) |item, value| {
        try testing.expect(item.eql(value));
        const address = @intFromPtr(item.pending.?.ptr);
        try testing.expect(address >= start and address < start + source.len);
    }
}

test "lazy get shares retained bytes" {
    const encoded = try codec.encode(Bytes, test_gpa, .init("hello"));
    defer test_gpa.free(encoded);
    var lazy = Lazy(Bytes).deferred(encoded, .full());
    const value = lazy.get(test_gpa).?;
    try testing.expectEqualStrings("hello", value.data);
    try testing.expectEqual(@intFromPtr(encoded.ptr) + 1, @intFromPtr(value.data.ptr));

    const Fields = struct { Bytes, u32, Bytes };
    const fields = try codec.encode(Fields, test_gpa, .{ .init("hello"), 7, .init("world") });
    defer test_gpa.free(fields);
    var lazy_fields = Lazy(Fields).deferred(fields, .{ .full(), {}, .full() });
    const first, const scalar, const second = lazy_fields.get(test_gpa).?.*;
    try testing.expectEqualStrings("hello", first.data);
    try testing.expectEqual(@as(u32, 7), scalar);
    try testing.expectEqual(@intFromPtr(fields.ptr) + 11, @intFromPtr(second.data.ptr));

    // Trailing bytes fail decoding.
    const extra = try std.mem.concat(test_gpa, u8, &.{ encoded, &.{0} });
    defer test_gpa.free(extra);
    var failing = Lazy(Bytes).deferred(extra, .full());
    try testing.expectEqual(@as(?*const Bytes, null), failing.get(test_gpa));
}
