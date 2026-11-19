//! `iobuf::iobuf::decode_fixed` (commonware `runtime/src/iobuf/benches`; Criterion names it by
//! module path, module `iobuf` in bench `iobuf`): the cost of
//! an `IoBuf` handle compared to a deep-cloned vector and a borrowed slice, decoding one
//! fixed-size value from a prebuilt payload that each iteration clones or wraps.
//!
//! - `iobuf_native`: an `IoBuf` frozen from `IoBufMut.with_capacity`, cloned (a reference
//!   count) and decoded whole; `_ref` decodes through the clone and advances it.
//! - `iobuf_bytes`: commonware wraps external `Bytes`; zigware's `IoBuf` has no external
//!   reference-counted owner, so these modes wrap the payload with `from_static`, the handle
//!   over memory it does not own. The pair still isolates the owner kind.
//! - `vec_slice`: a deep clone decoded through a slice; `slice`: a borrowed slice of the
//!   payload, the no-copy decode floor.
//!
//! Not ported: `bytes` and `bytes_ref` measure the `bytes` crate, which has no zigware
//! counterpart, and `vec` decodes an owned `Vec<u8>` as a buffer, which here is the same
//! slice decode as `vec_slice`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const codec = @import("codec");
const iobuf = @import("runtime").iobuf;

const IoBuf = iobuf.IoBuf;
const IoBufMut = iobuf.IoBufMut;

const Mode = enum {
    iobuf_bytes,
    iobuf_bytes_ref,
    iobuf_native,
    iobuf_native_ref,
    vec_slice,
    slice,
};

pub fn run(runner: *bench.Runner) !void {
    inline for (.{ 32, 128, 512, 1024, 4096 }) |size| try run_size(runner, size);
}

fn run_size(runner: *bench.Runner, comptime size: usize) !void {
    const gpa = runner.allocator;
    var payload: [size]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @as(u8, @truncate(index)) *% 37 +% 11;
    }
    var native_mut = try IoBufMut.with_capacity(gpa, size);
    native_mut.put_slice(&payload);
    var native = native_mut.freeze();
    defer native.deinit(gpa);
    const borrowed = IoBuf.from_static(&payload);
    for (std.enums.values(Mode)) |mode| {
        const benchmark = bench.Benchmark.init("iobuf::iobuf::decode_fixed")
            .with_param("mode", mode)
            .with_param("size", size);
        var workload: Decode(size) = .{
            .gpa = gpa,
            .mode = mode,
            .payload = &payload,
            .borrowed = borrowed,
            .native = native,
        };
        try runner.run(benchmark, &workload);
    }
}

fn Decode(comptime size: usize) type {
    const Value = [size]u8;
    return struct {
        const Self = @This();

        gpa: Allocator,
        mode: Mode,
        payload: *const Value,
        borrowed: IoBuf,
        native: IoBuf,

        pub fn iter(self: *Self) !Value {
            const value: Value = switch (self.mode) {
                .iobuf_bytes => try self.decode_whole(self.borrowed),
                .iobuf_bytes_ref => try self.decode_ref(self.borrowed),
                .iobuf_native => try self.decode_whole(self.native),
                .iobuf_native_ref => try self.decode_ref(self.native),
                .vec_slice => vec: {
                    const copy = try self.gpa.dupe(u8, self.payload);
                    defer self.gpa.free(copy);
                    std.mem.doNotOptimizeAway(copy.ptr);
                    break :vec try codec.decode(Value, self.gpa, copy);
                },
                .slice => try codec.decode(Value, self.gpa, self.payload),
            };
            assert(value[0] == self.payload[0]);
            return value;
        }

        /// Decode a clone of `source` whole, then drop it.
        fn decode_whole(self: *Self, source: IoBuf) !Value {
            var buf = source.clone();
            defer buf.deinit(self.gpa);
            return codec.decode(Value, self.gpa, buf.bytes());
        }

        /// Decode from a clone of `source`, advancing it past the value, then drop it.
        fn decode_ref(self: *Self, source: IoBuf) !Value {
            var buf = source.clone();
            defer buf.deinit(self.gpa);
            var reader = codec.Reader.init(buf.bytes());
            const value = try codec.read_cfg(Value, self.gpa, &reader, {});
            buf.advance(size - reader.remaining());
            assert(buf.is_empty());
            return value;
        }
    };
}
