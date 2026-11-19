//! commonware's `#[should_panic]` tests of `iobuf/buf.rs` and `iobuf/bufs.rs`, as death tests
//! (`utils.death`): each body breaks a precondition that zigware asserts, so the child dies
//! with "reached unreachable code". Not ported: the ones on methods zigware lacks
//! (`copy_to_slice`, `copy_to_bytes`, `put_bytes`, `put` from another `Buf`, `RangeBounds`
//! overflow), the oversized `with_capacity` (`error.OutOfMemory` here), and `owner.rs`
//! (zigware's owner is one allocation header).

const std = @import("std");
const codec = @import("codec");
const death = @import("utils").death;
const iobuf = @import("iobuf.zig");

const IoBuf = iobuf.IoBuf;
const IoBufMut = iobuf.IoBufMut;
const IoBufs = iobuf.IoBufs;
const IoBufsMut = iobuf.IoBufsMut;
const Builder = iobuf.Builder;
const gpa = std.testing.allocator;
const assert_message = "reached unreachable code";

fn expect_assert(
    comptime src: std.builtin.SourceLocation,
    comptime body: fn () anyerror!void,
) !void {
    try death.expect_panic(src, assert_message, body);
}

test "iobuf advance past end panics (test_iobuf_advance_past_end)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var buf = IoBuf.from_static("hello");
            buf.advance(10);
        }
    }.body);
}

test "iobuf slice out of bounds panics (test_iobuf_slice_out_of_bounds)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            const buf = IoBuf.from_static("hello");
            _ = buf.slice(0, 6);
        }
    }.body);
}

test "iobuf inverted slice panics (test_iobuf_slice_inverted_range)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            const buf = IoBuf.from_static("hello");
            _ = buf.slice(3, 1);
        }
    }.body);
}

test "iobuf split_to out of bounds panics (test_iobuf_split_to_out_of_bounds)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var buf = IoBuf.from_static("abc");
            _ = buf.split_to(4);
        }
    }.body);
}

test "iobufmut advance past end panics (test_iobufmut_advance_past_end)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var buf = try IoBufMut.copy_from_slice(gpa, "hello");
            buf.advance(10);
        }
    }.body);
}

test "iobufmut put_slice past capacity panics (test_iobufmut_put_slice_past_capacity)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var buf = try IoBufMut.with_capacity(gpa, 4);
            buf.put_slice("hello");
        }
    }.body);
}

test "iobufmut advance_mut past capacity panics (test_iobufmut_advance_mut_past_capacity)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var buf = try IoBufMut.with_capacity(gpa, 4);
            buf.advance_mut(5);
        }
    }.body);
}

test "iobufs split_to out of bounds panics (test_iobufs_split_to_out_of_bounds)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var bufs = IoBufs.from(IoBuf.from_static("abc"));
            _ = try bufs.split_to(gpa, 4);
        }
    }.body);
}

test "iobufs advance past end panics (test_iobufs_advance_past_end)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var bufs = IoBufs.from(IoBuf.from_static("hel"));
            try bufs.append(gpa, IoBuf.from_static("lo"));
            bufs.advance(10);
        }
    }.body);
}

test "iobufsmut advance past end panics (test_iobufsmut_advance_past_end)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var bufs = IoBufsMut.from(try IoBufMut.copy_from_slice(gpa, "hello"));
            try bufs.append(gpa, try IoBufMut.copy_from_slice(gpa, " world"));
            bufs.advance(20);
        }
    }.body);
}

test "iobufsmut wrong-length copy panics (test_iobufsmut_copy_from_slice_wrong_length)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var bufs = IoBufsMut.from(try IoBufMut.zeroed(gpa, 5));
            bufs.copy_from_slice("hello world");
        }
    }.body);
}

test "iobufsmut put_slice past capacity panics (test_iobufsmut_advance_mut_past_end_pair)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var bufs = IoBufsMut.from(try IoBufMut.with_capacity(gpa, 1));
            try bufs.append(gpa, try IoBufMut.with_capacity(gpa, 1));
            bufs.put_slice("abc");
        }
    }.body);
}

test "iobufsmut set_len past capacity panics (test_iobufsmut_set_len_overflow)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var bufs = IoBufsMut.from(try IoBufMut.with_capacity(gpa, 4));
            try bufs.append(gpa, try IoBufMut.with_capacity(gpa, 4));
            bufs.set_len(9);
        }
    }.body);
}

test "builder put_slice past capacity panics (test_put_slice_exceeding_capacity_panics)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var builder = try Builder.init(gpa, 1);
            builder.put_slice(&.{ 0xfe, 0xfe });
        }
    }.body);
}

test "builder write past full panics (test_write_past_full_panics)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            var builder = try Builder.init(gpa, 1);
            builder.put_slice(&.{0xff});
            builder.put(u8, 0x42);
        }
    }.body);
}

/// Declares 4 inline bytes and writes 2 (commonware's `UnderWriter`).
const UnderWriter = struct {
    pub fn write(_: UnderWriter, writer: *codec.Writer) void {
        writer.write_bytes("ab");
    }
    pub fn read(_: std.mem.Allocator, _: *codec.Reader, _: void) codec.Error!UnderWriter {
        return .{};
    }
    pub fn encode_size(_: UnderWriter) usize {
        return 4;
    }
    pub fn encode_inline_size(_: UnderWriter) usize {
        return 4;
    }
    pub fn write_bufs(_: UnderWriter, _: std.mem.Allocator, builder: *Builder) !void {
        builder.put_slice("ab");
    }
};

test "encode_iobufs rejects a short write (test_encode_iobufs_rejects_short_write)" {
    try expect_assert(@src(), struct {
        fn body() !void {
            _ = try iobuf.encode_iobufs(UnderWriter, gpa, .{});
        }
    }.body);
}
