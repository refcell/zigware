//! Tests of `IoBuf` and `IoBufMut` (commonware `iobuf::buf::tests`). No counterpart: the
//! owner-word and descriptor-promotion tests (zigware's owner is one allocation header), the
//! `Bytes`, `BytesMut`, and `Vec` conversions, auto traits, and the should_panic tests (Zig
//! asserts and cannot catch a panic).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const conformance = @import("conformance");
const iobuf = @import("iobuf.zig");

const IoBuf = iobuf.IoBuf;
const IoBufMut = iobuf.IoBufMut;
const gpa = testing.allocator;

fn frozen(source: []const u8) !IoBuf {
    return IoBuf.copy_from_slice(gpa, source);
}

test "iobuf core behaviors (test_iobuf_core_behaviors)" {
    // Clone stays zero-copy.
    const ones: [1000]u8 = @splat(1);
    var first = try frozen(&ones);
    defer first.deinit(gpa);
    var second = first.clone();
    defer second.deinit(gpa);
    try testing.expectEqual(first.ptr, second.ptr);
    // copy_from_slice owns a copy; an empty copy holds nothing.
    var copied = try frozen(&.{ 1, 2, 3, 4, 5 });
    defer copied.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, copied.bytes());
    var empty = try frozen(&.{});
    try testing.expect(empty.is_empty() and empty.owner == null);
    empty.deinit(gpa);
    // Equality compares bytes, whatever backs them.
    var hello = try frozen("hello");
    defer hello.deinit(gpa);
    try testing.expect(hello.eql(.from_static("hello")));
    try testing.expect(!hello.eql(.from_static("world")));
    // advance keeps len in sync.
    var buf = try frozen("hello world");
    defer buf.deinit(gpa);
    buf.advance(6);
    try testing.expectEqualStrings("world", buf.bytes());
    // Slicing is zero-copy.
    const source: IoBuf = .from_static("hello world");
    try testing.expectEqualStrings("hello", source.slice(0, 5).bytes());
    try testing.expectEqualStrings("world", source.slice(6, 11).bytes());
    try testing.expectEqualStrings("lo wo", source.slice(3, 8).bytes());
    try testing.expect(source.slice(5, 5).is_empty());
}

test "slices share the allocation and keep it alive" {
    var buf = try frozen("abcdefgh");
    var head = buf.slice(0, 3);
    defer head.deinit(gpa);
    try testing.expectEqual(buf.ptr, head.ptr);
    buf.deinit(gpa);
    // The slice outlives the handle it came from (the leak checker verifies the release).
    try testing.expectEqualStrings("abc", head.bytes());
}

test "iobuf codec roundtrip (test_iobuf_codec_roundtrip)" {
    const cfg: IoBuf.Cfg = .inclusive(0, 1024);
    var large_bytes: [10000]u8 = @splat(42);
    const values = [_][]const u8{ "hello world", "", &large_bytes };
    for (values) |value| {
        const encoded = try codec.encode(IoBuf, gpa, .from_static(value));
        defer gpa.free(encoded);
        const range: IoBuf.Cfg = if (value.len > 1024) .inclusive(0, 20000) else cfg;
        var decoded = try codec.decode_cfg(IoBuf, gpa, encoded, range);
        defer decoded.deinit(gpa);
        try testing.expectEqualSlices(u8, value, decoded.bytes());
    }
    // A length past the input ends the buffer.
    const truncated = [_]u8{ 4, 'x', 'y' };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(IoBuf, gpa, &truncated, cfg));
    // A length past the range is rejected.
    const long = [_]u8{ 3, 'x', 'y', 'z' };
    const short: IoBuf.Cfg = .inclusive(0, 2);
    try testing.expectError(error.InvalidLength, codec.decode_cfg(IoBuf, gpa, &long, short));
}

test "decoding from an iobuf is zero-copy (test_iobuf_read_cfg_zero_copy_from_iobuf_source)" {
    const payload: [100]u8 = @splat(7);
    const encoded = try codec.encode(IoBuf, gpa, .from_static(&payload));
    defer gpa.free(encoded);
    var source = try frozen(encoded);
    defer source.deinit(gpa);
    const payload_ptr = source.ptr + (encoded.len - payload.len);
    var decoded = try IoBuf.take_encoded(&source, .inclusive(0, 1024));
    defer decoded.deinit(gpa);
    try testing.expectEqual(payload_ptr, decoded.ptr);
    try testing.expectEqualSlices(u8, &payload, decoded.bytes());
    try testing.expect(source.is_empty());
    // A truncated source is left unchanged.
    var short = try frozen(encoded[0..50]);
    defer short.deinit(gpa);
    const result = IoBuf.take_encoded(&short, .inclusive(0, 1024));
    try testing.expectError(error.EndOfBuffer, result);
    try testing.expectEqual(@as(usize, 50), short.len);
}

test "try_into_mut of empty and static views (test_iobuf_try_into_mut_empty_and_static)" {
    var empty: IoBuf = .empty;
    const converted = empty.try_into_mut().?;
    try testing.expect(converted.is_empty() and converted.capacity == 0);
    var static: IoBuf = .from_static("static");
    try testing.expect(static.try_into_mut() == null);
    try testing.expectEqualStrings("static", static.bytes());
    var empty_static: IoBuf = .from_static("");
    try testing.expect(empty_static.try_into_mut() != null);
}

test "split_to matches across backings (test_iobuf_split_to_consistent_across_backings)" {
    var native_mut: IoBufMut = try .with_capacity(gpa, 256);
    native_mut.put_slice("hello world");
    var native = native_mut.freeze();
    defer native.deinit(gpa);
    var static: IoBuf = .from_static("hello world");
    for ([_]usize{ 0, 5, 6 }) |at| {
        var native_prefix = native.split_to(at);
        defer native_prefix.deinit(gpa);
        const static_prefix = static.split_to(at);
        try testing.expect(native_prefix.eql(static_prefix));
        try testing.expect(native.eql(static));
    }
    try testing.expect(native.is_empty() and static.is_empty());
    try testing.expect(native.owner == null);
}

test "iobufmut core behaviors (test_iobufmut_core_behaviors)" {
    var buf: IoBufMut = try .with_capacity(gpa, 100);
    try testing.expectEqual(@as(usize, 100), buf.capacity);
    try testing.expect(buf.is_empty());
    buf.put_slice("hello");
    buf.put_slice(" world");
    try testing.expectEqualStrings("hello world", buf.bytes());
    var hello = buf.freeze();
    defer hello.deinit(gpa);
    try testing.expectEqualStrings("hello world", hello.bytes());
    var zeroed: IoBufMut = try .zeroed(gpa, 10);
    const zeros: [10]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zeros, zeroed.bytes());
    zeroed.truncate(5);
    @memcpy(zeroed.bytes(), "hello");
    var frozen_zeroed = zeroed.freeze();
    defer frozen_zeroed.deinit(gpa);
    try testing.expectEqualStrings("hello", frozen_zeroed.bytes());
}

test "freeze after advance recovers capacity (test_iobufmut_freeze_after_advance...)" {
    var buf: IoBufMut = try .with_capacity(gpa, 16);
    buf.put_slice("abcdefghijklmnop");
    buf.advance(3);
    try testing.expectEqualStrings("defghijklmnop", buf.bytes());
    try testing.expectEqual(@as(usize, 13), buf.capacity);
    var view = buf.freeze();
    var recovered = view.try_into_mut().?;
    defer recovered.deinit();
    try testing.expectEqualStrings("defghijklmnop", recovered.bytes());
    try testing.expectEqual(@as(usize, 13), recovered.capacity);
}

test "writes after a partial advance append at the tail" {
    var buf: IoBufMut = try .with_capacity(gpa, 8);
    defer buf.deinit();
    buf.put_slice("abcd");
    buf.advance(2);
    buf.put_slice("ef");
    try testing.expectEqualStrings("cdef", buf.bytes());
    try testing.expectEqual(@as(usize, 6), buf.capacity);
    // spare and advance_mut write in place.
    @memcpy(buf.spare()[0..2], "gh");
    buf.advance_mut(2);
    try testing.expectEqualStrings("cdefgh", buf.bytes());
    buf.clear();
    try testing.expectEqual(@as(usize, 6), buf.capacity);
}

test "recovering a mutable buffer (test_iobufmut_from_iobuf)" {
    // A unique buffer comes back without copying.
    var unique: IoBufMut = try .with_capacity(gpa, 4);
    unique.put_slice("data");
    const unique_ptr = unique.ptr;
    var unique_view = unique.freeze();
    var recovered = try IoBufMut.from_iobuf(gpa, &unique_view);
    try testing.expectEqual(unique_ptr, recovered.ptr);
    recovered.deinit();
    // A shared buffer is copied.
    var shared = try frozen("copy");
    var other = shared.clone();
    defer other.deinit(gpa);
    var copied = try IoBufMut.from_iobuf(gpa, &shared);
    defer copied.deinit();
    try testing.expectEqualStrings("copy", copied.bytes());
    try testing.expect(copied.ptr != other.ptr);
    // Once transient slices are gone, recovery keeps the whole buffer and capacity.
    var mirror: IoBufMut = try .with_capacity(gpa, 8);
    mirror.put_slice("abcdefgh");
    const mirror_ptr = mirror.ptr;
    var view = mirror.freeze();
    var head = view.slice(0, 3);
    var tail = view.slice(5, 8);
    try testing.expect(view.try_into_mut() == null);
    head.deinit(gpa);
    tail.deinit(gpa);
    var again = view.try_into_mut().?;
    defer again.deinit();
    try testing.expectEqual(mirror_ptr, again.ptr);
    try testing.expectEqualStrings("abcdefgh", again.bytes());
    try testing.expectEqual(@as(usize, 8), again.capacity);
}

test "aligned buffers (test_iobuf_aligned_public_paths)" {
    var buf: IoBufMut = try .with_alignment(gpa, 8, .@"64");
    try testing.expect(buf.is_empty() and buf.capacity == 8);
    try testing.expect(std.mem.Alignment.@"64".check(@intFromPtr(buf.ptr)));
    buf.put_slice("abcdefgh");
    buf.advance(2);
    try testing.expectEqualStrings("cdefgh", buf.bytes());
    buf.clear();
    buf.put_slice("wxyz");
    var aligned = buf.freeze();
    defer aligned.deinit(gpa);
    var head = aligned.slice(0, 2);
    try testing.expectEqualStrings("wx", head.bytes());
    head.deinit(gpa);
    var split = aligned.clone();
    var prefix = split.split_to(2);
    try testing.expectEqualStrings("wx", prefix.bytes());
    try testing.expectEqualStrings("yz", split.bytes());
    prefix.deinit(gpa);
    split.deinit(gpa);
    var zeroed: IoBufMut = try .zeroed_with_alignment(gpa, 4, .@"64");
    @memcpy(zeroed.bytes(), "pqrs");
    var unique = zeroed.freeze();
    var recovered = unique.try_into_mut().?;
    defer recovered.deinit();
    try testing.expectEqualStrings("pqrs", recovered.bytes());
    try testing.expect(std.mem.Alignment.@"64".check(@intFromPtr(recovered.ptr)));
    // Zero-length aligned buffers hold nothing.
    var nothing: IoBufMut = try .zeroed_with_alignment(gpa, 0, .fromByteUnits(4096));
    try testing.expect(nothing.owner == null);
    nothing.deinit();
}

test "views move between threads" {
    var buf = try frozen("shared across threads");
    defer buf.deinit(gpa);
    const Worker = struct {
        fn run(view: IoBuf) void {
            var owned = view;
            for (0..1000) |_| {
                var copy = owned.clone();
                copy.deinit(std.heap.page_allocator);
            }
            owned.deinit(std.heap.page_allocator);
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{buf.clone()});
    for (threads) |thread| thread.join();
    var only = buf.try_into_mut().?;
    buf = only.freeze();
}

/// `CodecConformance<IoBuf>`: commonware's `Arbitrary` (an `arbitrary_len::<u8>` length, then
/// up to that many bytes from `arbitrary_iter`) encoded.
const IoBufConformance = struct {
    fn generate(
        arena: std.mem.Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error![]const u8 {
        const len = u.byte_size();
        var data: std.ArrayList(u8) = .empty;
        while (data.items.len < len and u.keep_going()) try data.append(arena, u.int(u8));
        return data.items;
    }

    pub fn commit(allocator: std.mem.Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const data = try codec.arbitrary.generate([]const u8, generate, arena.allocator(), seed);
        return codec.encode(IoBuf, allocator, .from_static(data));
    }
};

test "iobuf conformance: CodecConformance<IoBuf>" {
    try conformance.verify(
        IoBufConformance,
        std.heap.smp_allocator,
        "commonware_runtime::iobuf::buf::tests::conformance::CodecConformance<IoBuf>",
        conformance.default_cases,
        @embedFile("conformance.toml"),
    );
}

// IoBufs (commonware `iobuf::bufs::tests`). No counterpart: the representation tests (zigware
// keeps up to three chunks inline and spills to a list, which it then keeps), `IoBufsMut`,
// `Builder`, and `encode_iobufs` (the codec writes one buffer).

const IoBufs = iobuf.IoBufs;

/// An `IoBufs` of copies of `parts`, in order.
fn bufs_of(parts: []const []const u8) !IoBufs {
    var bufs: IoBufs = .empty;
    errdefer bufs.deinit(gpa);
    for (parts) |part| {
        var buf = try frozen(part);
        bufs.append(gpa, buf) catch |err| {
            buf.deinit(gpa);
            return err;
        };
    }
    return bufs;
}

fn expect_coalesced(bufs: *IoBufs, expected: []const u8) !void {
    var whole = try bufs.coalesce(gpa);
    defer whole.deinit(gpa);
    try testing.expectEqualStrings(expected, whole.bytes());
}

test "iobufs chunk count and chunk_at (test_iobufs_chunk_count, test_iobufs_chunk_at)" {
    const chunks = [_][]const u8{ "ab", "cd", "ef", "gh", "ij" };
    for (0..chunks.len + 1) |count| {
        var bufs = try bufs_of(chunks[0..count]);
        defer bufs.deinit(gpa);
        try testing.expectEqual(count, bufs.chunk_count());
        for (chunks[0..count], 0..) |chunk, index| {
            try testing.expectEqualStrings(chunk, bufs.chunk_at(index).?);
        }
        try testing.expect(bufs.chunk_at(count) == null);
        try testing.expect(bufs.chunk_at(std.math.maxInt(usize)) == null);
        try testing.expectEqual(count * 2, bufs.len());
        if (count > 0) {
            bufs.advance(1);
            try testing.expectEqualStrings("b", bufs.chunk_at(0).?);
            bufs.advance(1);
            if (count > 1) {
                try testing.expectEqualStrings(chunks[1], bufs.chunk_at(0).?);
            } else {
                try testing.expect(bufs.chunk_at(0) == null and bufs.is_empty());
            }
        }
    }
}

test "iobufs drop empty buffers and advance across chunks (test_iobufs_advance_*)" {
    var bufs = try bufs_of(&.{ "hello", "", " ", "world" });
    defer bufs.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), bufs.chunk_count());
    bufs.advance(5);
    try testing.expectEqual(@as(usize, 6), bufs.len());
    try testing.expectEqualStrings(" ", bufs.chunk_at(0).?);
    bufs.advance(4);
    try testing.expectEqualStrings("ld", bufs.chunk_at(0).?);
    try testing.expect(bufs.as_single() != null);
    bufs.advance(2);
    try testing.expect(bufs.is_empty());
}

test "iobufs coalesce shapes (test_iobufs_coalesce_shapes)" {
    // One chunk coalesces without copying.
    var single = try bufs_of(&.{"12345"});
    const original_ptr = single.as_single().?.ptr;
    var coalesced = try single.coalesce(gpa);
    try testing.expectEqual(original_ptr, coalesced.ptr);
    coalesced.deinit(gpa);
    var pair = try bufs_of(&.{ "hello", " world" });
    try expect_coalesced(&pair, "hello world");
    var advanced = try bufs_of(&.{ "hello", " world" });
    advanced.advance(3);
    try expect_coalesced(&advanced, "lo world");
    var nothing: IoBufs = .empty;
    try expect_coalesced(&nothing, "");
    var four = try bufs_of(&.{ "ab", "cd", "ef", "gh" });
    try expect_coalesced(&four, "abcdefgh");
}

test "iobufs prepend and append keep order past the inline chunks" {
    var bufs: IoBufs = .empty;
    defer bufs.deinit(gpa);
    const order = [_][]const u8{ "c", "d", "b", "e", "a", "f" };
    for (order, 0..) |part, index| {
        const buf: IoBuf = .from_static(part);
        if (index % 2 == 0) try bufs.prepend(gpa, buf) else try bufs.append(gpa, buf);
    }
    // c; c d; b c d; b c d e; a b c d e; a b c d e f.
    var out: [6]u8 = undefined;
    bufs.copy_to(&out);
    try testing.expectEqualStrings("abcdef", &out);
    var slices: [6][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 6), bufs.slices(&slices).len);
}

test "iobufs split positions (test_iobufs_split_positions)" {
    var parts: [9][2]u8 = undefined;
    for (&parts, 0..) |*part, byte| part.* = @splat(@intCast(byte));
    for (1..10) |count| {
        for (0..count) |rotation| {
            var expected: [18]u8 = undefined;
            var views: [9][]const u8 = undefined;
            for (0..count) |index| {
                views[index] = &parts[(index + rotation) % count];
                @memcpy(expected[index * 2 ..][0..2], views[index]);
            }
            for (0..2 * count + 1) |at| {
                var bufs = try bufs_of(views[0..count]);
                // Rotate a spilled list's front forward first, as a drained deque would.
                var prefix = try bufs.split_to(gpa, at);
                for ([_]*IoBufs{ &prefix, &bufs }) |side| {
                    for (side.chunks()) |chunk| try testing.expect(!chunk.is_empty());
                }
                try expect_coalesced(&prefix, expected[0..at]);
                try expect_coalesced(&bufs, expected[at .. 2 * count]);
            }
        }
    }
}

/// Random operations on an `IoBufs` match the same operations on a flat byte string
/// (commonware `test_iobufs_matches_bytes_chain`).
fn fuzz_iobufs(_: void, smith: *std.testing.Smith) anyerror!void {
    var bufs: IoBufs = .empty;
    defer bufs.deinit(gpa);
    var model: std.ArrayList(u8) = .empty;
    defer model.deinit(gpa);
    var next_byte: u8 = 0;
    for (0..64) |_| {
        switch (smith.valueRangeAtMost(u8, 0, 4)) {
            0, 1 => |kind| {
                var part: [16]u8 = undefined;
                const size = smith.valueRangeAtMost(u8, 0, part.len);
                for (part[0..size]) |*byte| {
                    byte.* = next_byte;
                    next_byte +%= 1;
                }
                var buf = try frozen(part[0..size]);
                if (kind == 0) {
                    try bufs.append(gpa, buf);
                    try model.appendSlice(gpa, part[0..size]);
                } else {
                    try bufs.prepend(gpa, buf);
                    try model.insertSlice(gpa, 0, part[0..size]);
                }
                if (size == 0) buf.deinit(gpa);
            },
            2 => {
                const count = smith.valueRangeAtMost(u32, 0, @intCast(model.items.len));
                bufs.advance(count);
                model.replaceRangeAssumeCapacity(0, count, &.{});
            },
            3 => {
                const at = smith.valueRangeAtMost(u32, 0, @intCast(model.items.len));
                var prefix = try bufs.split_to(gpa, at);
                defer prefix.deinit(gpa);
                try testing.expectEqual(at, prefix.len());
                var out: [1024]u8 = undefined;
                prefix.copy_to(out[0..at]);
                try testing.expectEqualSlices(u8, model.items[0..at], out[0..at]);
                model.replaceRangeAssumeCapacity(0, at, &.{});
            },
            else => {
                var whole = try bufs.coalesce(gpa);
                bufs = .from(whole.clone());
                defer whole.deinit(gpa);
                try testing.expectEqualSlices(u8, model.items, whole.bytes());
            },
        }
        try testing.expectEqual(model.items.len, bufs.len());
        var index: usize = 0;
        for (bufs.chunks()) |chunk| {
            try testing.expect(!chunk.is_empty());
            try testing.expectEqualSlices(u8, model.items[index..][0..chunk.len], chunk.bytes());
            index += chunk.len;
        }
    }
}

test "iobufs match a flat byte string (fuzz)" {
    const build_options = @import("build_options");
    var prng = std.Random.DefaultPrng.init(0x696f_6275_6673 ^ build_options.fuzz_seed);
    var input: [256]u8 = undefined;
    const total: u64 = @as(u64, 500) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        prng.random().bytes(&input);
        var smith: std.testing.Smith = .{ .in = &input };
        fuzz_iobufs({}, &smith) catch |err| {
            std.debug.print("fuzz: iteration {d} failed: {t}\n", .{ iteration, err });
            return err;
        };
    }
    try std.testing.fuzz({}, fuzz_iobufs, .{});
}
