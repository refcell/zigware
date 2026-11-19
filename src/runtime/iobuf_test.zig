//! Tests of `IoBuf` and `IoBufMut` (commonware `iobuf::buf::tests`). No counterpart: the
//! owner-word and descriptor-promotion tests and `iobuf/owner.rs` (zigware's owner is one
//! allocation header), the `Bytes`, `BytesMut`, and `Vec` conversions, the `Buf`/`BufMut`
//! trait methods zigware does not have (`copy_to_slice`, `copy_to_bytes`, `put_bytes`, `put`
//! from another `Buf`), the oversized and impossible-alignment requests (they are
//! `error.OutOfMemory` here), and auto traits. The should_panic tests are death tests in
//! `iobuf_panic_test.zig`.

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

test "aligned capacity survives recovery (test_iobufmut_aligned_capacity_stable_*)" {
    const page: std.mem.Alignment = .fromByteUnits(4096);
    var buf: IoBufMut = try .with_alignment(gpa, 100, page);
    try testing.expectEqual(@as(usize, 100), buf.capacity);
    try testing.expect(page.check(@intFromPtr(buf.ptr)));
    buf.put_slice("data");
    var frozen_buf = buf.freeze();
    var recovered = frozen_buf.try_into_mut().?;
    defer recovered.deinit();
    try testing.expectEqual(@as(usize, 100), recovered.capacity);
    try testing.expectEqualStrings("data", recovered.bytes());
    var zeroed: IoBufMut = try .zeroed_with_alignment(gpa, 100, page);
    defer zeroed.deinit();
    try testing.expectEqual(@as(usize, 100), zeroed.len);
    try testing.expectEqual(@as(usize, 100), zeroed.capacity);
    // Zero-length buffers allocate nothing, so their alignment is never checked.
    var empty: IoBufMut = try .with_alignment(gpa, 0, .@"64");
    try testing.expect(empty.is_empty() and empty.capacity == 0);
    empty.deinit();
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

// IoBufs (commonware `iobuf::bufs::tests`). No counterpart: the representation and
// canonicalization tests (zigware keeps up to three chunks inline and spills to a list, which
// it then keeps), owner-record allocation counts, the `Buf`/`BufMut` trait methods zigware
// has no counterpart for (`copy_to_bytes`, `chunks_vectored`, `chunk_mut`; reads go through
// `chunk_at`, `slices`, `copy_to`, and `advance`), `Vec`/array/iterator conversions, the
// past-end and overflow `should_panic` tests (Zig asserts), and the nested-container, map,
// lazy, and range `encode_iobufs` tests (zigware's codec has no `write_bufs`).

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

/// `bufs` holds exactly `expected`, by length, emptiness, and contents.
fn expect_state(bufs: *const IoBufs, expected: []const u8) !void {
    try testing.expectEqual(expected.len, bufs.len());
    try testing.expectEqual(expected.len == 0, bufs.is_empty());
    var out: [16]u8 = undefined;
    bufs.copy_to(out[0..expected.len]);
    try testing.expectEqualStrings(expected, out[0..expected.len]);
}

test "iobufs emptiness after consumption (test_iobufs_emptiness_after_consumption)" {
    const data = "abcdefgh";
    for (0..data.len + 1) |end| {
        var suffix = try bufs_of(&.{ "", "ab", "", "cd", "ef", "", "gh", "" });
        defer suffix.deinit(gpa);
        var prefix = try suffix.split_to(gpa, end);
        defer prefix.deinit(gpa);
        try expect_state(&prefix, data[0..end]);
        try expect_state(&suffix, data[end..]);
        for ([_]usize{ 1, 2, 3, data.len }) |step| {
            var advanced = try bufs_of(&.{data[0..end]});
            defer advanced.deinit(gpa);
            try advanced.append(gpa, try frozen(""));
            var offset: usize = 0;
            while (offset < end) {
                const count = @min(step, end - offset);
                advanced.advance(count);
                offset += count;
                try expect_state(&advanced, data[offset..end]);
            }
        }
    }
}

test "iobufs as_single (test_iobufs_try_into_single)" {
    var single = try bufs_of(&.{"hello"});
    defer single.deinit(gpa);
    try testing.expectEqualStrings("hello", single.as_single().?.bytes());
    var multi = try bufs_of(&.{ "ab", "cd" });
    try testing.expect(multi.as_single() == null);
    try expect_coalesced(&multi, "abcd");
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

// IoBufsMut, Builder, and encode_iobufs (commonware `iobuf::bufs::tests`).

const IoBufsMut = iobuf.IoBufsMut;
const Builder = iobuf.Builder;

/// An `IoBufsMut` of the given buffers (a copy of each `parts` entry, or an empty buffer of
/// capacity `capacities[i]` when the part is empty).
fn bufs_mut_of(parts: []const []const u8, capacities: []const usize) !IoBufsMut {
    var bufs: IoBufsMut = .empty;
    errdefer bufs.deinit(gpa);
    for (parts, capacities) |part, capacity| {
        var buf: IoBufMut = try .with_capacity(gpa, @max(part.len, capacity));
        buf.put_slice(part);
        bufs.append(gpa, buf) catch |err| {
            buf.deinit();
            return err;
        };
    }
    return bufs;
}

fn expect_frozen(bufs: *IoBufsMut, expected: []const u8, chunk_count: usize) !void {
    var frozen_bufs = try bufs.freeze(gpa);
    try testing.expectEqual(chunk_count, frozen_bufs.chunk_count());
    try expect_coalesced(&frozen_bufs, expected);
}

test "iobufsmut freeze drops empty buffers (test_iobufsmut_freeze_chunked)" {
    var two = try bufs_mut_of(&.{ "hello", " world" }, &.{ 0, 0 });
    try expect_frozen(&two, "hello world", 2);
    var with_empty = try bufs_mut_of(&.{ "hello", "", " world" }, &.{ 0, 0, 0 });
    try testing.expectEqual(@as(usize, 2), with_empty.chunk_count());
    try expect_frozen(&with_empty, "hello world", 2);
    var one = try bufs_mut_of(&.{ "", "only one", "" }, &.{ 0, 0, 0 });
    try expect_frozen(&one, "only one", 1);
    var none = try bufs_mut_of(&.{ "", "" }, &.{ 0, 0 });
    try expect_frozen(&none, "", 0);
    // Spare capacity of an empty chunk does not survive a freeze.
    var reserved = try bufs_mut_of(&.{ "ab", "" }, &.{ 0, 8 });
    try testing.expectEqual(@as(usize, 2), reserved.chunk_count());
    try expect_frozen(&reserved, "ab", 1);
}

test "iobufsmut writes across chunks (test_iobufsmut_bufmut_put_slice)" {
    var bufs = try bufs_mut_of(&.{ "", "" }, &.{ 5, 6 });
    try testing.expect(bufs.is_empty());
    try testing.expectEqual(@as(usize, 11), bufs.remaining_mut());
    bufs.put_slice("hello");
    bufs.put_slice(" world");
    try testing.expectEqual(@as(usize, 0), bufs.remaining_mut());
    var whole = try bufs.coalesce(gpa);
    defer whole.deinit();
    try testing.expectEqualStrings("hello world", whole.bytes());
}

test "iobufsmut advance skips and drops spent chunks (test_iobufsmut_with_empty_buffers)" {
    var bufs = try bufs_mut_of(&.{ "hello", "", " world" }, &.{ 0, 0, 0 });
    defer bufs.deinit(gpa);
    try testing.expectEqual(@as(usize, 11), bufs.len());
    bufs.advance(5);
    try testing.expectEqual(@as(usize, 1), bufs.chunk_count());
    try testing.expectEqualStrings(" world", bufs.chunks()[0].bytes());
    // An empty chunk with capacity left is skipped, not dropped.
    var leading = try bufs_mut_of(&.{ "", "ab" }, &.{ 4, 0 });
    defer leading.deinit(gpa);
    leading.advance(1);
    try testing.expectEqual(@as(usize, 2), leading.chunk_count());
    try testing.expectEqualStrings("b", leading.chunks()[1].bytes());
}

test "iobufsmut reads keep writable capacity (test_iobufsmut_read_ops_preserve_*)" {
    // Draining the filled first chunk keeps the never-filled second chunk's capacity.
    const ones: [8]u8 = @splat(1);
    var bufs = try bufs_mut_of(&.{ &ones, "" }, &.{ 8, 8 });
    try testing.expectEqual(@as(usize, 8), bufs.len());
    try testing.expectEqual(@as(usize, 8), bufs.remaining_mut());
    bufs.advance(8);
    try testing.expectEqual(@as(usize, 0), bufs.len());
    try testing.expectEqual(@as(usize, 8), bufs.remaining_mut());
    const twos: [8]u8 = @splat(2);
    bufs.put_slice(&twos);
    try expect_frozen(&bufs, &twos, 1);
}

test "iobufsmut freeze after advance (test_iobufsmut_freeze_after_advance)" {
    var partial = try bufs_mut_of(&.{ "hello", " world" }, &.{ 0, 0 });
    partial.advance(3);
    try testing.expectEqual(@as(usize, 8), partial.len());
    try expect_frozen(&partial, "lo world", 2);
    var boundary = try bufs_mut_of(&.{ "hello", " world" }, &.{ 0, 0 });
    boundary.advance(5);
    try expect_frozen(&boundary, " world", 1);
}

test "iobufsmut copy_from_slice and set_len (test_iobufsmut_copy_from_slice_*, set_len)" {
    var zeroed = try bufs_mut_of(&.{ "\x00\x00\x00\x00\x00", "\x00\x00\x00\x00\x00\x00" }, &.{
        0, 0,
    });
    zeroed.copy_from_slice("hello world");
    try testing.expectEqualStrings("hello", zeroed.chunks()[0].bytes());
    try expect_frozen(&zeroed, "hello world", 2);
    // [3, 20, 2] set to 18 fills [3, 15, 0].
    var uneven = try bufs_mut_of(&.{ "", "", "" }, &.{ 3, 20, 2 });
    defer uneven.deinit(gpa);
    uneven.set_len(18);
    try testing.expectEqual(@as(usize, 18), uneven.len());
    const expected_lens = [_]usize{ 3, 15, 0 };
    for (uneven.chunks(), expected_lens) |chunk, expected| {
        try testing.expectEqual(expected, chunk.len);
    }
}

test "iobufsmut coalesce shapes (test_iobufsmut_coalesce_shapes)" {
    var single = try bufs_mut_of(&.{"abc"}, &.{8});
    const single_ptr = single.chunks()[0].ptr;
    var coalesced = try single.coalesce(gpa);
    try testing.expectEqual(single_ptr, coalesced.ptr);
    try testing.expectEqual(@as(usize, 8), coalesced.capacity);
    coalesced.deinit();
    var four = try bufs_mut_of(&.{ "ab", "cd", "ef", "gh" }, &.{ 0, 0, 0, 0 });
    var merged = try four.coalesce(gpa);
    defer merged.deinit();
    try testing.expectEqualStrings("abcdefgh", merged.bytes());
}

test "builder places pushed chunks between inline bytes" {
    var builder: Builder = try .init(gpa, 6);
    builder.put(u16, 99);
    try builder.push(gpa, .from_static("payload"));
    try builder.push(gpa, .empty);
    builder.put(u32, 0xdeadbeef);
    var bufs = try builder.finish(gpa);
    try testing.expectEqual(@as(usize, 3), bufs.chunk_count());
    try testing.expectEqualStrings("payload", bufs.chunk_at(1).?);
    try expect_coalesced(&bufs, "\x00\x63payload\xde\xad\xbe\xef");
    // Only pushes, nothing inline.
    var pushed_only: Builder = try .init(gpa, 0);
    try pushed_only.push(gpa, .from_static("a"));
    try pushed_only.push(gpa, .from_static("b"));
    var pieces = try pushed_only.finish(gpa);
    try testing.expectEqual(@as(usize, 2), pieces.chunk_count());
    try expect_coalesced(&pieces, "ab");
    // An unfinished builder releases what it holds.
    var abandoned: Builder = try .init(gpa, 4);
    try abandoned.push(gpa, try frozen("held"));
    abandoned.deinit(gpa);
}

test "builder pushes without copying (test_push_is_zero_copy, test_push_at_start_*)" {
    const payload: [32]u8 = @splat(0xcc);
    var builder: Builder = try .init(gpa, 8);
    try builder.push(gpa, .from_static(&payload));
    builder.put(u8, 1);
    var bufs = try builder.finish(gpa);
    // No empty inline segment precedes a push at the start.
    try testing.expectEqual(@as(usize, 2), bufs.chunk_count());
    try testing.expectEqual(@as([*]const u8, &payload), bufs.chunk_at(0).?.ptr);
    const expected = payload ++ [_]u8{1};
    try expect_coalesced(&bufs, &expected);
}

test "a zero-capacity builder allocates nothing (test_zero_capacity_push_only, test_empty)" {
    var failing: std.testing.FailingAllocator = .init(gpa, .{ .fail_index = 0 });
    var empty: Builder = try .init(failing.allocator(), 0);
    var nothing = try empty.finish(failing.allocator());
    try testing.expect(nothing.is_empty());
    nothing.deinit(failing.allocator());
    try testing.expectEqual(@as(usize, 0), failing.allocations);
    const first: [100]u8 = @splat('a');
    const second: [200]u8 = @splat('c');
    var builder: Builder = try .init(gpa, 0);
    try builder.push(gpa, .from_static(&first));
    try builder.push(gpa, .empty);
    try builder.push(gpa, .from_static(&second));
    var bufs = try builder.finish(gpa);
    defer bufs.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), bufs.chunk_count());
    try testing.expectEqual(@as(usize, 300), bufs.len());
}

fn expect_encode_iobufs_matches(comptime T: type, value: T) !void {
    const expected = try codec.encode(T, gpa, value);
    defer gpa.free(expected);
    var bufs = try iobuf.encode_iobufs(T, gpa, value);
    try expect_coalesced(&bufs, expected);
}

test "encode_iobufs matches encode (test_encode_iobufs_matches_encode)" {
    try expect_encode_iobufs_matches(u64, 0x0102030405060708);
    try expect_encode_iobufs_matches([]const u8, "inline bytes");
    try expect_encode_iobufs_matches(struct { u8, bool }, .{ 7, true });
    try expect_encode_iobufs_matches(IoBuf, .from_static("hello"));
    try expect_encode_iobufs_matches(IoBuf, .empty);
    var large: [300]u8 = @splat(9);
    try expect_encode_iobufs_matches(IoBuf, .from_static(&large));
}

test "encode_iobufs keeps the pushed iobuf (test_encode_iobufs_keeps_pushed_iobuf)" {
    var payload: IoBufMut = try .with_capacity(gpa, 512);
    @memset(payload.spare(), 0xab);
    payload.advance_mut(512);
    const ptr = payload.ptr;
    var value = payload.freeze();
    var encoded = try iobuf.encode_iobufs(IoBuf, gpa, value);
    value.deinit(gpa);
    const prefix_len = codec.encode_size(usize, 512);
    var prefix = try encoded.split_to(gpa, prefix_len);
    prefix.deinit(gpa);
    var chunk = try encoded.coalesce(gpa);
    // The one remaining chunk is the original buffer, now its only handle.
    var recovered = chunk.try_into_mut().?;
    defer recovered.deinit();
    try testing.expectEqual(ptr, recovered.ptr);
}

test "iobufmut aligned allocation declines impossible layouts" {
    // commonware `test_iobufmut_try_with_alignment_declines_impossible_layouts`. Zig's
    // `Alignment` is a power of two by construction, so the non-power-of-two case cannot
    // arise; oversized requests fail with OutOfMemory instead of returning None.
    const page: std.mem.Alignment = .fromByteUnits(4096);
    const heap = std.heap.page_allocator;
    const too_big = @as(usize, std.math.maxInt(isize)) + 1;
    try testing.expectError(error.OutOfMemory, IoBufMut.with_alignment(heap, too_big, page));
    try testing.expectError(
        error.OutOfMemory,
        IoBufMut.with_alignment(heap, std.math.maxInt(usize) - 100, page),
    );
    var buf = try IoBufMut.with_alignment(gpa, 100, page);
    defer buf.deinit();
    try testing.expectEqual(@as(usize, 100), buf.capacity);
    try testing.expect(page.check(@intFromPtr(buf.ptr)));
    var empty = try IoBufMut.with_alignment(gpa, 0, page);
    defer empty.deinit();
    try testing.expectEqual(@as(usize, 0), empty.capacity);
}

test "iobufsmut emptiness with reserved capacity" {
    // commonware `test_iobufsmut_emptiness_with_reserved_capacity`.
    for (0..9) |count| {
        for (0..count + 1) |readable| {
            var bufs: IoBufsMut = .empty;
            defer bufs.deinit(gpa);
            for (0..count) |index| {
                var chunk: IoBufMut = try .with_capacity(gpa, 4);
                if (index == readable) chunk.put_slice(&.{7});
                try bufs.append(gpa, chunk);
            }
            try testing.expectEqual(readable == count, bufs.is_empty());
            if (readable != count) {
                bufs.advance(1);
                try testing.expect(bufs.is_empty());
            }
            if (bufs.remaining_mut() > 0) {
                bufs.put_slice(&.{9});
                try testing.expect(!bufs.is_empty());
            }
        }
    }
}

test "iobufsmut as_single" {
    // commonware `test_iobufsmut_try_into_single`.
    var single = try bufs_mut_of(&.{"hello"}, &.{0});
    defer single.deinit(gpa);
    try testing.expectEqualStrings("hello", single.as_single().?.bytes());
    var multi = try bufs_mut_of(&.{ "ab", "cd" }, &.{ 0, 0 });
    try testing.expect(multi.as_single() == null);
    try expect_frozen(&multi, "abcd", 2);
}

test "encode_iobufs of containers, maps, lazy values, and ranges matches encode" {
    // commonware `test_nested_container_encode_iobufs_matches_encode`,
    // `test_map_encode_iobufs_matches_encode`, `test_lazy_encode_iobufs_matches_encode`, and
    // `test_non_empty_range_encode_iobufs_matches_encode`. Zig containers encode inline (no
    // `write_bufs`), so only the bytes are compared; a deferred `Lazy` is one inline chunk.
    const aa: [256]u8 = @splat(0xaa);
    const bb: [128]u8 = @splat(0xbb);
    const cc: [64]u8 = @splat(0xcc);
    const Nested = struct { ?[]const u8, []const []const u8 };
    try expect_encode_iobufs_matches(Nested, .{ &aa, &.{ &bb, &cc } });
    const dd: [96]u8 = @splat(0xdd);
    const ee: [48]u8 = @splat(0xee);
    inline for (.{ codec.Map(u8, []const u8), codec.HashMap(u8, []const u8) }) |M| {
        const entries = [_]M.Entry{ .{ .key = 1, .value = &ee }, .{ .key = 2, .value = &dd } };
        try expect_encode_iobufs_matches(M, .init(&entries));
    }
    const lazy_bytes: [200]u8 = @splat(0x44);
    try expect_encode_iobufs_matches(codec.Lazy([]const u8), .init(&lazy_bytes));
    const pending = try codec.encode(u64, gpa, 42);
    defer gpa.free(pending);
    try expect_encode_iobufs_matches(codec.Lazy(u64), .deferred(pending, {}));
    const utils = @import("utils");
    const range = try utils.range.NonEmptyRange(u64).init(32, 48);
    try expect_encode_iobufs_matches(@TypeOf(range), range);
}

test "encode_iobufs of an empty value does not allocate" {
    // commonware `test_encode_iobufs_without_inline_bytes_does_not_allocate`.
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var bufs = try iobuf.encode_iobufs([0]u8, failing.allocator(), .{});
    defer bufs.deinit(failing.allocator());
    try testing.expectEqual(@as(usize, 0), failing.allocations);
    try testing.expectEqual(@as(usize, 0), bufs.len());
    try testing.expectEqual(@as(usize, 0), bufs.chunk_count());
}
