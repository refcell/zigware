//! Buffers for I/O (commonware `runtime/src/iobuf`): `IoBufMut`, a fixed-capacity mutable
//! buffer, and `IoBuf`, an immutable view that clones and slices without copying.
//!
//! ```zig
//! var buf: IoBufMut = try .with_capacity(gpa, 8);
//! buf.put_slice("abcdef");
//! var frozen = buf.freeze();       // the owner moves; no copy, no refcount change
//! var head = frozen.slice(0, 3);   // "abc", sharing the allocation
//! head.deinit(gpa);
//! var again = frozen.try_into_mut().?; // the only view: the mutable handle comes back
//! again.deinit();
//! ```
//!
//! Ownership: a native buffer is one allocation that holds an `Owner` header (a reference
//! count, the allocator, and the layout) followed by the bytes, so creating a buffer allocates
//! once and cloning or slicing allocates nothing. Zig has no `Drop`: every handle that holds an
//! allocation is released with `deinit` exactly once, and `freeze`, `try_into_mut`, and
//! `split_to` move ownership as commonware's do. Static views (`from_static`) and empty
//! buffers hold no allocation. The reference count is atomic, so views may move between
//! threads.
//!
//! Codec: an `IoBuf` encodes like `Vec<u8>` (a `usize` length, then the bytes). `read` copies
//! the payload into a new buffer; `take_encoded` decodes from an `IoBuf` without copying.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const codec = @import("codec");

/// The header of a native allocation, stored at its start.
const Owner = struct {
    references: std.atomic.Value(u32),
    gpa: Allocator,
    alignment: Alignment,
    /// Bytes from the start of the allocation to the first data byte.
    data_offset: usize,
    capacity: usize,

    fn create(gpa: Allocator, capacity: usize, data_alignment: Alignment) Allocator.Error!*Owner {
        assert(capacity > 0);
        const alignment = Alignment.max(data_alignment, .of(Owner));
        const data_offset = data_alignment.forward(@sizeOf(Owner));
        const total = std.math.add(usize, data_offset, capacity) catch return error.OutOfMemory;
        const base = gpa.rawAlloc(total, alignment, @returnAddress()) orelse
            return error.OutOfMemory;
        const owner: *Owner = @ptrCast(@alignCast(base));
        owner.* = .{
            .references = .init(1),
            .gpa = gpa,
            .alignment = alignment,
            .data_offset = data_offset,
            .capacity = capacity,
        };
        assert(data_alignment.check(@intFromPtr(owner.data())));
        return owner;
    }

    fn data(owner: *Owner) [*]u8 {
        const base: [*]u8 = @ptrCast(owner);
        return base + owner.data_offset;
    }

    fn retain(owner: *Owner) void {
        const previous = owner.references.fetchAdd(1, .monotonic);
        assert(previous > 0);
        assert(previous < std.math.maxInt(u32));
    }

    fn release(owner: *Owner) void {
        const previous = owner.references.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous > 1) return;
        const base: [*]u8 = @ptrCast(owner);
        const total = owner.data_offset + owner.capacity;
        owner.gpa.rawFree(base[0..total], owner.alignment, @returnAddress());
    }

    fn is_unique(owner: *Owner) bool {
        return owner.references.load(.acquire) == 1;
    }
};

/// An immutable byte buffer (commonware `IoBuf`): a view of `len` bytes that keeps its
/// allocation alive.
pub const IoBuf = struct {
    ptr: [*]const u8,
    len: usize,
    owner: ?*Owner,

    /// The empty buffer; holds no allocation (commonware `IoBuf::default`).
    pub const empty: IoBuf = .{ .ptr = &.{}, .len = 0, .owner = null };

    /// A view of `source`, which must outlive every view of it (commonware `From<&'static
    /// [u8]>`). Holds no allocation.
    pub fn from_static(source: []const u8) IoBuf {
        return .{ .ptr = source.ptr, .len = source.len, .owner = null };
    }

    /// A new buffer holding a copy of `source` (commonware `IoBuf::copy_from_slice`).
    pub fn copy_from_slice(gpa: Allocator, source: []const u8) Allocator.Error!IoBuf {
        var buf: IoBufMut = try .with_capacity(gpa, source.len);
        buf.put_slice(source);
        return buf.freeze();
    }

    /// Releases this handle's reference. `gpa` is unused (the allocation records its own
    /// allocator); it is the codec's `deinit` contract, so decoded values holding an `IoBuf`
    /// free it like any other field.
    pub fn deinit(buf: *IoBuf, gpa: Allocator) void {
        _ = gpa;
        buf.release();
    }

    fn release(buf: *IoBuf) void {
        if (buf.owner) |owner| owner.release();
        buf.* = undefined;
    }

    /// The readable bytes.
    pub fn bytes(buf: IoBuf) []const u8 {
        return buf.ptr[0..buf.len];
    }

    pub fn is_empty(buf: IoBuf) bool {
        return buf.len == 0;
    }

    /// Another handle to the same bytes; release it with its own `deinit`.
    pub fn clone(buf: IoBuf) IoBuf {
        if (buf.owner) |owner| owner.retain();
        return buf;
    }

    /// A view of bytes `[start, end)` sharing the allocation (commonware `IoBuf::slice`). An
    /// empty range returns `empty`, which holds no allocation.
    pub fn slice(buf: IoBuf, start: usize, end: usize) IoBuf {
        assert(start <= end);
        assert(end <= buf.len);
        if (start == end) return .empty;
        var result = buf.clone();
        result.ptr += start;
        result.len = end - start;
        return result;
    }

    /// Splits off and returns bytes `[0, at)`; `buf` keeps `[at, len)` (commonware
    /// `IoBuf::split_to`). The empty half of a split at either end holds no allocation.
    pub fn split_to(buf: *IoBuf, at: usize) IoBuf {
        assert(at <= buf.len);
        if (at == 0) return .empty;
        if (at == buf.len) {
            const whole = buf.*;
            buf.* = .empty;
            return whole;
        }
        const prefix: IoBuf = .{ .ptr = buf.ptr, .len = at, .owner = buf.owner };
        if (buf.owner) |owner| owner.retain();
        buf.ptr += at;
        buf.len -= at;
        assert(buf.len > 0);
        return prefix;
    }

    /// Consumes the first `count` readable bytes (commonware `Buf::advance`).
    pub fn advance(buf: *IoBuf, count: usize) void {
        assert(count <= buf.len);
        buf.ptr += count;
        buf.len -= count;
        if (buf.len == 0) {
            if (buf.owner) |owner| owner.release();
            buf.* = .empty;
        }
    }

    /// The mutable handle for this view's allocation, if this is its only handle (commonware
    /// `IoBuf::try_into_mut`). Its capacity runs from the view's start to the end of the
    /// allocation. On success `buf` is consumed; on null `buf` is unchanged. An empty view
    /// with no allocation converts to an empty mutable buffer; a non-empty static view never
    /// converts.
    pub fn try_into_mut(buf: *IoBuf) ?IoBufMut {
        const owner = buf.owner orelse {
            if (buf.len != 0) return null;
            buf.* = undefined;
            return IoBufMut.empty;
        };
        if (!owner.is_unique()) return null;
        const offset = @intFromPtr(buf.ptr) - @intFromPtr(owner.data());
        assert(offset + buf.len <= owner.capacity);
        const result: IoBufMut = .{
            .ptr = owner.data() + offset,
            .len = buf.len,
            .capacity = owner.capacity - offset,
            .owner = owner,
        };
        buf.* = undefined;
        return result;
    }

    pub fn eql(a: IoBuf, b: IoBuf) bool {
        return std.mem.eql(u8, a.bytes(), b.bytes());
    }

    // Codec (commonware `Write`, `EncodeSize`, and `Read` for `IoBuf`).

    pub const Cfg = codec.RangeCfg(usize);

    pub fn write(buf: IoBuf, writer: *codec.Writer) void {
        codec.write(usize, buf.len, writer);
        writer.write_bytes(buf.bytes());
    }

    pub fn encode_size(buf: IoBuf) usize {
        return codec.encode_size(usize, buf.len) + buf.len;
    }

    /// Decodes a copy of the payload into a new buffer.
    pub fn read(gpa: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!IoBuf {
        const len = try codec.read_usize(reader, range);
        const payload = try reader.take(len);
        assert(payload.len == len);
        return copy_from_slice(gpa, payload) catch error.OutOfMemory;
    }

    /// Decodes one encoded buffer from the front of `source` without copying: the result is a
    /// view of `source`'s allocation, and `source` keeps the bytes after it (commonware
    /// `Read for IoBuf` over an `IoBuf` input, `try_take_owned`).
    pub fn take_encoded(source: *IoBuf, range: Cfg) codec.Error!IoBuf {
        var reader: codec.Reader = .init(source.bytes());
        const len = try codec.read_usize(&reader, range);
        const prefix = source.len - reader.remaining();
        if (reader.remaining() < len) return error.EndOfBuffer;
        source.advance(prefix);
        const result = source.split_to(len);
        assert(result.len == len);
        return result;
    }
};

/// A mutable byte buffer with a fixed capacity (commonware `IoBufMut`): `len` readable bytes,
/// then spare capacity that `put_slice` fills.
pub const IoBufMut = struct {
    ptr: [*]u8,
    len: usize,
    capacity: usize,
    owner: ?*Owner,

    /// The empty buffer with no capacity; holds no allocation.
    pub const empty: IoBufMut = .{ .ptr = &.{}, .len = 0, .capacity = 0, .owner = null };

    /// An empty buffer that can hold `capacity` bytes (commonware `IoBufMut::with_capacity`).
    pub fn with_capacity(gpa: Allocator, capacity: usize) Allocator.Error!IoBufMut {
        return with_alignment(gpa, capacity, .@"1");
    }

    /// An empty buffer whose bytes start at an `alignment` boundary (commonware
    /// `IoBufMut::with_alignment`), for direct I/O.
    pub fn with_alignment(
        gpa: Allocator,
        capacity: usize,
        alignment: Alignment,
    ) Allocator.Error!IoBufMut {
        if (capacity == 0) return .empty;
        const owner = try Owner.create(gpa, capacity, alignment);
        return .{ .ptr = owner.data(), .len = 0, .capacity = capacity, .owner = owner };
    }

    /// A buffer of `len` zero bytes (commonware `IoBufMut::zeroed`).
    pub fn zeroed(gpa: Allocator, len: usize) Allocator.Error!IoBufMut {
        return zeroed_with_alignment(gpa, len, .@"1");
    }

    pub fn zeroed_with_alignment(
        gpa: Allocator,
        len: usize,
        alignment: Alignment,
    ) Allocator.Error!IoBufMut {
        var buf = try with_alignment(gpa, len, alignment);
        @memset(buf.ptr[0..len], 0);
        buf.len = len;
        return buf;
    }

    /// A new buffer holding a copy of `bytes`, with no spare capacity.
    pub fn copy_from_slice(gpa: Allocator, source: []const u8) Allocator.Error!IoBufMut {
        var buf = try with_capacity(gpa, source.len);
        buf.put_slice(source);
        return buf;
    }

    pub fn deinit(buf: *IoBufMut) void {
        if (buf.owner) |owner| {
            assert(owner.is_unique());
            owner.release();
        }
        buf.* = undefined;
    }

    /// The readable bytes.
    pub fn bytes(buf: *const IoBufMut) []u8 {
        return buf.ptr[0..buf.len];
    }

    /// The unwritten capacity after the readable bytes; `advance_mut` publishes what was
    /// written there.
    pub fn spare(buf: *const IoBufMut) []u8 {
        return buf.ptr[buf.len..buf.capacity];
    }

    /// Marks `count` bytes of `spare()` as written (commonware `BufMut::advance_mut`).
    pub fn advance_mut(buf: *IoBufMut, count: usize) void {
        assert(count <= buf.capacity - buf.len);
        buf.len += count;
    }

    /// Consumes the first `count` readable bytes; the capacity shrinks with them (commonware
    /// `Buf::advance`).
    pub fn advance(buf: *IoBufMut, count: usize) void {
        assert(count <= buf.len);
        buf.ptr += count;
        buf.len -= count;
        buf.capacity -= count;
    }

    /// The mutable handle of `source`'s allocation if `source` is its only handle, else a copy
    /// of its bytes (commonware `From<IoBuf> for IoBufMut`). Consumes `source` either way.
    pub fn from_iobuf(gpa: Allocator, source: *IoBuf) Allocator.Error!IoBufMut {
        if (source.try_into_mut()) |recovered| return recovered;
        const copy = try copy_from_slice(gpa, source.bytes());
        source.deinit(gpa);
        return copy;
    }

    /// Appends `source`; panics past the capacity (commonware `BufMut::put_slice`).
    pub fn put_slice(buf: *IoBufMut, source: []const u8) void {
        assert(source.len <= buf.capacity - buf.len);
        @memcpy(buf.spare()[0..source.len], source);
        buf.len += source.len;
    }

    pub fn is_empty(buf: *const IoBufMut) bool {
        return buf.len == 0;
    }

    /// Keeps the first `len` readable bytes; no effect if `len` is longer.
    pub fn truncate(buf: *IoBufMut, len: usize) void {
        buf.len = @min(buf.len, len);
    }

    /// Removes every readable byte, keeping the capacity.
    pub fn clear(buf: *IoBufMut) void {
        buf.len = 0;
    }

    /// The immutable buffer of the readable bytes; the allocation moves with it (commonware
    /// `IoBufMut::freeze`). Freezing an empty buffer releases its allocation.
    pub fn freeze(buf: *IoBufMut) IoBuf {
        if (buf.len == 0) {
            buf.deinit();
            return .empty;
        }
        assert(buf.owner != null);
        const result: IoBuf = .{ .ptr = buf.ptr, .len = buf.len, .owner = buf.owner };
        buf.* = undefined;
        return result;
    }
};

/// A sequence of immutable buffers read as one byte string (commonware `IoBufs`). Up to three
/// chunks are stored inline, so building one from one to three buffers allocates nothing; a
/// fourth moves every chunk into a list allocated from the `gpa` passed to `append`/`prepend`.
/// Empty buffers are never stored. Release with `deinit`, passing the same `gpa`.
pub const IoBufs = struct {
    small: [small_max]IoBuf = undefined,
    small_len: u8 = 0,
    /// Every chunk once more than `small_max` were held; chunks before `large_front` are gone.
    large: std.ArrayList(IoBuf) = .empty,
    large_front: usize = 0,
    spilled: bool = false,

    pub const small_max = 3;

    pub const empty: IoBufs = .{};

    /// The sequence of one buffer, which it takes; allocates nothing.
    pub fn from(buf: IoBuf) IoBufs {
        var result: IoBufs = .{};
        if (buf.is_empty()) return result;
        result.small[0] = buf;
        result.small_len = 1;
        return result;
    }

    pub fn deinit(bufs: *IoBufs, gpa: Allocator) void {
        for (bufs.chunks()) |*chunk| chunk.deinit(gpa);
        bufs.large.deinit(gpa);
        bufs.* = undefined;
    }

    /// The chunks, in order, all non-empty.
    pub fn chunks(bufs: *IoBufs) []IoBuf {
        if (bufs.spilled) return bufs.large.items[bufs.large_front..];
        return bufs.small[0..bufs.small_len];
    }

    fn chunks_const(bufs: *const IoBufs) []const IoBuf {
        if (bufs.spilled) return bufs.large.items[bufs.large_front..];
        return bufs.small[0..bufs.small_len];
    }

    /// Total readable bytes.
    pub fn len(bufs: *const IoBufs) usize {
        var total: usize = 0;
        for (bufs.chunks_const()) |chunk| total += chunk.len;
        return total;
    }

    pub fn is_empty(bufs: *const IoBufs) bool {
        return bufs.chunks_const().len == 0;
    }

    pub fn chunk_count(bufs: *const IoBufs) usize {
        return bufs.chunks_const().len;
    }

    /// The bytes of chunk `index`, or null past the last chunk.
    pub fn chunk_at(bufs: *const IoBufs, index: usize) ?[]const u8 {
        const all = bufs.chunks_const();
        if (index >= all.len) return null;
        return all[index].bytes();
    }

    /// The only chunk, if there is exactly one.
    pub fn as_single(bufs: *const IoBufs) ?IoBuf {
        const all = bufs.chunks_const();
        return if (all.len == 1) all[0] else null;
    }

    /// The chunks' bytes in `out` (at least `chunk_count()` long), for a vectored write such
    /// as `Sink.send`.
    pub fn slices(bufs: *const IoBufs, out: [][]const u8) [][]const u8 {
        const all = bufs.chunks_const();
        assert(out.len >= all.len);
        for (all, out[0..all.len]) |chunk, *slot| slot.* = chunk.bytes();
        return out[0..all.len];
    }

    /// Adds `buf` at the back, taking it; an empty `buf` is dropped. On error `buf` stays the
    /// caller's and `bufs` is unchanged.
    pub fn append(bufs: *IoBufs, gpa: Allocator, buf: IoBuf) Allocator.Error!void {
        if (buf.is_empty()) return;
        if (!bufs.spilled and bufs.small_len < small_max) {
            bufs.small[bufs.small_len] = buf;
            bufs.small_len += 1;
            return;
        }
        try bufs.reserve(gpa, 1);
        bufs.large.appendAssumeCapacity(buf);
    }

    /// Adds `buf` at the front, taking it; an empty `buf` is dropped. On error `buf` stays the
    /// caller's and `bufs` is unchanged.
    pub fn prepend(bufs: *IoBufs, gpa: Allocator, buf: IoBuf) Allocator.Error!void {
        if (buf.is_empty()) return;
        if (!bufs.spilled and bufs.small_len < small_max) {
            const count = bufs.small_len;
            std.mem.copyBackwards(IoBuf, bufs.small[1 .. count + 1], bufs.small[0..count]);
            bufs.small[0] = buf;
            bufs.small_len += 1;
            return;
        }
        if (bufs.spilled and bufs.large_front > 0) {
            bufs.large_front -= 1;
            bufs.large.items[bufs.large_front] = buf;
            return;
        }
        try bufs.reserve(gpa, 1);
        bufs.large.insertAssumeCapacity(bufs.large_front, buf);
    }

    /// Ensures room for `extra` more chunks in the list, moving the inline chunks into it.
    fn reserve(bufs: *IoBufs, gpa: Allocator, extra: usize) Allocator.Error!void {
        const count = bufs.chunk_count();
        try bufs.large.ensureTotalCapacity(gpa, bufs.large_front + count + extra);
        if (bufs.spilled) return;
        assert(bufs.large.items.len == 0 and bufs.large_front == 0);
        bufs.large.appendSliceAssumeCapacity(bufs.small[0..bufs.small_len]);
        bufs.small_len = 0;
        bufs.spilled = true;
    }

    /// Drops the first `count` chunks, which the caller has released or moved.
    fn drop_front(bufs: *IoBufs, count: usize) void {
        assert(count <= bufs.chunk_count());
        if (bufs.spilled) {
            bufs.large_front += count;
            if (bufs.large_front == bufs.large.items.len) {
                bufs.large.clearRetainingCapacity();
                bufs.large_front = 0;
            }
            return;
        }
        const left = bufs.small_len - count;
        std.mem.copyForwards(IoBuf, bufs.small[0..left], bufs.small[count..bufs.small_len]);
        bufs.small_len = @intCast(left);
    }

    /// Consumes the first `count` bytes (commonware `Buf::advance`).
    pub fn advance(bufs: *IoBufs, count: usize) void {
        assert(count <= bufs.len());
        var left = count;
        var whole: usize = 0;
        for (bufs.chunks()) |*chunk| {
            if (left == 0) break;
            if (left < chunk.len) {
                chunk.advance(left);
                left = 0;
                break;
            }
            left -= chunk.len;
            chunk.release();
            whole += 1;
        }
        assert(left == 0);
        bufs.drop_front(whole);
    }

    /// Splits off and returns bytes `[0, at)`; `bufs` keeps `[at, len)` (commonware
    /// `IoBufs::split_to`). Whole chunks move without copying, and a chunk the split lands in
    /// is split zero-copy. On error `bufs` is unchanged.
    pub fn split_to(bufs: *IoBufs, gpa: Allocator, at: usize) Allocator.Error!IoBufs {
        assert(at <= bufs.len());
        var whole: usize = 0;
        var left = at;
        for (bufs.chunks()) |chunk| {
            if (left < chunk.len) break;
            left -= chunk.len;
            whole += 1;
        }
        var prefix: IoBufs = .{};
        const prefix_count = whole + @intFromBool(left > 0);
        if (prefix_count > small_max) try prefix.reserve(gpa, prefix_count);
        const all = bufs.chunks();
        for (all[0..whole]) |chunk| prefix.append(gpa, chunk) catch unreachable; // Reserved.
        if (left > 0) {
            const head = all[whole].split_to(left);
            prefix.append(gpa, head) catch unreachable; // Reserved above.
        }
        bufs.drop_front(whole);
        assert(prefix.len() == at);
        return prefix;
    }

    /// One buffer of every byte, taking the chunks (commonware `IoBufs::coalesce`): the chunk
    /// itself when there is one, else a copy into one new allocation. On error `bufs` is
    /// unchanged.
    pub fn coalesce(bufs: *IoBufs, gpa: Allocator) Allocator.Error!IoBuf {
        if (bufs.as_single()) |single| {
            bufs.large.deinit(gpa);
            bufs.* = undefined;
            return single;
        }
        var out: IoBufMut = try .with_capacity(gpa, bufs.len());
        for (bufs.chunks()) |chunk| out.put_slice(chunk.bytes());
        bufs.deinit(gpa);
        return out.freeze();
    }

    /// Copies the first `out.len` bytes into `out` without consuming them.
    pub fn copy_to(bufs: *const IoBufs, out: []u8) void {
        assert(out.len <= bufs.len());
        var written: usize = 0;
        for (bufs.chunks_const()) |chunk| {
            if (written == out.len) break;
            const count = @min(chunk.len, out.len - written);
            @memcpy(out[written..][0..count], chunk.bytes()[0..count]);
            written += count;
        }
        assert(written == out.len);
    }
};

test {
    _ = @import("iobuf_test.zig");
}
