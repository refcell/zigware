//! Core encode and decode operations (codec/src/codec.rs, types/primitives.rs, types/vec.rs,
//! types/tuple.rs).
//!
//! commonware's traits (`Write`, `Read`, `EncodeSize`, `FixedSize`, `MaxEncodeSize`) become
//! comptime dispatch on the value's type:
//!
//! | Zig type | commonware type | encoding |
//! | --- | --- | --- |
//! | `bool` | `bool` | one byte, 0 or 1 |
//! | `u8`..`u128`, `i8`..`i128` (any whole-byte width) | same | fixed-width big-endian |
//! | `f32`, `f64` | same | IEEE 754 bits, big-endian |
//! | `usize` | `usize` | `UInt<u32>` varint, read with `RangeCfg(usize)` |
//! | `[N]T` | `[T; N]` | each element, no length prefix |
//! | `?T` | `Option<T>` | bool, then the value if present |
//! | `[]const T`, `[]T` | `Vec<T>` | `usize` length, then each element (decode allocates) |
//! | `*const T`, `*T` | `Arc<T>` | the pointee (decode allocates) |
//! | tuple `struct { A, B }` | `(A, B)` | each field in order |
//! | `enum(uN)` without methods | hand-written tag enums | the tag, unknown tags rejected |
//! | any other type | a type implementing the traits | its own methods, see below |
//!
//! A custom type implements the interface with declarations:
//!
//! ```zig
//! pub const Cfg = ...;                       // optional; default `void`
//! pub const fixed_size: usize = N;           // optional; makes the type FixedSize
//! pub const max_encode_size: usize = M;      // optional; MaxEncodeSize
//! pub fn write(self: Self, writer: *codec.Writer) void
//! pub fn encode_size(self: Self) usize       // required unless `fixed_size` is declared
//! pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self
//! pub fn deinit(self: *Self, gpa: Allocator) void  // optional; frees what `read` allocated
//! pub const owns_memory: bool = ...;         // optional; false when `deinit` frees nothing
//! ```
//!
//! Decoding takes an allocator explicitly. Types that do not allocate ignore it, and
//! `decode_fixed`/`read_fixed` pass `Allocator.failing`. Free decoded values with `free`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const buf = @import("buf.zig");
const Reader = buf.Reader;
const Writer = buf.Writer;
const Error = @import("error.zig").Error;
const RangeCfg = @import("config.zig").RangeCfg;
const varint = @import("varint.zig");

const Kind = enum { bool, int, usize, float, array, optional, slice, pointer, tuple, tag, custom };

fn kind(comptime T: type) Kind {
    if (T == usize) return .usize;
    return switch (@typeInfo(T)) {
        .bool => .bool,
        // Unsigned integers of any width are commonware's `Uint<BITS, LIMBS>`; signed widths
        // must be whole bytes.
        .int => |info| if (info.bits % 8 == 0 or info.signedness == .unsigned)
            .int
        else
            @compileError("codec: signed integer width must be whole bytes: " ++ @typeName(T)),
        .float => if (T == f32 or T == f64) .float else @compileError(
            "codec: only f32 and f64 are supported: " ++ @typeName(T),
        ),
        .array => .array,
        .optional => .optional,
        .pointer => |info| switch (info.size) {
            .slice => if (info.sentinel_ptr == null) .slice else @compileError(
                "codec: sentinel slices are not supported: " ++ @typeName(T),
            ),
            .one => .pointer,
            else => @compileError("codec: unsupported pointer type: " ++ @typeName(T)),
        },
        .@"struct" => |info| if (info.is_tuple) .tuple else custom_kind(T),
        .@"enum" => if (@hasDecl(T, "write")) .custom else .tag,
        .@"union", .@"opaque" => custom_kind(T),
        else => @compileError("codec: unsupported type: " ++ @typeName(T)),
    };
}

fn custom_kind(comptime T: type) Kind {
    if (!@hasDecl(T, "write") or !@hasDecl(T, "read")) {
        @compileError("codec: " ++ @typeName(T) ++ " must declare `write` and `read`");
    }
    if (!@hasDecl(T, "fixed_size") and !@hasDecl(T, "encode_size")) {
        @compileError("codec: " ++ @typeName(T) ++ " must declare `encode_size` or `fixed_size`");
    }
    return .custom;
}

/// Config for reading a slice (`Vec<T>`): the permitted length range and the item config.
pub fn SliceCfg(comptime ItemCfg: type) type {
    if (ItemCfg == void) {
        return struct { range: RangeCfg(usize), item: void = {} };
    }
    return struct { range: RangeCfg(usize), item: ItemCfg };
}

/// The read configuration type of `T` (commonware's `Read::Cfg`).
pub fn Cfg(comptime T: type) type {
    return switch (comptime kind(T)) {
        .bool, .int, .float, .tag => void,
        .usize => RangeCfg(usize),
        .array => Cfg(@typeInfo(T).array.child),
        .optional => Cfg(@typeInfo(T).optional.child),
        .slice => SliceCfg(Cfg(@typeInfo(T).pointer.child)),
        .pointer => Cfg(@typeInfo(T).pointer.child),
        .tuple => tuple: {
            const field_types = @typeInfo(T).@"struct".field_types;
            var cfg_types: [field_types.len]type = undefined;
            for (field_types, 0..) |field_type, index| cfg_types[index] = Cfg(field_type);
            const result = cfg_types;
            break :tuple @Tuple(&result);
        },
        .custom => if (@hasDecl(T, "Cfg")) T.Cfg else void,
    };
}

/// The value of a unit config (`void`, or tuples and slices of units), as used by commonware's
/// `ReadExt::read` and `DecodeExt::decode`.
pub fn unit_cfg(comptime C: type) C {
    if (C == void) return {};
    const info = @typeInfo(C);
    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("codec: config is not unit-like: " ++ @typeName(C));
    }
    var result: C = undefined;
    inline for (info.@"struct".field_types, 0..) |field_type, index| {
        result[index] = unit_cfg(field_type);
    }
    return result;
}

/// The encoded size of every value of `T`, or null when it varies (`FixedSize::SIZE`).
pub fn fixed_size(comptime T: type) ?usize {
    return switch (comptime kind(T)) {
        .bool => 1,
        .int => int_bytes(T),
        .float => @bitSizeOf(T) / 8,
        .tag => @bitSizeOf(@typeInfo(T).@"enum".tag_type) / 8,
        .usize, .optional, .slice => null,
        .array => if (fixed_size(@typeInfo(T).array.child)) |size|
            size * @typeInfo(T).array.len
        else
            null,
        .pointer => fixed_size(@typeInfo(T).pointer.child),
        .tuple => tuple: {
            var total: usize = 0;
            inline for (@typeInfo(T).@"struct".field_types) |field_type| {
                total += fixed_size(field_type) orelse break :tuple null;
            }
            break :tuple total;
        },
        .custom => if (@hasDecl(T, "fixed_size")) T.fixed_size else null,
    };
}

/// An upper bound on the encoded size of `T` that does not depend on caller limits
/// (`MaxEncodeSize`), or null when `T` has none (slices are bounded by `max_items_size`).
pub fn max_encode_size(comptime T: type) ?usize {
    if (fixed_size(T)) |size| return size;
    return switch (comptime kind(T)) {
        .usize => varint.max_u32_varint_size,
        .optional => if (max_encode_size(@typeInfo(T).optional.child)) |size| 1 + size else null,
        .array => if (max_encode_size(@typeInfo(T).array.child)) |size|
            size * @typeInfo(T).array.len
        else
            null,
        .pointer => max_encode_size(@typeInfo(T).pointer.child),
        .tuple => tuple: {
            var total: usize = 0;
            inline for (@typeInfo(T).@"struct".field_types) |field_type| {
                total += max_encode_size(field_type) orelse break :tuple null;
            }
            break :tuple total;
        },
        .custom => if (@hasDecl(T, "max_encode_size")) T.max_encode_size else null,
        else => null,
    };
}

/// Whether decoded values of `T` own allocated memory that `free` must release.
pub fn owns_memory(comptime T: type) bool {
    return switch (comptime kind(T)) {
        .bool, .int, .float, .tag, .usize => false,
        .array => owns_memory(@typeInfo(T).array.child),
        .optional => owns_memory(@typeInfo(T).optional.child),
        .slice, .pointer => true,
        .tuple => tuple: {
            inline for (@typeInfo(T).@"struct".field_types) |field_type| {
                if (owns_memory(field_type)) break :tuple true;
            }
            break :tuple false;
        },
        // A generic type may declare `owns_memory` to say whether its `deinit` frees anything.
        .custom => if (@hasDecl(T, "owns_memory")) T.owns_memory else @hasDecl(T, "deinit"),
    };
}

fn usize_to_u32(value: usize) u32 {
    // commonware panics here too: lengths must fit the u32 wire format on every platform.
    assert(value <= std.math.maxInt(u32));
    return @intCast(value);
}

/// The exact number of bytes `write` produces for `value` (`EncodeSize::encode_size`).
pub fn encode_size(comptime T: type, value: T) usize {
    if (comptime fixed_size(T)) |size| return size;
    return switch (comptime kind(T)) {
        .usize => varint.size(u32, usize_to_u32(value)),
        .optional => if (value) |inner| 1 + encode_size(@TypeOf(inner), inner) else 1,
        .array => encode_size_items(@typeInfo(T).array.child, &value),
        .slice => varint.size(u32, usize_to_u32(value.len)) +
            encode_size_items(@typeInfo(T).pointer.child, value),
        .pointer => encode_size(@typeInfo(T).pointer.child, value.*),
        .tuple => tuple: {
            var total: usize = 0;
            inline for (@typeInfo(T).@"struct".field_types, 0..) |field_type, index| {
                total += encode_size(field_type, value[index]);
            }
            break :tuple total;
        },
        .custom => value.encode_size(),
        .bool, .int, .float, .tag => unreachable, // Proof: these are fixed-size.
    };
}

/// Encoded size of `items` without any length prefix (`EncodeSize::encode_size_slice`).
pub fn encode_size_items(comptime T: type, items: []const T) usize {
    if (comptime fixed_size(T)) |size| return size * items.len;
    var total: usize = 0;
    for (items) |item| total += encode_size(T, item);
    return total;
}

/// Writes the encoding of `value` (`Write::write`).
pub fn write(comptime T: type, value: T, writer: *Writer) void {
    switch (comptime kind(T)) {
        .bool => writer.write_byte(@intFromBool(value)),
        .int => writer.write_int(IntBytes(T), value),
        .float => writer.write_int(@Int(.unsigned, @bitSizeOf(T)), @bitCast(value)),
        .tag => writer.write_int(@typeInfo(T).@"enum".tag_type, @backingInt(value)),
        .usize => varint.write(u32, usize_to_u32(value), writer),
        .optional => {
            writer.write_byte(@intFromBool(value != null));
            if (value) |inner| write(@TypeOf(inner), inner, writer);
        },
        .array => write_items(@typeInfo(T).array.child, &value, writer),
        .slice => {
            varint.write(u32, usize_to_u32(value.len), writer);
            write_items(@typeInfo(T).pointer.child, value, writer);
        },
        .pointer => write(@typeInfo(T).pointer.child, value.*, writer),
        .tuple => inline for (@typeInfo(T).@"struct".field_types, 0..) |field_type, index| {
            write(field_type, value[index], writer);
        },
        .custom => value.write(writer),
    }
}

/// Writes each of `items` without a length prefix (`Write::write_slice`). Bytes are copied
/// in bulk.
pub fn write_items(comptime T: type, items: []const T, writer: *Writer) void {
    if (T == u8) return writer.write_bytes(items);
    for (items) |item| write(T, item, writer);
}

/// Reads a value of `T` (`Read::read_cfg`). Free the result with `free(T, gpa, value)`.
pub fn read_cfg(comptime T: type, gpa: Allocator, reader: *Reader, cfg: Cfg(T)) Error!T {
    switch (comptime kind(T)) {
        .bool => return read_bool(reader),
        .int => return read_int(T, reader),
        .float => return @bitCast(try reader.read_int(@Int(.unsigned, @bitSizeOf(T)))),
        .tag => return read_tag(T, reader),
        .usize => return read_usize(reader, cfg),
        .optional => {
            if (!try read_bool(reader)) return null;
            return try read_cfg(@typeInfo(T).optional.child, gpa, reader, cfg);
        },
        .array => return read_array(T, gpa, reader, cfg),
        .slice => {
            const len = try read_usize(reader, cfg.range);
            return read_items(@typeInfo(T).pointer.child, gpa, reader, len, cfg.item);
        },
        .pointer => {
            const Child = @typeInfo(T).pointer.child;
            const pointer = try gpa.create(Child);
            errdefer gpa.destroy(pointer);
            pointer.* = try read_cfg(Child, gpa, reader, cfg);
            return pointer;
        },
        .tuple => return read_tuple(T, gpa, reader, cfg),
        .custom => return T.read(gpa, reader, cfg),
    }
}

/// Bytes in the encoding of integer `T`: the fewest that hold its bits (`Uint::BYTES`).
fn int_bytes(comptime T: type) usize {
    return (@bitSizeOf(T) + 7) / 8;
}

/// The whole-byte integer `T` is written as.
fn IntBytes(comptime T: type) type {
    return @Int(@typeInfo(T).int.signedness, int_bytes(T) * 8);
}

fn read_int(comptime T: type, reader: *Reader) Error!T {
    const wide = try reader.read_int(IntBytes(T));
    // A width that ends inside a byte leaves bits no value sets; refuse them so every value
    // has one encoding.
    return std.math.cast(T, wide) orelse reader.invalid("Uint", "a bit is set beyond the width");
}

fn read_bool(reader: *Reader) Error!bool {
    return switch (try reader.read_byte()) {
        0 => false,
        1 => true,
        else => error.InvalidBool,
    };
}

fn read_tag(comptime T: type, reader: *Reader) Error!T {
    const Tag = @typeInfo(T).@"enum".tag_type;
    const raw = try reader.read_int(Tag);
    return std.enums.fromInt(T, raw) orelse
        reader.fail(error.InvalidEnum, @truncate(@as(u128, @bitCast(@as(i128, raw)))));
}

/// Reads a `usize` (a `UInt<u32>` varint) and checks it against `range`.
pub fn read_usize(reader: *Reader, range: RangeCfg(usize)) Error!usize {
    const value: usize = try varint.read(u32, reader);
    if (!range.contains(value)) return reader.fail(error.InvalidLength, value);
    return value;
}

fn read_array(comptime T: type, gpa: Allocator, reader: *Reader, cfg: Cfg(T)) Error!T {
    const info = @typeInfo(T).array;
    var result: T = undefined;
    if (info.child == u8) {
        @memcpy(&result, try reader.take(info.len));
        return result;
    }
    if (comptime fixed_size(info.child)) |size| try reader.at_least_items(info.len, size);
    var count: usize = 0;
    errdefer free_items(info.child, gpa, result[0..count]);
    while (count < info.len) : (count += 1) {
        result[count] = try read_cfg(info.child, gpa, reader, cfg);
    }
    return result;
}

/// Reads `len` items of `T` into a new slice (`Read::read_vec`). The buffer must hold every
/// fixed-size item before anything is allocated, so a hostile length fails fast.
pub fn read_items(
    comptime T: type,
    gpa: Allocator,
    reader: *Reader,
    len: usize,
    cfg: Cfg(T),
) Error![]T {
    if (T == u8) {
        const bytes = try reader.take(len);
        return gpa.dupe(u8, bytes);
    }
    if (comptime fixed_size(T)) |size| {
        try reader.at_least_items(len, size);
        const items = try gpa.alloc(T, len);
        var count: usize = 0;
        errdefer {
            free_items(T, gpa, items[0..count]);
            gpa.free(items);
        }
        while (count < len) : (count += 1) items[count] = try read_cfg(T, gpa, reader, cfg);
        return items;
    }
    // Variable-size items: each consumes at least one byte in practice, so the remaining
    // input bounds the up-front reservation.
    var list = try std.ArrayList(T).initCapacity(gpa, @min(len, reader.remaining()));
    errdefer {
        free_items(T, gpa, list.items);
        list.deinit(gpa);
    }
    var index: usize = 0;
    while (index < len) : (index += 1) {
        const item = try read_cfg(T, gpa, reader, cfg);
        list.append(gpa, item) catch |err| {
            free(T, gpa, item);
            return err;
        };
    }
    return list.toOwnedSlice(gpa);
}

fn read_tuple(comptime T: type, gpa: Allocator, reader: *Reader, cfg: Cfg(T)) Error!T {
    const field_types = @typeInfo(T).@"struct".field_types;
    var result: T = undefined;
    comptime var index: usize = 0;
    inline while (index < field_types.len) : (index += 1) {
        result[index] = read_cfg(field_types[index], gpa, reader, cfg[index]) catch |err| {
            inline for (0..index) |done| free(field_types[done], gpa, result[done]);
            return err;
        };
    }
    return result;
}

/// Releases memory owned by a value produced by `read_cfg`/`decode_cfg`.
pub fn free(comptime T: type, gpa: Allocator, value: T) void {
    if (comptime !owns_memory(T)) return;
    switch (comptime kind(T)) {
        .array => free_items(@typeInfo(T).array.child, gpa, &value),
        .optional => if (value) |inner| free(@TypeOf(inner), gpa, inner),
        .slice => {
            free_items(@typeInfo(T).pointer.child, gpa, value);
            gpa.free(value);
        },
        .pointer => {
            free(@typeInfo(T).pointer.child, gpa, value.*);
            gpa.destroy(value);
        },
        .tuple => inline for (@typeInfo(T).@"struct".field_types, 0..) |field_type, index| {
            free(field_type, gpa, value[index]);
        },
        .custom => {
            var copy = value;
            copy.deinit(gpa);
        },
        .bool, .int, .float, .tag, .usize => unreachable, // Proof: these own no memory.
    }
}

/// Releases memory owned by each of `items` (not the slice itself).
pub fn free_items(comptime T: type, gpa: Allocator, items: []const T) void {
    if (comptime !owns_memory(T)) return;
    for (items) |item| free(T, gpa, item);
}

/// Reads a value whose config is unit-like (`ReadExt::read`).
pub fn read(comptime T: type, gpa: Allocator, reader: *Reader) Error!T {
    return read_cfg(T, gpa, reader, unit_cfg(Cfg(T)));
}

/// Reads a slice-like value with a length range and unit item config
/// (`ReadRangeExt::read_range`).
pub fn read_range(
    comptime T: type,
    gpa: Allocator,
    reader: *Reader,
    range: RangeCfg(usize),
) Error!T {
    return read_cfg(T, gpa, reader, range_cfg(T, range));
}

fn range_cfg(comptime T: type, range: RangeCfg(usize)) Cfg(T) {
    const C = Cfg(T);
    if (C == RangeCfg(usize)) return range;
    if (@typeInfo(C) == .@"struct" and @hasField(C, "range")) {
        // Slices, sets, and maps: the range plus unit configs for their items.
        const info = @typeInfo(C).@"struct";
        var result: C = undefined;
        result.range = range;
        inline for (info.field_names, info.field_types) |name, field_type| {
            if (comptime std.mem.eql(u8, name, "range")) continue;
            @field(result, name) = unit_cfg(field_type);
        }
        return result;
    }
    @compileError("codec: config is not a range config: " ++ @typeName(C));
}

/// Reads a fixed-size value that allocates nothing.
pub fn read_fixed(comptime T: type, reader: *Reader) Error!T {
    comptime assert(fixed_size(T) != null and !owns_memory(T));
    return read_cfg(T, Allocator.failing, reader, unit_cfg(Cfg(T)));
}

/// Reads a value from `reader` and fails with `ExtraData` unless all input was consumed.
/// `reader.diagnostic` describes the failure.
pub fn decode_reader(comptime T: type, gpa: Allocator, reader: *Reader, cfg: Cfg(T)) Error!T {
    const value = try read_cfg(T, gpa, reader, cfg);
    const remaining = reader.remaining();
    if (remaining > 0) {
        free(T, gpa, value);
        return reader.fail(error.ExtraData, remaining);
    }
    return value;
}

/// Decodes `bytes` as exactly one value of `T` (`Decode::decode_cfg`).
pub fn decode_cfg(comptime T: type, gpa: Allocator, bytes: []const u8, cfg: Cfg(T)) Error!T {
    var reader = Reader.init(bytes);
    return decode_reader(T, gpa, &reader, cfg);
}

/// Decodes a value whose config is unit-like (`DecodeExt::decode`).
pub fn decode(comptime T: type, gpa: Allocator, bytes: []const u8) Error!T {
    return decode_cfg(T, gpa, bytes, unit_cfg(Cfg(T)));
}

/// Decodes a slice-like value with a length range (`DecodeRangeExt::decode_range`).
pub fn decode_range(
    comptime T: type,
    gpa: Allocator,
    bytes: []const u8,
    range: RangeCfg(usize),
) Error!T {
    return decode_cfg(T, gpa, bytes, range_cfg(T, range));
}

/// Decodes a fixed-size value that allocates nothing from exactly its encoded bytes
/// (`DecodeFixed::decode_fixed`).
pub fn decode_fixed(comptime T: type, bytes: *const [fixed_size(T).?]u8) Error!T {
    comptime assert(!owns_memory(T));
    return decode_cfg(T, Allocator.failing, bytes, unit_cfg(Cfg(T)));
}

/// Orders two values the way commonware's `Ord` does (the order maps and sets encode in):
/// integers and bools by value, arrays/slices/tuples lexicographically, null before any value,
/// tag enums by tag, pointers by pointee, custom types by their `order(a, b)` declaration.
pub fn order(comptime T: type, a: T, b: T) std.math.Order {
    switch (comptime kind(T)) {
        .bool => return std.math.order(@intFromBool(a), @intFromBool(b)),
        .int, .usize => return std.math.order(a, b),
        .float => @compileError("codec: floats have no total order (Rust f32/f64 are not Ord)"),
        .tag => return std.math.order(@backingInt(a), @backingInt(b)),
        .optional => {
            const left = a orelse return if (b == null) .eq else .lt;
            const right = b orelse return .gt;
            return order(@TypeOf(left), left, right);
        },
        .array => return order_items(@typeInfo(T).array.child, &a, &b),
        .slice => return order_items(@typeInfo(T).pointer.child, a, b),
        .pointer => return order(@typeInfo(T).pointer.child, a.*, b.*),
        .tuple => {
            inline for (@typeInfo(T).@"struct".field_types, 0..) |field_type, index| {
                const field_order = order(field_type, a[index], b[index]);
                if (field_order != .eq) return field_order;
            }
            return .eq;
        },
        .custom => {
            if (!@hasDecl(T, "order")) {
                @compileError("codec: " ++ @typeName(T) ++ " has no `order`");
            }
            return T.order(a, b);
        },
    }
}

/// Lexicographic order of two item sequences, then shorter first.
pub fn order_items(comptime T: type, a: []const T, b: []const T) std.math.Order {
    if (T == u8) return std.mem.order(u8, a, b);
    const common = @min(a.len, b.len);
    for (a[0..common], b[0..common]) |left, right| {
        const item_order = order(T, left, right);
        if (item_order != .eq) return item_order;
    }
    return std.math.order(a.len, b.len);
}

/// Writes `value` into the front of `out` and returns the written bytes. `out` must hold
/// at least `encode_size(T, value)` bytes.
pub fn encode_to(comptime T: type, value: T, out: []u8) []u8 {
    const size = encode_size(T, value);
    assert(out.len >= size);
    var writer = Writer.init(out[0..size]);
    write(T, value, &writer);
    assert(writer.end == size); // `encode_size` must match what `write` wrote.
    return writer.written();
}

/// Encodes `value` into a new exactly-sized buffer (`Encode::encode`). Caller owns it.
pub fn encode(comptime T: type, gpa: Allocator, value: T) Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, encode_size(T, value));
    const written = encode_to(T, value, out);
    assert(written.len == out.len);
    return out;
}

/// Encodes a fixed-size value into an array (`EncodeFixed::encode_fixed`).
pub fn encode_fixed(comptime T: type, value: T) [fixed_size(T).?]u8 {
    var out: [fixed_size(T).?]u8 = undefined;
    const written = encode_to(T, value, &out);
    assert(written.len == out.len);
    return out;
}
