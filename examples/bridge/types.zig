//! The bridge's wire messages (commonware `examples/bridge/src/types`): the block format
//! validators agree on, the requests a validator sends the indexer (`Inbound`), and the
//! indexer's responses (`Outbound`). Enums encode as a `u8` tag then the variant, structs as
//! their fields in order, and an unknown tag fails as `InvalidEnum`, byte for byte as in
//! commonware. No value here owns memory.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const lib = @import("lib.zig");

const codec = zigware.codec;

/// A finalization certificate from one network.
pub const Finalization = zigware.consensus.simplex.types.Finalization(lib.Scheme, lib.Digest);
/// A network's identity: the constant term of its threshold polynomial.
pub const Public = lib.Variant.Public;

/// What a block carries (commonware `BlockFormat`).
pub const BlockFormat = union(enum(u8)) {
    /// Arbitrary data.
    random: u128,
    /// A finalization certificate of a block from the other network.
    bridge: Finalization,

    pub const write = Tagged(BlockFormat).write;
    pub const encode_size = Tagged(BlockFormat).encode_size;
    pub const read = Tagged(BlockFormat).read;
};

/// A request from a validator to the indexer (commonware `Inbound`).
pub const Inbound = union(enum(u8)) {
    put_block: PutBlock,
    get_block: GetBlock,
    put_finalization: PutFinalization,
    get_finalization: GetFinalization,

    pub const write = Tagged(Inbound).write;
    pub const encode_size = Tagged(Inbound).encode_size;
    pub const read = Tagged(Inbound).read;
};

/// Store a block for `network`.
pub const PutBlock = struct {
    network: Public,
    block: BlockFormat,

    pub const write = Fields(PutBlock).write;
    pub const encode_size = Fields(PutBlock).encode_size;
    pub const read = Fields(PutBlock).read;
};

/// Fetch `network`'s block named `digest`.
pub const GetBlock = struct {
    network: Public,
    digest: lib.Digest,

    pub const write = Fields(GetBlock).write;
    pub const encode_size = Fields(GetBlock).encode_size;
    pub const read = Fields(GetBlock).read;
};

/// Store a finalization certificate for `network`.
pub const PutFinalization = struct {
    network: Public,
    finalization: Finalization,

    pub const write = Fields(PutFinalization).write;
    pub const encode_size = Fields(PutFinalization).encode_size;
    pub const read = Fields(PutFinalization).read;
};

/// Fetch `network`'s latest finalization certificate.
pub const GetFinalization = struct {
    network: Public,

    pub const write = Fields(GetFinalization).write;
    pub const encode_size = Fields(GetFinalization).encode_size;
    pub const read = Fields(GetFinalization).read;
};

/// The indexer's response to an `Inbound` (commonware `Outbound`).
pub const Outbound = union(enum(u8)) {
    /// Whether a put succeeded, or `false` when a get found nothing.
    success: bool,
    /// The block a `get_block` asked for.
    block: BlockFormat,
    /// The finalization a `get_finalization` asked for.
    finalization: Finalization,

    pub const write = Tagged(Outbound).write;
    pub const encode_size = Tagged(Outbound).encode_size;
    pub const read = Tagged(Outbound).read;
};

/// The largest `Outbound` encoding: a tag, a block's tag, and a finalization.
pub const outbound_size_max = 2 + Finalization.max_encode_size_for(0);

/// codec for an enum: the variant's index as a `u8`, then the variant.
fn Tagged(comptime U: type) type {
    const info = @typeInfo(U).@"union";
    comptime assert(info.tag_type != null);
    comptime assert(info.field_names.len > 0 and info.field_names.len <= 256);
    return struct {
        pub fn write(self: U, writer: *codec.Writer) void {
            const tag = @backingInt(std.meta.activeTag(self));
            assert(tag < info.field_names.len);
            writer.write_byte(@intCast(tag));
            switch (self) {
                inline else => |payload| codec.write(@TypeOf(payload), payload, writer),
            }
        }

        pub fn encode_size(self: U) usize {
            const size = switch (self) {
                inline else => |payload| codec.encode_size(@TypeOf(payload), payload),
            };
            assert(size > 0);
            return 1 + size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!U {
            const tag = try reader.read_byte();
            inline for (info.field_names, info.field_types, 0..) |name, Field, index| {
                if (tag == index) return @unionInit(U, name, try codec.read(Field, gpa, reader));
            }
            assert(tag >= info.field_names.len);
            return error.InvalidEnum;
        }
    };
}

/// codec for a struct: its fields in declaration order.
fn Fields(comptime T: type) type {
    const info = @typeInfo(T).@"struct";
    comptime assert(info.layout == .auto);
    comptime assert(info.field_names.len > 0);
    return struct {
        pub fn write(self: T, writer: *codec.Writer) void {
            inline for (info.field_names, info.field_types) |name, Field| {
                codec.write(Field, @field(self, name), writer);
            }
        }

        pub fn encode_size(self: T) usize {
            var size: usize = 0;
            inline for (info.field_names, info.field_types) |name, Field| {
                size += codec.encode_size(Field, @field(self, name));
            }
            assert(size > 0);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!T {
            var self: T = undefined;
            inline for (info.field_names, info.field_types) |name, Field| {
                @field(self, name) = try codec.read(Field, gpa, reader);
            }
            return self;
        }
    };
}

test {
    _ = @import("types_test.zig");
}
