//! The encoding every simplex message enum shares: a `u8` tag (the variant's position) then
//! the variant's own encoding, with unknown tags rejected as `Invalid(<context>, "Invalid
//! type")`. A union opts in by forwarding its codec methods here.
//!
//! On read, a variant whose config type equals the union's config gets that config (the
//! certificate config); every other variant reads with its unit config, as in commonware.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const types = @import("../types.zig");

fn assert_union(comptime U: type) void {
    comptime {
        const info = @typeInfo(U).@"union";
        assert(info.tag_type != null);
        assert(info.field_names.len > 0 and info.field_names.len <= 256);
    }
}

fn tag_of(value: anytype) u8 {
    const index = @backingInt(std.meta.activeTag(value));
    assert(index < @typeInfo(@TypeOf(value)).@"union".field_names.len);
    return @intCast(index);
}

pub fn write(comptime U: type, value: U, writer: *codec.Writer) void {
    comptime assert_union(U);
    writer.write_byte(tag_of(value));
    switch (value) {
        inline else => |payload| codec.write(@TypeOf(payload), payload, writer),
    }
}

pub fn encode_size(comptime U: type, value: U) usize {
    comptime assert_union(U);
    const size = switch (value) {
        inline else => |payload| codec.encode_size(@TypeOf(payload), payload),
    };
    return 1 + size;
}

pub fn read(
    comptime U: type,
    comptime context: []const u8,
    gpa: Allocator,
    reader: *codec.Reader,
    cfg: anytype,
) codec.Error!U {
    comptime assert_union(U);
    const tag = try reader.read_byte();
    const info = @typeInfo(U).@"union";
    inline for (info.field_names, info.field_types, 0..) |name, Field, index| {
        if (tag == index) {
            const FieldCfg = codec.Cfg(Field);
            const field_cfg: FieldCfg = if (FieldCfg == @TypeOf(cfg))
                cfg
            else
                codec.unit_cfg(FieldCfg);
            const payload = try codec.read_cfg(Field, gpa, reader, field_cfg);
            return @unionInit(U, name, payload);
        }
    }
    return reader.invalid(context, "Invalid type");
}

/// commonware's `int_in_range(0..=n-1)` tag, then the variant's `Arbitrary`.
pub fn arbitrary(
    comptime U: type,
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!U {
    comptime assert_union(U);
    const info = @typeInfo(U).@"union";
    const tag = u.int_in_range(u32, 0, info.field_names.len - 1);
    inline for (info.field_names, info.field_types, 0..) |name, Field, index| {
        if (tag == index) {
            const payload = try codec.arbitrary.value(Field, gpa, u);
            return @unionInit(U, name, payload);
        }
    }
    unreachable; // Proof: int_in_range returns a value in [0, field count - 1].
}

/// Frees whatever the active variant's decode allocated.
pub fn deinit(comptime U: type, value: *U, gpa: Allocator) void {
    comptime assert_union(U);
    switch (value.*) {
        inline else => |payload| codec.free(@TypeOf(payload), gpa, payload),
    }
    value.* = undefined;
}

pub fn epoch(value: anytype) types.Epoch {
    return switch (value) {
        inline else => |payload| payload.epoch(),
    };
}

pub fn view(value: anytype) types.View {
    return switch (value) {
        inline else => |payload| payload.view(),
    };
}

/// Variant-wise equality through each payload's `eql`.
pub fn eql(a: anytype, b: @TypeOf(a)) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        inline else => |payload, tag| payload.eql(@field(b, @tagName(tag))),
    };
}
