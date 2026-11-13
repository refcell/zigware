//! Operations for keyless stores (qmdb/keyless/operation/{mod,fixed,variable}.rs).
//!
//! `Operation(F, E)` is commonware's `Operation<F, V>` for a value encoding `E`
//! (`value.Fixed(V)` or `value.Variable(V)`). The fixed encoding pads every operation to the
//! commit size (`1 + 1 + V::SIZE + 8`); the variable encoding does not pad.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const value_mod = @import("../value.zig");
const operation = @import("../operation.zig");

/// Wire tag for `commit`.
pub const commit_context: u8 = 0;
/// Wire tag for `append`.
pub const append_context: u8 = 1;

pub fn Operation(comptime F: type, comptime E: type) type {
    merkle.check_family(F);
    value_mod.check(E);
    return union(enum) {
        const Self = @This();
        pub const Value = E.Value;
        pub const Family = F;
        pub const Encoding = E;
        pub const Commit = operation.Commit(Value);

        /// The value appended to the database by this operation.
        append: Value,
        /// The database has been committed, with optional metadata and the inactivity floor
        /// the application declared at commit time.
        commit: Commit,

        pub const Cfg = if (E.fixed) void else codec.Cfg(Value);
        pub const owns_memory = codec.owns_memory(Value);
        /// Every fixed-encoded operation has the commit's size; variable ones vary.
        pub const fixed_size: ?usize = if (E.fixed)
            operation.commit_fixed_operation_size(Value)
        else
            null;

        /// The value this operation carries, if any.
        pub fn into_value(self: Self) ?Value {
            return switch (self) {
                .append => |v| v,
                .commit => |c| c.metadata,
            };
        }

        pub fn inactivity_floor(self: Self) ?u64 {
            return switch (self) {
                .commit => |c| c.floor,
                .append => null,
            };
        }

        pub fn is_commit(self: Self) bool {
            return self == .commit;
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .append => |v| value_mod.eql(Value, v, b.append),
                .commit => |c| c.floor == b.commit.floor and
                    value_mod.eql(?Value, c.metadata, b.commit.metadata),
            };
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self) {
                .append => |v| .{ .append = try value_mod.clone(Value, gpa, v) },
                .commit => |c| .{ .commit = .{
                    .metadata = try value_mod.clone(?Value, gpa, c.metadata),
                    .floor = c.floor,
                } },
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .append => |v| codec.free(Value, gpa, v),
                .commit => |c| codec.free(?Value, gpa, c.metadata),
            }
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            if (comptime E.fixed) return fixed_size.?;
            return 1 + switch (self) {
                .append => |v| codec.encode_size(Value, v),
                .commit => |c| operation.commit_variable_payload_size(Value, c),
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            const start = writer.end;
            switch (self) {
                .append => |v| {
                    writer.write_byte(append_context);
                    codec.write(Value, v, writer);
                    // Pad to the uniform size: the option-tag gap and the floor gap.
                    if (comptime E.fixed) writer.write_byte_n(0, 1 + 8);
                },
                .commit => |c| {
                    writer.write_byte(commit_context);
                    if (comptime E.fixed) {
                        operation.write_commit_fixed(Value, c, writer);
                    } else {
                        operation.write_commit_variable(Value, c, writer);
                    }
                },
            }
            assert(writer.end - start == self.encode_size());
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            if (comptime E.fixed) {
                try codec.util.at_least(reader, fixed_size.?);
                return switch (try reader.read_byte()) {
                    append_context => append: {
                        const v = try codec.read(Value, gpa, reader);
                        try codec.util.ensure_zeros(reader, 1 + 8);
                        break :append .{ .append = v };
                    },
                    commit_context => .{
                        .commit = try operation.read_commit_fixed(F, Value, gpa, reader),
                    },
                    else => |tag| reader.fail(error.InvalidEnum, tag),
                };
            }
            return switch (try reader.read_byte()) {
                append_context => .{ .append = try codec.read_cfg(Value, gpa, reader, cfg) },
                commit_context => .{
                    .commit = try operation.read_commit_variable(F, Value, gpa, reader, cfg),
                },
                else => |tag| reader.fail(error.InvalidEnum, tag),
            };
        }

        /// commonware's `Display`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .append => |v| {
                    try writer.writeAll("[append value:");
                    try operation.format_encoded(Value, v, writer);
                    try writer.writeAll("]");
                },
                .commit => |c| try operation.format_commit(Value, c, writer),
            }
        }

        /// `Operation::arbitrary`.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return switch (u.int_in_range(u8, 0, 1)) {
                0 => .{ .append = try value_mod.arbitrary(Value, gpa, u) },
                1 => commit: {
                    const metadata = try value_mod.arbitrary(?Value, gpa, u);
                    const floor = operation.arbitrary_location(F, u);
                    break :commit .{ .commit = .{ .metadata = metadata, .floor = floor } };
                },
                else => unreachable, // Proof: int_in_range returns 0 or 1.
            };
        }
    };
}

test {
    _ = @import("operation_test.zig");
}
