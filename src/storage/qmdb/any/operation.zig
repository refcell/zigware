//! Operations for the `any` databases (qmdb/any/operation/**).
//!
//! `Operation(F, S)` is commonware's `Operation<F, S>` over an update type `S`:
//! `update.Unordered(K, E)` (key and value) or `update.Ordered(K, E)` (key, value, and the
//! next key in sorted order). The fixed encoding pads every operation to the largest of the
//! delete (`1 + K`), update (`1 + S`), and commit (`1 + 1 + V + 8`) sizes; the variable
//! encoding does not pad.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const value_mod = @import("../value.zig");
const operation = @import("../operation.zig");

/// Wire tag for `delete`.
pub const delete_context: u8 = 0xD1;
/// Wire tag for `update`.
pub const update_context: u8 = 0xD2;
/// Wire tag for `commit`.
pub const commit_context: u8 = 0xD3;

pub const update = struct {
    /// An unordered update: a key and its new value.
    pub fn Unordered(comptime K: type, comptime E: type) type {
        return Update(K, E, false);
    }

    /// An ordered update: a key, its new value, and the next active key in sorted order.
    pub fn Ordered(comptime K: type, comptime E: type) type {
        return Update(K, E, true);
    }
};

fn Update(comptime K: type, comptime E: type, comptime ordered: bool) type {
    value_mod.check(E);
    return struct {
        const Self = @This();
        pub const Key = K;
        pub const Value = E.Value;
        pub const Encoding = E;
        /// Whether updates carry the next key (commonware's `Parts::SIBLINGS`).
        pub const siblings = ordered;

        key: K,
        value: Value,
        /// The next key in sorted order; `void` for unordered updates.
        next_key: if (ordered) K else void = if (ordered) undefined else {},

        pub const Cfg = if (E.fixed) void else struct { codec.Cfg(K), codec.Cfg(Value) };
        pub const owns_memory = codec.owns_memory(K) or codec.owns_memory(Value);
        pub const fixed_size: ?usize = if (E.fixed)
            codec.fixed_size(K).? * (if (ordered) 2 else 1) + E.value_size
        else
            null;

        pub fn eql(a: Self, b: Self) bool {
            if (!value_mod.eql(K, a.key, b.key)) return false;
            if (!value_mod.eql(Value, a.value, b.value)) return false;
            if (comptime ordered) return value_mod.eql(K, a.next_key, b.next_key);
            return true;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            codec.free(K, gpa, self.key);
            codec.free(Value, gpa, self.value);
            if (comptime ordered) codec.free(K, gpa, self.next_key);
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            if (comptime E.fixed) return fixed_size.?;
            var size = codec.encode_size(K, self.key) + codec.encode_size(Value, self.value);
            if (comptime ordered) size += codec.encode_size(K, self.next_key);
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(K, self.key, writer);
            codec.write(Value, self.value, writer);
            if (comptime ordered) codec.write(K, self.next_key, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const key_cfg = if (comptime E.fixed) codec.unit_cfg(codec.Cfg(K)) else cfg[0];
            const value_cfg = if (comptime E.fixed) codec.unit_cfg(codec.Cfg(Value)) else cfg[1];
            const key = try codec.read_cfg(K, gpa, reader, key_cfg);
            errdefer codec.free(K, gpa, key);
            const value = try codec.read_cfg(Value, gpa, reader, value_cfg);
            if (comptime !ordered) return .{ .key = key, .value = value };
            errdefer codec.free(Value, gpa, value);
            const next_key = try codec.read_cfg(K, gpa, reader, key_cfg);
            return .{ .key = key, .value = value, .next_key = next_key };
        }

        /// commonware's `Update::fmt`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("[key:{x}", .{value_mod.bytes(K, &self.key)});
            if (comptime ordered) {
                try writer.print(" next_key:{x}", .{value_mod.bytes(K, &self.next_key)});
            }
            try writer.writeAll(" value:");
            try operation.format_encoded(Value, self.value, writer);
            try writer.writeAll("]");
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const key = try value_mod.arbitrary(K, gpa, u);
            const value = try value_mod.arbitrary(Value, gpa, u);
            if (comptime !ordered) return .{ .key = key, .value = value };
            const next_key = try value_mod.arbitrary(K, gpa, u);
            return .{ .key = key, .value = value, .next_key = next_key };
        }
    };
}

/// An operation of an `any` database over update type `S`.
pub fn Operation(comptime F: type, comptime S: type) type {
    merkle.check_family(F);
    return union(enum) {
        const Self = @This();
        pub const Family = F;
        pub const Update = S;
        pub const Key = S.Key;
        pub const Value = S.Value;
        pub const Encoding = S.Encoding;
        pub const Commit = operation.Commit(Value);
        const fixed = S.Encoding.fixed;

        /// Deletes the key's value.
        delete: Key,
        /// Gives the key a value.
        update: S,
        /// Commits the database with optional metadata and an inactivity floor.
        commit: Commit,

        const delete_size: usize = if (fixed) 1 + codec.fixed_size(Key).? else 0;
        const update_size: usize = if (fixed) 1 + S.fixed_size.? else 0;
        const commit_size: usize = if (fixed) operation.commit_fixed_operation_size(Value) else 0;

        pub const Cfg = S.Cfg;
        pub const owns_memory = S.owns_memory;
        pub const fixed_size: ?usize = if (fixed)
            @max(update_size, @max(commit_size, delete_size))
        else
            null;

        pub fn key(self: *const Self) ?*const Key {
            return switch (self.*) {
                .delete => |*k| k,
                .update => |*u| &u.key,
                .commit => null,
            };
        }

        pub fn is_update(self: Self) bool {
            return self == .update;
        }

        pub fn is_delete(self: Self) bool {
            return self == .delete;
        }

        pub fn is_commit(self: Self) bool {
            return self == .commit;
        }

        pub fn inactivity_floor(self: Self) ?u64 {
            return switch (self) {
                .commit => |c| c.floor,
                else => null,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .delete => |k| value_mod.eql(Key, k, b.delete),
                .update => |u| u.eql(b.update),
                .commit => |c| c.floor == b.commit.floor and
                    value_mod.eql(?Value, c.metadata, b.commit.metadata),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .delete => |k| codec.free(Key, gpa, k),
                .update => |*u| u.deinit(gpa),
                .commit => |c| codec.free(?Value, gpa, c.metadata),
            }
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            if (comptime fixed) return fixed_size.?;
            return 1 + switch (self) {
                .delete => |k| codec.encode_size(Key, k),
                .update => |u| u.encode_size(),
                .commit => |c| operation.commit_variable_payload_size(Value, c),
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            const start = writer.end;
            switch (self) {
                .delete => |k| {
                    writer.write_byte(delete_context);
                    codec.write(Key, k, writer);
                    if (comptime fixed) writer.write_byte_n(0, fixed_size.? - delete_size);
                },
                .update => |u| {
                    writer.write_byte(update_context);
                    u.write(writer);
                    if (comptime fixed) writer.write_byte_n(0, fixed_size.? - update_size);
                },
                .commit => |c| {
                    writer.write_byte(commit_context);
                    if (comptime fixed) {
                        operation.write_commit_fixed(Value, c, writer);
                        writer.write_byte_n(0, fixed_size.? - commit_size);
                    } else {
                        operation.write_commit_variable(Value, c, writer);
                    }
                },
            }
            assert(writer.end - start == self.encode_size());
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            if (comptime fixed) return read_fixed(gpa, reader);
            return switch (try reader.read_byte()) {
                delete_context => .{ .delete = try codec.read_cfg(Key, gpa, reader, cfg[0]) },
                update_context => .{ .update = try S.read(gpa, reader, cfg) },
                commit_context => .{
                    .commit = try operation.read_commit_variable(F, Value, gpa, reader, cfg[1]),
                },
                else => |tag| reader.fail(error.InvalidEnum, tag),
            };
        }

        fn read_fixed(gpa: Allocator, reader: *codec.Reader) codec.Error!Self {
            const total = fixed_size.?;
            try codec.util.at_least(reader, total);
            return switch (try reader.read_byte()) {
                delete_context => delete: {
                    const k = try codec.read(Key, gpa, reader);
                    try codec.util.ensure_zeros(reader, total - delete_size);
                    break :delete .{ .delete = k };
                },
                update_context => update_op: {
                    const u = try S.read(gpa, reader, {});
                    try codec.util.ensure_zeros(reader, total - update_size);
                    break :update_op .{ .update = u };
                },
                commit_context => commit: {
                    const c = try operation.read_commit_fixed(F, Value, gpa, reader);
                    try codec.util.ensure_zeros(reader, total - commit_size);
                    break :commit .{ .commit = c };
                },
                else => |tag| reader.fail(error.InvalidEnum, tag),
            };
        }

        /// commonware's `Display`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .delete => |k| try writer.print("[key:{x} <deleted>]", .{value_mod.bytes(Key, &k)}),
                .update => |u| try u.format(writer),
                .commit => |c| try operation.format_commit(Value, c, writer),
            }
        }

        /// `Operation::arbitrary`.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return switch (u.int_in_range(u8, 0, 2)) {
                0 => .{ .delete = try value_mod.arbitrary(Key, gpa, u) },
                1 => .{ .update = try S.arbitrary(gpa, u) },
                2 => commit: {
                    const metadata = try value_mod.arbitrary(?Value, gpa, u);
                    const floor = operation.arbitrary_location(F, u);
                    break :commit .{ .commit = .{ .metadata = metadata, .floor = floor } };
                },
                else => unreachable, // Proof: int_in_range returns 0, 1, or 2.
            };
        }
    };
}

/// An ordered operation (commonware's `any::ordered::Operation`).
pub fn Ordered(comptime F: type, comptime K: type, comptime E: type) type {
    return Operation(F, update.Ordered(K, E));
}

/// An unordered operation (commonware's `any::unordered::Operation`).
pub fn Unordered(comptime F: type, comptime K: type, comptime E: type) type {
    return Operation(F, update.Unordered(K, E));
}

test {
    _ = @import("operation_test.zig");
}
