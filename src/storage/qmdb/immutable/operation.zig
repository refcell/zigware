//! Operations for immutable authenticated databases (qmdb/immutable/operation/*.rs).
//!
//! An immutable database only adds new keyed values: no updates or deletions. The fixed
//! encoding pads every operation to `max(1 + K + V, 1 + 1 + V + 8)` bytes; the variable
//! encoding does not pad.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const value_mod = @import("../value.zig");
const operation = @import("../operation.zig");

pub const set_context = operation.set_context;
pub const commit_context = operation.commit_context;

pub fn Operation(comptime F: type, comptime K: type, comptime E: type) type {
    merkle.check_family(F);
    value_mod.check(E);
    return union(enum) {
        const Self = @This();
        pub const Key = K;
        pub const Value = E.Value;
        pub const Family = F;
        pub const Encoding = E;
        pub const Commit = operation.Commit(Value);
        pub const Set = struct { key: K, value: Value };

        /// Sets a key to a value. The key must not already exist.
        set: Set,
        /// Commits the database with optional metadata and an inactivity floor.
        commit: Commit,

        const set_size: usize = if (E.fixed) 1 + codec.fixed_size(K).? + E.value_size else 0;
        const commit_size: usize = if (E.fixed) operation.commit_fixed_operation_size(Value) else 0;

        pub const Cfg = if (E.fixed) void else struct { codec.Cfg(K), codec.Cfg(Value) };
        pub const owns_memory = codec.owns_memory(K) or codec.owns_memory(Value);
        pub const fixed_size: ?usize = if (E.fixed) @max(set_size, commit_size) else null;

        pub fn key(self: *const Self) ?*const K {
            return switch (self.*) {
                .set => |*s| &s.key,
                .commit => null,
            };
        }

        pub fn is_commit(self: Self) bool {
            return self == .commit;
        }

        pub fn is_update(self: Self) bool {
            return self == .set;
        }

        /// Immutable databases do not support deletion.
        pub fn is_delete(_: Self) bool {
            return false;
        }

        pub fn inactivity_floor(self: Self) ?u64 {
            return switch (self) {
                .commit => |c| c.floor,
                .set => null,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .set => |s| value_mod.eql(K, s.key, b.set.key) and
                    value_mod.eql(Value, s.value, b.set.value),
                .commit => |c| c.floor == b.commit.floor and
                    value_mod.eql(?Value, c.metadata, b.commit.metadata),
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .set => |s| {
                    codec.free(K, gpa, s.key);
                    codec.free(Value, gpa, s.value);
                },
                .commit => |c| codec.free(?Value, gpa, c.metadata),
            }
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            if (comptime E.fixed) return fixed_size.?;
            return 1 + switch (self) {
                .set => |s| codec.encode_size(K, s.key) + codec.encode_size(Value, s.value),
                .commit => |c| operation.commit_variable_payload_size(Value, c),
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            const start = writer.end;
            switch (self) {
                .set => |s| {
                    writer.write_byte(set_context);
                    codec.write(K, s.key, writer);
                    codec.write(Value, s.value, writer);
                    if (comptime E.fixed) writer.write_byte_n(0, fixed_size.? - set_size);
                },
                .commit => |c| {
                    writer.write_byte(commit_context);
                    if (comptime E.fixed) {
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
            if (comptime E.fixed) return read_fixed(gpa, reader);
            return switch (try reader.read_byte()) {
                set_context => set: {
                    const k = try codec.read_cfg(K, gpa, reader, cfg[0]);
                    errdefer codec.free(K, gpa, k);
                    const v = try codec.read_cfg(Value, gpa, reader, cfg[1]);
                    break :set .{ .set = .{ .key = k, .value = v } };
                },
                commit_context => .{
                    .commit = try operation.read_commit_variable(F, Value, gpa, reader, cfg[1]),
                },
                else => |tag| reader.fail(error.InvalidEnum, tag),
            };
        }

        fn read_fixed(gpa: Allocator, reader: *codec.Reader) codec.Error!Self {
            try codec.util.at_least(reader, fixed_size.?);
            return switch (try reader.read_byte()) {
                set_context => set: {
                    const k = try codec.read(K, gpa, reader);
                    const v = try codec.read(Value, gpa, reader);
                    try codec.util.ensure_zeros(reader, fixed_size.? - set_size);
                    break :set .{ .set = .{ .key = k, .value = v } };
                },
                commit_context => commit: {
                    const c = try operation.read_commit_fixed(F, Value, gpa, reader);
                    try codec.util.ensure_zeros(reader, fixed_size.? - commit_size);
                    break :commit .{ .commit = c };
                },
                else => |tag| reader.fail(error.InvalidEnum, tag),
            };
        }

        /// commonware's `Display`.
        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .set => |s| {
                    try writer.print("[key:{x} value:", .{value_mod.bytes(K, &s.key)});
                    try operation.format_encoded(Value, s.value, writer);
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
                0 => set: {
                    const k = try value_mod.arbitrary(K, gpa, u);
                    const v = try value_mod.arbitrary(Value, gpa, u);
                    break :set .{ .set = .{ .key = k, .value = v } };
                },
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
