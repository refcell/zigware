//! Ordered current proofs (commonware's `qmdb/current/ordered/proof.rs`): a key-value proof
//! carries the key's next key, and an exclusion proof shows a key is absent through the
//! active update whose `[key, next_key)` span covers it, or through the commit of an empty
//! database. Verification lands with current's database.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const any = @import("../../any/operation.zig");
const value = @import("../../value.zig");
const proof = @import("../proof.zig");

/// Exclusion-proof tag of a key-value span.
pub const key_value_context: u8 = 0;
/// Exclusion-proof tag of an empty database's commit.
pub const commit_context: u8 = 1;

/// A proof that a key has a value, with the next active key in sorted order.
pub fn KeyValueProof(
    comptime F: type,
    comptime K: type,
    comptime D: type,
    comptime chunk_size: ?usize,
) type {
    return struct {
        const Self = @This();
        pub const Operation = proof.OperationProof(F, D, chunk_size);
        pub const Cfg = struct { Operation.Cfg, codec.Cfg(K) };

        proof: Operation,
        next_key: K,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            codec.free(K, gpa, self.next_key);
            self.* = undefined;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.proof.eql(b.proof) and value.eql(K, a.next_key, b.next_key);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.proof.encode_size() + codec.encode_size(K, self.next_key);
            assert(size > self.proof.encode_size() or codec.fixed_size(K) == 0);
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            const start = writer.end;
            self.proof.write(writer);
            codec.write(K, self.next_key, writer);
            assert(writer.end > start);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            var operation_proof = try Operation.read(gpa, reader, cfg[0]);
            errdefer operation_proof.deinit(gpa);
            const next_key = try codec.read_cfg(K, gpa, reader, cfg[1]);
            return .{ .proof = operation_proof, .next_key = next_key };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            var operation_proof = try Operation.arbitrary(gpa, u);
            errdefer operation_proof.deinit(gpa);
            return .{ .proof = operation_proof, .next_key = try value.arbitrary(K, gpa, u) };
        }
    };
}

/// A proof that a key is absent: an active update whose cyclic span `[key, next_key)` covers
/// it, or the commit operation of an empty database with its metadata.
pub fn ExclusionProof(
    comptime F: type,
    comptime K: type,
    comptime E: type,
    comptime D: type,
    comptime chunk_size: ?usize,
) type {
    return union(enum) {
        const Self = @This();
        pub const Operation = proof.OperationProof(F, D, chunk_size);
        pub const Update = any.update.Ordered(K, E);
        pub const Value = E.Value;
        pub const Cfg = struct { Operation.Cfg, codec.Cfg(Update), codec.Cfg(Value) };

        key_value: struct { proof: Operation, update: Update },
        commit: struct { proof: Operation, value: ?Value },

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .key_value => |*span| {
                    span.proof.deinit(gpa);
                    span.update.deinit(gpa);
                },
                .commit => |*commit| {
                    commit.proof.deinit(gpa);
                    codec.free(?Value, gpa, commit.value);
                },
            }
            self.* = undefined;
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .key_value => |span| span.proof.eql(b.key_value.proof) and
                    span.update.eql(b.key_value.update),
                .commit => |commit| commit.proof.eql(b.commit.proof) and
                    value.eql(?Value, commit.value, b.commit.value),
            };
        }

        pub fn encode_size(self: Self) usize {
            const size: usize = 1 + switch (self) {
                .key_value => |span| span.proof.encode_size() +
                    codec.encode_size(Update, span.update),
                .commit => |commit| commit.proof.encode_size() +
                    codec.encode_size(?Value, commit.value),
            };
            assert(size > 1);
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            write_exclusion(Self, self, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return read_exclusion(Self, gpa, reader, cfg);
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return arbitrary_exclusion(Self, gpa, u);
        }
    };
}

fn write_exclusion(comptime Self: type, self: Self, writer: *codec.Writer) void {
    const start = writer.end;
    switch (self) {
        .key_value => |span| {
            writer.write_byte(key_value_context);
            span.proof.write(writer);
            codec.write(Self.Update, span.update, writer);
        },
        .commit => |commit| {
            writer.write_byte(commit_context);
            commit.proof.write(writer);
            codec.write(?Self.Value, commit.value, writer);
        },
    }
    assert(writer.end > start + 1);
}

fn read_exclusion(
    comptime Self: type,
    gpa: Allocator,
    reader: *codec.Reader,
    cfg: Self.Cfg,
) codec.Error!Self {
    const tag = try reader.read_byte();
    if (tag != key_value_context and tag != commit_context) {
        return reader.fail(error.InvalidEnum, tag);
    }
    var operation = try Self.Operation.read(gpa, reader, cfg[0]);
    errdefer operation.deinit(gpa);
    if (tag == key_value_context) {
        const update = try codec.read_cfg(Self.Update, gpa, reader, cfg[1]);
        return .{ .key_value = .{ .proof = operation, .update = update } };
    }
    assert(tag == commit_context);
    const metadata = try codec.read_cfg(?Self.Value, gpa, reader, cfg[2]);
    return .{ .commit = .{ .proof = operation, .value = metadata } };
}

fn arbitrary_exclusion(
    comptime Self: type,
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!Self {
    var operation = try Self.Operation.arbitrary(gpa, u);
    errdefer operation.deinit(gpa);
    if (u.boolean()) {
        const update = try Self.Update.arbitrary(gpa, u);
        return .{ .key_value = .{ .proof = operation, .update = update } };
    }
    const metadata = try value.arbitrary(?Self.Value, gpa, u);
    assert(operation.chunk.len > 0);
    return .{ .commit = .{ .proof = operation, .value = metadata } };
}

/// Proofs with fixed-size bitmap chunks.
pub const constant = struct {
    pub fn KeyValue(comptime F: type, comptime K: type, comptime D: type, comptime N: usize) type {
        return KeyValueProof(F, K, D, N);
    }

    pub fn Exclusion(
        comptime F: type,
        comptime K: type,
        comptime E: type,
        comptime D: type,
        comptime N: usize,
    ) type {
        return ExclusionProof(F, K, E, D, N);
    }
};

/// Proofs with runtime-sized bitmap chunks.
pub const dynamic = struct {
    pub fn KeyValue(comptime F: type, comptime K: type, comptime D: type) type {
        return KeyValueProof(F, K, D, null);
    }

    pub fn Exclusion(comptime F: type, comptime K: type, comptime E: type, comptime D: type) type {
        return ExclusionProof(F, K, E, D, null);
    }
};
