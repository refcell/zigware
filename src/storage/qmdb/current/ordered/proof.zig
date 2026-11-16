//! Ordered current proofs (commonware's `qmdb/current/ordered/proof.rs`): a key-value proof
//! carries the key's next key, and an exclusion proof shows a key is absent through the
//! active update whose `[key, next_key)` span covers it, or through the commit of an empty
//! database.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const any = @import("../../any/operation.zig");
const value = @import("../../value.zig");
const proof = @import("../proof.zig");
const verification = @import("../verification.zig");
const ordered = @import("../../any/ordered.zig");

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

        /// Whether this proves that `key` holds `value` (with this proof's next key) in a
        /// database with canonical `root`; `U` is the database's ordered update type.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            comptime U: type,
            key: K,
            value_of_key: U.Value,
            root: *const D,
        ) bool {
            comptime assert(U.siblings and U.Key == K);
            const update: U = .{ .key = key, .value = value_of_key, .next_key = self.next_key };
            return verify_update(F, H, U, &self.proof, update, root);
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
            deinit_exclusion(Self, self, gpa);
        }

        /// Whether this proves `key` absent from a database with canonical `root`.
        pub fn verify(self: *const Self, comptime H: type, key: K, root: *const D) bool {
            return verify_exclusion(F, H, Self, self, key, root);
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

fn deinit_exclusion(comptime Self: type, self: *Self, gpa: Allocator) void {
    switch (self.*) {
        .key_value => |*span| {
            span.proof.deinit(gpa);
            span.update.deinit(gpa);
        },
        .commit => |*commit| {
            commit.proof.deinit(gpa);
            codec.free(?Self.Value, gpa, commit.value);
        },
    }
    self.* = undefined;
}

/// Whether `operation_proof` shows the ordered update `update` active under `root`.
fn verify_update(
    comptime F: type,
    comptime H: type,
    comptime U: type,
    operation_proof: anytype,
    update: U,
    root: *const H.Digest,
) bool {
    comptime assert(U.siblings);
    const Op = any.Operation(F, U);
    const op: Op = .{ .update = update };
    return verification.verify_fixed_operation(F, H, Op, operation_proof, op, root);
}

/// `ExclusionProof.verify`: the proven update's cyclic span `[key, next_key)` covers `key` and
/// is not its own, or the proven commit is an empty database's (its floor is its location).
fn verify_exclusion(
    comptime F: type,
    comptime H: type,
    comptime Self: type,
    self: *const Self,
    key: Self.Update.Key,
    root: *const H.Digest,
) bool {
    const K = Self.Update.Key;
    switch (self.*) {
        .key_value => |*span| {
            const update = &span.update;
            if (value.eql(K, update.key, key)) return false;
            if (!ordered.in_span(K, &update.key, &update.next_key, &key)) return false;
            return verify_update(F, H, Self.Update, &span.proof, update.*, root);
        },
        .commit => |*commit| {
            const Op = any.Operation(F, Self.Update);
            const floor = commit.proof.loc;
            const op: Op = .{ .commit = .{ .metadata = commit.value, .floor = floor } };
            return verification.verify_fixed_operation(F, H, Op, &commit.proof, op, root);
        },
    }
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
