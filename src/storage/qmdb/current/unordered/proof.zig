//! Unordered current proofs (commonware's `qmdb/current/unordered/proof.rs`): a key-value
//! proof is an operation proof of the key's active update.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const proof = @import("../proof.zig");
const verification = @import("../verification.zig");
const operation = @import("../../any/operation.zig");

/// A proof that a key has a value in the database. Chunk sizes are as in
/// `proof.OperationProof`.
pub fn KeyValueProof(comptime F: type, comptime D: type, comptime chunk_size: ?usize) type {
    return struct {
        const Self = @This();
        pub const Operation = proof.OperationProof(F, D, chunk_size);
        pub const Cfg = Operation.Cfg;

        /// The proof that the key's update is active.
        proof: Operation,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        /// Whether this proves that `key` holds `value` in a database with canonical `root`:
        /// that `Update(key, value)` (of update type `U`, fixed-size) is active there.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            comptime U: type,
            key: U.Key,
            value: U.Value,
            root: *const D,
        ) bool {
            const Op = operation.Operation(F, U);
            comptime assert(!U.siblings);
            const op: Op = .{ .update = .{ .key = key, .value = value } };
            return verification.verify_typed_operation(F, H, Op, &self.proof, op, root);
        }

        /// `verify` for update types that own memory, encoding the update with `gpa`.
        pub fn verify_alloc(
            self: *const Self,
            gpa: Allocator,
            comptime H: type,
            comptime U: type,
            key: U.Key,
            value: U.Value,
            root: *const D,
        ) Allocator.Error!bool {
            const Op = operation.Operation(F, U);
            comptime assert(!U.siblings);
            const op: Op = .{ .update = .{ .key = key, .value = value } };
            const verify_op = verification.verify_typed_operation_alloc;
            return verify_op(F, H, Op, gpa, &self.proof, op, root);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.proof.eql(b.proof);
        }

        pub fn encode_size(self: Self) usize {
            const size = self.proof.encode_size();
            assert(size > 0);
            return size;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            const start = writer.end;
            self.proof.write(writer);
            assert(writer.end > start);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return .{ .proof = try Operation.read(gpa, reader, cfg) };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return .{ .proof = try Operation.arbitrary(gpa, u) };
        }
    };
}

/// Proofs with fixed-size bitmap chunks.
pub const constant = struct {
    pub fn KeyValue(comptime F: type, comptime D: type, comptime N: usize) type {
        return KeyValueProof(F, D, N);
    }
};

/// Proofs with runtime-sized bitmap chunks.
pub const dynamic = struct {
    pub fn KeyValue(comptime F: type, comptime D: type) type {
        return KeyValueProof(F, D, null);
    }
};
