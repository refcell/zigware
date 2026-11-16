//! Sync wire types (commonware's `qmdb/sync/source.rs`): the `Request` a client sends a source
//! and the `Response` it answers with, plus `max_response_size`. The `Source` interface and
//! `Feedback` come with the engine.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const operation = @import("../operation.zig");
const value = @import("../value.zig");

/// A request for operations from a source's log.
pub fn Request(comptime F: type) type {
    merkle.check_family(F);
    return union(enum) {
        const Self = @This();

        /// Fetch the operations in `[start, start + max_ops)`, proven against the root the
        /// database had at `size`.
        operations: struct { size: u64, start: u64, max_ops: u64 },
        /// Fetch the single operation at `start` plus the pinned nodes at `start`, the lowest
        /// location the client will retain. The response's proof authenticates the pinned nodes.
        boundary: struct { size: u64, start: u64 },

        /// The widest variant: a tag, two locations, and an operation count.
        pub const max_encode_size: usize = 1 + 2 * codec.varint.max_size(u64) + 8;

        /// The size whose root the response's proof must verify against.
        pub fn size(self: Self) u64 {
            return switch (self) {
                inline else => |request| request.size,
            };
        }

        /// The first operation to return.
        pub fn start(self: Self) u64 {
            return switch (self) {
                inline else => |request| request.start,
            };
        }

        /// The most operations to return (one for a boundary request).
        pub fn max_ops(self: Self) u64 {
            const result: u64 = switch (self) {
                .operations => |request| request.max_ops,
                .boundary => 1,
            };
            assert(result > 0);
            return result;
        }

        /// commonware's total order: `(size, start, max_ops, is_boundary)`.
        pub fn order(a: Self, b: Self) std.math.Order {
            const keys = [2][4]u64{ a.order_key(), b.order_key() };
            for (keys[0], keys[1]) |x, y| {
                const result = std.math.order(x, y);
                if (result != .eq) return result;
            }
            return .eq;
        }

        fn order_key(self: Self) [4]u64 {
            return .{ self.size(), self.start(), self.max_ops(), @intFromBool(self == .boundary) };
        }

        pub fn eql(a: Self, b: Self) bool {
            return order(a, b) == .eq;
        }

        pub fn encode_size(self: Self) usize {
            const locations = operation.location_size(self.size()) +
                operation.location_size(self.start());
            return 1 + locations + @as(usize, if (self == .operations) 8 else 0);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            assert(self.start() < self.size());
            writer.write_byte(@backingInt(self));
            operation.write_location(self.size(), writer);
            operation.write_location(self.start(), writer);
            if (self == .operations) writer.write_int(u64, self.operations.max_ops);
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const tag = try reader.read_byte();
            if (tag > 1) return reader.fail(error.InvalidEnum, tag);
            const request_size = try operation.read_location(F, reader);
            const request_start = try operation.read_location(F, reader);
            const request: Self = if (tag == 0) .{ .operations = .{
                .size = request_size,
                .start = request_start,
                .max_ops = try read_non_zero(reader),
            } } else .{ .boundary = .{ .size = request_size, .start = request_start } };
            if (request.start() >= request.size()) {
                return reader.invalid("Request", "start >= size");
            }
            return request;
        }

        fn read_non_zero(reader: *codec.Reader) codec.Error!u64 {
            const count = try reader.read_int(u64);
            if (count == 0) return reader.invalid("NonZeroU64", "value is zero");
            return count;
        }

        pub fn arbitrary(
            _: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const request_size = u.int_in_range(u64, 1, F.max_leaves);
            const request_start = u.int_in_range(u64, 0, request_size - 1);
            if (u.boolean()) {
                return .{ .boundary = .{ .size = request_size, .start = request_start } };
            }
            // `NonZeroU64::arbitrary`: a zero draw is an incorrect format.
            const count = u.int(u64);
            if (count == 0) return error.IncorrectFormat;
            return .{ .operations = .{
                .size = request_size,
                .start = request_start,
                .max_ops = count,
            } };
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .operations => |request| try writer.print(
                    "Operations(size={d}, start={d}, max={d})",
                    .{ request.size, request.start, request.max_ops },
                ),
                .boundary => |request| try writer.print(
                    "Boundary(size={d}, start={d})",
                    .{ request.size, request.start },
                ),
            }
        }
    };
}

/// `Proof::arbitrary` (commonware's derive): a location, a `usize`, and collected digests.
pub fn arbitrary_proof(
    comptime F: type,
    comptime D: type,
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error!merkle.Proof(F, D) {
    const leaves = operation.arbitrary_location(F, u);
    const inactive_peaks: usize = @intCast(u.int(u64));
    return .{
        .leaves = leaves,
        .inactive_peaks = inactive_peaks,
        .digests = try arbitrary_digests(D, gpa, u),
    };
}

/// `Vec<D>::arbitrary`: a continuation bit before each digest.
pub fn arbitrary_digests(
    comptime D: type,
    gpa: Allocator,
    u: *codec.arbitrary.Unstructured,
) codec.arbitrary.Error![]D {
    var digests: std.ArrayList(D) = .empty;
    errdefer digests.deinit(gpa);
    while (u.keep_going()) try digests.append(gpa, try value.arbitrary(D, gpa, u));
    return digests.toOwnedSlice(gpa);
}

/// One response, shaped like the `Request` it answers. Owns its proof, operations, and pinned
/// nodes: free it with `deinit`.
pub fn Response(comptime F: type, comptime Op: type, comptime D: type) type {
    merkle.check_family(F);
    return union(enum) {
        const Self = @This();
        pub const Proof = merkle.Proof(F, D);
        /// The `max_ops` the request asked for, and the configuration of one operation.
        pub const Cfg = struct { max_ops: usize, op: codec.Cfg(Op) };

        /// Answer to an operations request.
        operations: struct { proof: Proof, operations: []Op },
        /// Answer to a boundary request: the proof, the operation, and the pinned nodes are
        /// verified as a unit.
        boundary: struct { proof: Proof, op: Op, pinned_nodes: []D },

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .operations => |*response| {
                    response.proof.deinit(gpa);
                    for (response.operations) |item| codec.free(Op, gpa, item);
                    gpa.free(response.operations);
                },
                .boundary => |*response| {
                    response.proof.deinit(gpa);
                    codec.free(Op, gpa, response.op);
                    gpa.free(response.pinned_nodes);
                },
            }
            self.* = undefined;
        }

        /// The proof authenticating this response.
        pub fn proof(self: *const Self) *const Proof {
            return switch (self.*) {
                inline else => |*response| &response.proof,
            };
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .operations => |response| response.proof.encode_size() +
                    codec.encode_size([]const Op, response.operations),
                .boundary => |response| response.proof.encode_size() +
                    codec.encode_size(Op, response.op) +
                    codec.encode_size([]const D, response.pinned_nodes),
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_byte(@backingInt(self));
            switch (self) {
                .operations => |response| {
                    response.proof.write(writer);
                    codec.write([]const Op, response.operations, writer);
                },
                .boundary => |response| {
                    response.proof.write(writer);
                    codec.write(Op, response.op, writer);
                    codec.write([]const D, response.pinned_nodes, writer);
                },
            }
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const tag = try reader.read_byte();
            return switch (tag) {
                0 => read_operations(gpa, reader, cfg),
                1 => read_boundary(gpa, reader, cfg),
                else => reader.fail(error.InvalidEnum, tag),
            };
        }

        fn read_operations(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const max_digests = std.math.mul(usize, cfg.max_ops, max_digests_per_element) catch
                std.math.maxInt(usize);
            var response_proof = try Proof.read(gpa, reader, max_digests);
            errdefer response_proof.deinit(gpa);
            const range: codec.RangeCfg(usize) = .to_inclusive(cfg.max_ops);
            const items_cfg: codec.Cfg([]const Op) = .{ .range = range, .item = cfg.op };
            const items = try codec.read_cfg([]const Op, gpa, reader, items_cfg);
            return .{ .operations = .{ .proof = response_proof, .operations = @constCast(items) } };
        }

        fn read_boundary(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            var response_proof = try Proof.read(gpa, reader, max_digests_per_element);
            errdefer response_proof.deinit(gpa);
            const op = try codec.read_cfg(Op, gpa, reader, cfg.op);
            errdefer codec.free(Op, gpa, op);
            const range: codec.RangeCfg(usize) = .to_inclusive(merkle.max_pinned_nodes);
            const pinned = try codec.read_range([]const D, gpa, reader, range);
            return .{ .boundary = .{
                .proof = response_proof,
                .op = op,
                .pinned_nodes = @constCast(pinned),
            } };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            if (u.boolean()) {
                const response_proof = try arbitrary_proof(F, D, gpa, u);
                const op = try codec.arbitrary.value(Op, gpa, u);
                const pinned = try arbitrary_digests(D, gpa, u);
                return .{ .boundary = .{
                    .proof = response_proof,
                    .op = op,
                    .pinned_nodes = pinned,
                } };
            }
            const response_proof = try arbitrary_proof(F, D, gpa, u);
            const items = try codec.arbitrary.collect(Op, gpa, u);
            return .{ .operations = .{ .proof = response_proof, .operations = items } };
        }
    };
}

const max_digests_per_element = merkle.proof.max_proof_digests_per_element;

/// An upper bound on the encoded size of a `Response` carrying at most `max_ops` operations of
/// at most `op_size` encoded bytes each. An operations response carries a proof of at most
/// `max_proof_digests_per_element` digests per operation; a boundary response carries a proof
/// for one operation and at most `max_pinned_nodes` pinned nodes.
pub fn max_response_size(comptime F: type, comptime D: type, max_ops: usize, op_size: usize) usize {
    const P = merkle.Proof(F, D);
    const operations = P.max_encode_size(max_ops * max_digests_per_element) +
        codec.util.max_items_size(max_ops, op_size);
    const boundary = P.max_encode_size(max_digests_per_element) + op_size +
        codec.util.max_items_size(merkle.max_pinned_nodes, D.fixed_size);
    const result = @max(operations, boundary) + 1;
    assert(result > op_size);
    return result;
}
