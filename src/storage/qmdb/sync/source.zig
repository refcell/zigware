//! Sync wire types (commonware's `qmdb/sync/source.rs`): the `Request` a client sends a source
//! and the `Response` it answers with, plus `max_response_size`, and `Feedback`, through which
//! the engine reports whether a served response verified.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const operation = @import("../operation.zig");
const value = @import("../value.zig");
const qmdb = @import("../mod.zig");
const channel = @import("utils").channel;
const oneshot = channel.oneshot;
const mpsc = channel.mpsc;

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

/// A later candidate response for a request, with the sender of its verdict.
pub fn Candidate(comptime R: type) type {
    return struct {
        const Self = @This();

        /// Releases `response` (when it owns memory) on discard.
        gpa: Allocator,
        response: R,
        verdict: oneshot.Sender(bool),

        /// Releases a candidate nobody judged (an `mpsc` discard hook).
        pub fn discard(self: Self) void {
            var owned = self;
            release(R, owned.gpa, &owned.response);
            owned.verdict.deinit();
        }
    };
}

fn release(comptime R: type, gpa: Allocator, response: *R) void {
    switch (@typeInfo(R)) {
        .@"struct", .@"union" => if (@hasDecl(R, "deinit")) response.deinit(gpa),
        else => {},
    }
}

/// A served response and, when the source can offer more candidates, its feedback.
pub fn Served(comptime R: type) type {
    return struct { response: R, feedback: ?Feedback(R) };
}

/// Reports whether a response's proof is valid, keeping the request open for another
/// candidate (commonware's `Feedback`). Feedback says nothing about whether the response was
/// applied or persisted. Releasing it with `deinit` leaves the response unjudged and cancels
/// the request.
pub fn Feedback(comptime R: type) type {
    return struct {
        const Self = @This();

        verdict: oneshot.Sender(bool),
        candidates: mpsc.Receiver(Candidate(R)),

        /// Feedback for one response and its request's later candidates.
        pub fn init(verdict: oneshot.Sender(bool), candidates: mpsc.Receiver(Candidate(R))) Self {
            return .{ .verdict = verdict, .candidates = candidates };
        }

        /// Reports the response valid and closes the request.
        pub fn accept(self: *Self) void {
            self.verdict.send(true) catch {}; // A source that stopped listening needs nothing.
            self.candidates.deinit();
            self.* = undefined;
        }

        /// Reports the response invalid and waits for the next candidate: null once the
        /// source stops listening or has no more. Consumes the feedback.
        pub fn reject(self: *Self) Io.Cancelable!?Served(R) {
            var candidates = self.candidates;
            var verdict = self.verdict;
            self.* = undefined;
            verdict.send(false) catch {
                candidates.deinit();
                return null;
            };
            errdefer candidates.deinit();
            const next = try candidates.recv() orelse {
                candidates.deinit();
                return null;
            };
            return .{ .response = next.response, .feedback = .init(next.verdict, candidates) };
        }

        /// Drops the feedback without a verdict, canceling the request.
        pub fn deinit(self: *Self) void {
            self.verdict.deinit();
            self.candidates.deinit();
            self.* = undefined;
        }
    };
}

/// Fails compilation unless `S` is a sync source: it declares `Family`, `Op`, `Digest`, and
/// `Error`, and `serve(*S, gpa, Request(Family)) (Error || Io.Cancelable)!Served(Response)`
/// (commonware's `Source`). The engine calls `serve` on one source from one task at a time.
pub fn assert_source(comptime S: type) void {
    comptime {
        for (.{ "Family", "Op", "Digest", "Error", "serve" }) |name| {
            if (!@hasDecl(S, name)) @compileError(@typeName(S) ++ " lacks " ++ name);
        }
        merkle.check_family(S.Family);
        if (@typeInfo(S.Error) != .error_set) @compileError("Source.Error must be an error set");
    }
}

/// The response type of source `S`.
pub fn ResponseOf(comptime S: type) type {
    return Response(S.Family, S.Op, S.Digest);
}

/// Serves requests from an authenticated journal `J` of family `F` (commonware's `Source for
/// authenticated::Journal`, which every QMDB variant's source delegates to). Responses carry
/// no feedback.
pub fn JournalSource(comptime F: type, comptime J: type) type {
    return struct {
        const Self = @This();
        pub const Family = F;
        pub const Op = J.Item;
        pub const Digest = J.Digest;
        pub const Error = qmdb.Error || J.Error || Allocator.Error;
        const R = Response(F, Op, Digest);

        journal: *J,

        /// Answers `request` against the root the journal had at `request.size()`. The
        /// response is allocated with the journal's allocator, which must be `gpa`.
        pub fn serve(self: *Self, gpa: Allocator, request: Request(F)) Error!Served(R) {
            assert(gpa.ptr == self.journal.gpa.ptr);
            // Rejected before the floor lookup, which must not read out-of-range locations.
            if (request.size() > self.journal.size()) return error.RangeOutOfBounds;
            var reader: LogReader(J) = .{ .journal = self.journal };
            const peaks = try qmdb.inactive_peaks_at(F, gpa, &reader, request.size());
            const max_ops = request.max_ops();
            var proved = try self.journal.historical_proof(
                request.size(),
                request.start(),
                max_ops,
                peaks,
            );
            if (request == .operations) {
                const response: R = .{ .operations = .{
                    .proof = proved.proof,
                    .operations = proved.items,
                } };
                return .{ .response = response, .feedback = null };
            }
            errdefer proved.deinit(gpa);
            assert(proved.items.len == 1);
            var buffer: [merkle.max_pinned_nodes]Digest = undefined;
            const pins = try self.journal.merkle.pinned_nodes_at(request.start(), &buffer);
            const pinned_nodes = try gpa.dupe(Digest, pins);
            const op = proved.items[0];
            gpa.free(proved.items);
            const response: R = .{ .boundary = .{
                .proof = proved.proof,
                .op = op,
                .pinned_nodes = pinned_nodes,
            } };
            return .{ .response = response, .feedback = null };
        }
    };
}

/// Reads an authenticated journal for `qmdb.inactive_peaks_at`.
fn LogReader(comptime J: type) type {
    return struct {
        const Self = @This();
        journal: *J,

        pub fn bounds(self: *const Self) merkle.Range {
            const span = self.journal.get_bounds();
            return .{ .start = span.start, .end = span.end };
        }

        pub fn read(self: *Self, _: Allocator, location: u64) !J.Item {
            return self.journal.read(location);
        }
    };
}

const Io = std.Io;
const testing = std.testing;

fn feedback_channels(comptime R: type) !struct {
    feedback: Feedback(R),
    verdict: oneshot.Receiver(bool),
    candidates: mpsc.Sender(Candidate(R)),
} {
    const candidates = try mpsc.channel(Candidate(R), testing.allocator, testing.io, 1);
    const verdict = try oneshot.channel(bool, testing.allocator, testing.io);
    return .{
        .feedback = .init(verdict.sender, candidates.receiver),
        .verdict = verdict.receiver,
        .candidates = candidates.sender,
    };
}

fn candidate(response: u8) !struct { Candidate(u8), oneshot.Receiver(bool) } {
    const verdict = try oneshot.channel(bool, testing.allocator, testing.io);
    const next: Candidate(u8) =
        .{ .gpa = testing.allocator, .response = response, .verdict = verdict.sender };
    return .{ next, verdict.receiver };
}

// commonware's `feedback_accepts_and_closes_request`.
test "sync feedback accepts and closes the request" {
    var parts = try feedback_channels(u8);
    defer parts.verdict.deinit();
    defer parts.candidates.deinit();
    parts.feedback.accept();
    try testing.expect(try parts.verdict.recv());
    const next, var next_verdict = try candidate(2);
    defer next_verdict.deinit();
    try testing.expectError(error.Closed, parts.candidates.try_send(next));
    next.discard();
}

// commonware's `feedback_rejects_and_returns_next_candidate`.
test "sync feedback rejects and returns the next candidate" {
    var parts = try feedback_channels(u8);
    defer parts.verdict.deinit();
    defer parts.candidates.deinit();
    const next, var next_verdict = try candidate(2);
    defer next_verdict.deinit();
    try parts.candidates.try_send(next);
    var served = (try parts.feedback.reject()).?;
    try testing.expect(!try parts.verdict.recv());
    try testing.expectEqual(@as(u8, 2), served.response);
    served.feedback.?.accept();
    try testing.expect(try next_verdict.recv());
}

// commonware's `dropping_feedback_cancels_request`.
test "sync dropping feedback cancels the request" {
    var parts = try feedback_channels(u8);
    defer parts.verdict.deinit();
    defer parts.candidates.deinit();
    parts.feedback.deinit();
    try testing.expectError(error.Closed, parts.verdict.recv());
    const next, var next_verdict = try candidate(2);
    defer next_verdict.deinit();
    try testing.expectError(error.Closed, parts.candidates.try_send(next));
    next.discard();
}

// A source with no further candidate ends the request: reject yields null.
test "sync feedback reject without candidates yields null" {
    var parts = try feedback_channels(u8);
    defer parts.verdict.deinit();
    parts.candidates.deinit();
    try testing.expect(try parts.feedback.reject() == null);
    try testing.expect(!try parts.verdict.recv());
}
