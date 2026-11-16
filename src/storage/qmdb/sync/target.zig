//! Sync targets (commonware's `qmdb/sync/target.rs`).
//!
//! A `Target` is the trusted state a sync converges to: the ops root the engine verifies
//! streamed batches against and the range of operations to fetch, from the inclusive lower
//! bound to the exclusive target size. A `CompactTarget` names only a root and a size, for
//! compact-storage databases. Locations encode as commonware's `Location` varints.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const operation = @import("../operation.zig");
const value = @import("../value.zig");
const errors = @import("error.zig");

/// The state to sync to: `root` over operations `[start, end)`.
pub fn Target(comptime F: type, comptime D: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        /// The ops root the engine verifies streamed batches against.
        root: D,
        /// Inclusive lower bound of the operations to sync.
        start: u64,
        /// Exclusive upper bound: the target database size.
        end: u64,

        /// A target over `[start, end)`; `start < end`.
        pub fn init(root: D, start: u64, end: u64) Self {
            assert(start < end);
            return .{ .root = root, .start = start, .end = end };
        }

        /// Whether this target advances relative to `from`: its end lies in the location
        /// domain and strictly increases, and its start does not decrease.
        pub fn advances(self: Self, from: Self) bool {
            assert(self.start < self.end);
            assert(from.start < from.end);
            return merkle.location_is_valid(F, self.end) and
                self.end > from.end and self.start >= from.start;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.root.eql(b.root) and a.start == b.start and a.end == b.end;
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(D, self.root) + operation.location_size(self.start) +
                operation.location_size(self.end);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            assert(self.start < self.end);
            codec.write(D, self.root, writer);
            operation.write_location(self.start, writer);
            operation.write_location(self.end, writer);
        }

        /// Reads `root || NonEmptyRange<Location>`, refusing out-of-domain or empty ranges.
        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const root = try codec.read(D, gpa, reader);
            const start = try operation.read_location(F, reader);
            const end = try operation.read_location(F, reader);
            if (start >= end) return reader.invalid("NonEmptyRange", "start must be < end");
            return init(root, start, end);
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const root = try value.arbitrary(D, gpa, u);
            const lower = u.int_in_range(u64, 0, F.max_leaves - 1);
            const upper = u.int_in_range(u64, lower + 1, F.max_leaves);
            return init(root, lower, upper);
        }
    };
}

/// The state to sync a compact-storage database to: `root` at `size` operations.
pub fn CompactTarget(comptime F: type, comptime D: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Ranged = Target(F, D);

        root: D,
        size: u64,

        pub fn eql(a: Self, b: Self) bool {
            return a.root.eql(b.root) and a.size == b.size;
        }

        /// The ranged target replaying the one operation that ends at `size`.
        pub fn to_target(self: Self) errors.EngineError!Ranged {
            if (self.size == 0 or !merkle.location_is_valid(F, self.size)) {
                return error.InvalidTarget;
            }
            const ranged = Ranged.init(self.root, self.size - 1, self.size);
            assert(ranged.end - ranged.start == 1);
            return ranged;
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(D, self.root) + operation.location_size(self.size);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(D, self.root, writer);
            operation.write_location(self.size, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const root = try codec.read(D, gpa, reader);
            const size = try operation.read_location(F, reader);
            if (size == 0) {
                return reader.invalid(
                    "storage::qmdb::sync::CompactTarget",
                    "size must be in 1..=MAX_LEAVES",
                );
            }
            assert(merkle.location_is_valid(F, size));
            return .{ .root = root, .size = size };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const root = try value.arbitrary(D, gpa, u);
            const size = u.int_in_range(u64, 1, F.max_leaves);
            return .{ .root = root, .size = size };
        }
    };
}
