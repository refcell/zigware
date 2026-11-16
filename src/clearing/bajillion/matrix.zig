//! The payment matrix a close settles (commonware `bajillion/matrix.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const storage = @import("storage");
const mod = @import("mod.zig");
const amounts_module = @import("amounts.zig");
const lookup_module = @import("lookup.zig");
const arb = @import("arbitrary.zig");

const bmt = storage.bmt;
const Lookup = lookup_module.Lookup;
const InvalidOpening = lookup_module.InvalidOpening;

/// The leaf committing to `sender`'s payment map with root `payments`.
pub fn leaf(
    comptime H: type,
    comptime P: type,
    sender: *const P,
    payments: *const H.Digest,
) H.Digest {
    return H.hash(&.{ sender.as_slice(), &payments.bytes });
}

/// The root of the matrix with `senders` and their payment map `roots`, senders strictly
/// increasing. Allocation-free.
pub fn root(
    comptime H: type,
    comptime P: type,
    senders: []const P,
    roots: []const H.Digest,
) H.Digest {
    assert(senders.len == roots.len);
    var builder: amounts_module.RootBuilder(H) = .{};
    for (senders, roots) |*sender, *payments| builder.add(&leaf(H, P, sender, payments));
    assert(builder.count == senders.len);
    return builder.finish();
}

/// The payment maps a close settles, one row per sender (commonware `Matrix<P, H, A>`).
///
/// The matrix commits to a binary Merkle tree of `(sender, payment map root)` leaves in sender
/// order, and opens rows with the hasher `H` that committed it. An `Opening` proves what one
/// sender paid one receiver, or that it paid nothing. Clones share the rows: `clone` takes a
/// reference and `deinit` drops one.
pub fn Matrix(comptime P: type, comptime H: type, comptime A: type) type {
    mod.assert_public_key(P);
    mod.assert_amount(A);
    return struct {
        const Self = @This();
        const D = H.Digest;

        pub const Payments = amounts_module.Amounts(P, A);
        /// A sender and the root of its payment map.
        pub const RowRoot = struct { P, D };
        /// A sender, its nonempty payment map (owned by the matrix), and that map's root.
        pub const Row = struct { P, Payments, D };

        inner: *Inner,

        const Inner = struct {
            gpa: Allocator,
            references: std.atomic.Value(u32),
            /// Senders and the roots of their payment maps, in sender order.
            rows: []RowRoot,
            /// Payment maps aligned with `rows`.
            payments: []Payments,
            /// Trees over the payment maps, built the first time a row is opened.
            trees: []?bmt.Tree(D),
            trees_mutex: std.atomic.Mutex = .unlocked,
            /// Tree over the leaves of `rows`.
            tree: bmt.Tree(D),
        };

        /// The matrix with no rows.
        pub fn empty(gpa: Allocator) Allocator.Error!Self {
            return from_sorted(gpa, &.{});
        }

        /// Builds a matrix from `rows` strictly increasing by sender, each with a nonempty
        /// payment map and its root. Takes ownership of the payment maps, even on failure.
        pub fn from_sorted(gpa: Allocator, sorted: []const Row) Allocator.Error!Self {
            errdefer for (sorted) |row| {
                var map = row[1];
                map.deinit(gpa);
            };
            const inner = try gpa.create(Inner);
            errdefer gpa.destroy(inner);
            const row_roots = try gpa.alloc(RowRoot, sorted.len);
            errdefer gpa.free(row_roots);
            const maps = try gpa.alloc(Payments, sorted.len);
            errdefer gpa.free(maps);
            const trees = try gpa.alloc(?bmt.Tree(D), sorted.len);
            errdefer gpa.free(trees);
            var builder = try bmt.Builder(H).init(gpa, sorted.len);
            defer builder.deinit(gpa);
            for (sorted, row_roots, maps, trees, 0..) |row, *row_root, *map, *tree, index| {
                assert(!row[1].is_empty());
                if (index > 0) assert(sorted[index - 1][0].order(row[0]) == .lt);
                row_root.* = .{ row[0], row[2] };
                map.* = row[1];
                tree.* = null;
                _ = try builder.add(gpa, &leaf(H, P, &row[0], &row[2]));
            }
            inner.* = .{
                .gpa = gpa,
                .references = .init(1),
                .rows = row_roots,
                .payments = maps,
                .trees = trees,
                .tree = try builder.build(gpa),
            };
            return .{ .inner = inner };
        }

        /// Takes another reference to the same rows.
        pub fn clone(self: *const Self) Self {
            const previous = self.inner.references.fetchAdd(1, .monotonic);
            assert(previous > 0);
            return .{ .inner = self.inner };
        }

        /// Drops a reference, freeing the rows with the last one.
        pub fn deinit(self: *Self) void {
            const inner = self.inner;
            self.* = undefined;
            const previous = inner.references.fetchSub(1, .acq_rel);
            assert(previous > 0);
            if (previous > 1) return;
            const gpa = inner.gpa;
            for (inner.payments) |*map| map.deinit(gpa);
            for (inner.trees) |*tree| if (tree.*) |*built| built.deinit(gpa);
            gpa.free(inner.rows);
            gpa.free(inner.payments);
            gpa.free(inner.trees);
            inner.tree.deinit(gpa);
            gpa.destroy(inner);
        }

        /// Returns the commitment to the matrix.
        pub fn root(self: *const Self) D {
            return self.inner.tree.root();
        }

        /// Returns the number of senders with a row.
        pub fn len(self: *const Self) usize {
            return self.inner.rows.len;
        }

        /// Returns whether no sender has a row.
        pub fn is_empty(self: *const Self) bool {
            return self.inner.rows.len == 0;
        }

        /// Every sender and the root of its payment map, in sender order.
        pub fn rows(self: *const Self) []const RowRoot {
            return self.inner.rows;
        }

        /// Every sender's payment map, aligned with `rows`.
        pub fn payment_maps(self: *const Self) []const Payments {
            return self.inner.payments;
        }

        fn position(self: *const Self, sender: *const P) ?usize {
            return std.sort.binarySearch(RowRoot, self.inner.rows, sender.*, compare_sender);
        }

        fn compare_sender(sender: P, row: RowRoot) std.math.Order {
            return sender.order(row[0]);
        }

        /// Returns `sender`'s payment map, if it has a row.
        pub fn payments(self: *const Self, sender: *const P) ?*const Payments {
            const index = self.position(sender) orelse return null;
            return &self.inner.payments[index];
        }

        /// Returns the root of `sender`'s payment map, if it has a row.
        pub fn payments_root(self: *const Self, sender: *const P) ?D {
            const index = self.position(sender) orelse return null;
            return self.inner.rows[index][1];
        }

        /// Opens the amount `sender` paid `receiver`, proving that it paid nothing if it did not.
        ///
        /// An opening reveals the payment it opens. When it proves that payment absent, it
        /// reveals the sender's payments to the receivers on either side or, for a sender
        /// without a row, the senders on either side and the roots of their payment maps.
        pub fn open(
            self: *const Self,
            gpa: Allocator,
            sender: *const P,
            receiver: *const P,
        ) Allocator.Error!Opening(P, D, A) {
            const inner = self.inner;
            var row = try Lookup(P, D, D).init(gpa, inner.rows, &inner.tree, sender);
            errdefer row.deinit(gpa);
            const index = switch (row) {
                .member => |m| m.position,
                .non_member => return .{ .row = row, .entry = null },
            };
            const tree = try self.row_tree(index);
            const entry = try inner.payments[index].lookup(D, gpa, tree, receiver);
            return .{ .row = row, .entry = entry };
        }

        /// The tree over row `index`'s payment map, built once.
        fn row_tree(self: *const Self, index: usize) Allocator.Error!*const bmt.Tree(D) {
            const inner = self.inner;
            while (!inner.trees_mutex.tryLock()) std.atomic.spinLoopHint();
            defer inner.trees_mutex.unlock();
            if (inner.trees[index] == null) {
                inner.trees[index] = try inner.payments[index].tree(H, inner.gpa);
            }
            return &inner.trees[index].?;
        }
    };
}

/// Opening of the amount one sender paid one receiver under a `Matrix` root (commonware
/// `Opening<P, D, A>`). Owns its proofs; `deinit` frees them.
pub fn Opening(comptime P: type, comptime D: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const Row = Lookup(P, D, D);
        pub const Entry = Lookup(P, A, D);

        /// Opening of the sender's row, binding the root of its payment map if it has one.
        row: Row,
        /// Opening of the receiver's entry under the root of the sender's payment map, present
        /// if and only if the sender has a row.
        entry: ?Entry,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.row.deinit(gpa);
            if (self.entry) |*entry| entry.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var row = try self.row.clone(gpa);
            errdefer row.deinit(gpa);
            const entry: ?Entry = if (self.entry) |*entry| try entry.clone(gpa) else null;
            return .{ .row = row, .entry = entry };
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            if (!self.row.eql(&other.row)) return false;
            if (self.entry == null or other.entry == null) {
                return self.entry == null and other.entry == null;
            }
            return self.entry.?.eql(&other.entry.?);
        }

        fn row_leaf(comptime H: type) fn (*const P, *const D) D {
            return struct {
                fn compute(sender: *const P, payments: *const D) D {
                    return leaf(H, P, sender, payments);
                }
            }.compute;
        }

        fn entry_leaf(comptime H: type) fn (*const P, *const A) D {
            return struct {
                fn compute(receiver: *const P, amount: *const A) D {
                    return amounts_module.leaf(H, P, A, receiver, amount.*);
                }
            }.compute;
        }

        /// Verifies the opening of `sender`'s row under the matrix root `matrix_root`. Returns
        /// the root of `sender`'s payment map, or null if it has no row.
        pub fn verify_row(
            self: *const Self,
            comptime H: type,
            matrix_root: *const D,
            sender: *const P,
        ) InvalidOpening!?D {
            const row = try self.row.verify(H, matrix_root, sender, row_leaf(H));
            if ((row != null) != (self.entry != null)) return error.InvalidOpening;
            return row;
        }

        /// Verifies the opening under the matrix root `matrix_root`. Returns the amount
        /// `sender` paid `receiver`, or zero if it paid nothing.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            matrix_root: *const D,
            sender: *const P,
            receiver: *const P,
        ) InvalidOpening!A {
            const payments = try self.verify_row(H, matrix_root, sender) orelse return 0;
            const entry = &self.entry.?;
            const amount = try entry.verify(H, &payments, receiver, entry_leaf(H));
            return amount orelse 0;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.row.write(writer);
            codec.write(?Entry, self.entry, writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.row.encode_size() + codec.encode_size(?Entry, self.entry);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            var row = try codec.read(Row, gpa, reader);
            errdefer row.deinit(gpa);
            const entry = try codec.read(?Entry, gpa, reader);
            return .{ .row = row, .entry = entry };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const row = try Row.arbitrary(gpa, u);
            const entry = try arb.value(?Entry, gpa, u);
            return .{ .row = row, .entry = entry };
        }
    };
}
