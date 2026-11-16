//! Amounts of funds, and nonzero amounts per account committed with a binary Merkle tree
//! (commonware `bajillion/amounts.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const storage = @import("storage");
const mod = @import("mod.zig");
const lookup_module = @import("lookup.zig");
const arb = @import("arbitrary.zig");

const bmt = storage.bmt;

/// Why entries do not form amounts, or two amounts do not add up.
pub const Error = error{
    /// An amount is zero.
    ZeroAmount,
    /// An account appears more than once.
    Duplicate,
    /// There are more entries than a tree can commit to.
    TooManyEntries,
    /// A sum overflows.
    Overflow,
};

/// The leaf committing to `amount` for `account`: `H(account || amount)`, the amount in its
/// fixed big-endian encoding.
pub fn leaf(
    comptime H: type,
    comptime P: type,
    comptime A: type,
    account: *const P,
    amount: A,
) H.Digest {
    mod.assert_amount(A);
    const encoded = codec.encode_fixed(A, amount);
    return H.hash(&.{ account.as_slice(), &encoded });
}

/// The root of the binary Merkle tree of `storage.bmt` over leaves added in order, computed
/// without allocating: a binary counter of completed subtrees, one per level, folded at the end
/// with the tree's rule that the last node of an odd level pairs with itself.
pub fn RootBuilder(comptime H: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;

        /// The completed subtree at each level still waiting for its right sibling.
        pending: [bmt.max_levels + 1]?D = @splat(null),
        count: u32 = 0,

        /// Adds the leaf at the next position, hashed with that position.
        pub fn add(self: *Self, entry: *const D) void {
            assert(self.count < std.math.maxInt(u32));
            var node = hash_leaf(self.count, entry);
            var level: usize = 0;
            while (self.pending[level]) |left| : (level += 1) {
                node = hash_node(&left, &node);
                self.pending[level] = null;
            }
            assert(level <= bmt.max_levels);
            self.pending[level] = node;
            self.count += 1;
        }

        /// Returns the finalized root, `H(leaf count || top)`.
        pub fn finish(self: *const Self) D {
            var count_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &count_bytes, self.count, .big);
            if (self.count == 0) {
                const top = H.hash(&.{});
                return H.hash(&.{ &count_bytes, &top.bytes });
            }
            var carry: ?D = null;
            var width: u64 = self.count;
            var level: usize = 0;
            while (width > 1) : ({
                width = (width + 1) / 2;
                level += 1;
            }) {
                const node = self.pending[level];
                if (carry) |right| {
                    carry = if (node) |left|
                        hash_node(&left, &right)
                    else
                        hash_node(&right, &right);
                } else if (node) |left| {
                    carry = hash_node(&left, &left);
                }
            }
            const top = carry orelse self.pending[level].?;
            assert(carry == null or self.pending[level] == null);
            return H.hash(&.{ &count_bytes, &top.bytes });
        }

        fn hash_leaf(position: u32, entry: *const D) D {
            var position_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &position_bytes, position, .big);
            return H.hash(&.{ &position_bytes, &entry.bytes });
        }

        fn hash_node(left: *const D, right: *const D) D {
            return H.hash(&.{ &left.bytes, &right.bytes });
        }
    };
}

/// Nonzero amounts per account, sorted by account (commonware `Amounts<P, A>`).
///
/// Their root is the root of a binary Merkle tree whose leaves are the `(account, amount)`
/// entries in account order. Each leaf is bound to its position, so a `Lookup` of two adjacent
/// entries proves that an account between them has no amount, and the root binds the number of
/// entries. The value owns its entries; `deinit` frees them.
pub fn Amounts(comptime P: type, comptime A: type) type {
    mod.assert_public_key(P);
    mod.assert_amount(A);
    return struct {
        const Self = @This();

        pub const Entry = struct { P, A };
        /// The accepted number of entries.
        pub const Cfg = codec.RangeCfg(usize);
        pub const empty: Self = .{ .entries = &.{} };

        entries: []const Entry,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.entries);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return .{ .entries = try gpa.dupe(Entry, self.entries) };
        }

        /// Collects a copy of `entries`, in any order, in account order.
        pub fn init(gpa: Allocator, entries: []const Entry) (Error || Allocator.Error)!Self {
            const owned = try gpa.dupe(Entry, entries);
            std.mem.sort(Entry, owned, {}, less);
            return from_sorted(gpa, owned);
        }

        /// Takes ownership of `entries` already in account order; frees them on error.
        pub fn from_sorted(gpa: Allocator, entries: []Entry) Error!Self {
            errdefer gpa.free(entries);
            try check(entries);
            return .{ .entries = entries };
        }

        fn check(entries: []const Entry) Error!void {
            if (entries.len > std.math.maxInt(u32)) return error.TooManyEntries;
            for (entries) |entry| if (entry[1] == 0) return error.ZeroAmount;
            for (entries[0..entries.len -| 1], entries[@min(1, entries.len)..]) |a, b| {
                if (a[0].order(b[0]) != .lt) return error.Duplicate;
            }
        }

        fn less(_: void, a: Entry, b: Entry) bool {
            return a[0].order(b[0]) == .lt;
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            if (self.entries.len != other.entries.len) return false;
            for (self.entries, other.entries) |a, b| {
                if (!a[0].eql(b[0]) or a[1] != b[1]) return false;
            }
            return true;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.entries.len == 0;
        }

        /// Returns the number of accounts with an amount.
        pub fn len(self: *const Self) usize {
            return self.entries.len;
        }

        /// Returns the amount of `account`, or zero if it has none.
        pub fn get(self: *const Self, account: *const P) A {
            const index = self.position(account) orelse return 0;
            assert(self.entries[index][1] != 0);
            return self.entries[index][1];
        }

        /// Returns the sum of all amounts, or null if it overflows.
        pub fn total(self: *const Self) ?A {
            var sum: A = 0;
            for (self.entries) |entry| sum = std.math.add(A, sum, entry[1]) catch return null;
            return sum;
        }

        /// Returns the amounts with `other` added entry by entry.
        pub fn combine(
            self: *const Self,
            gpa: Allocator,
            other: *const Self,
        ) (Error || Allocator.Error)!Self {
            const entries = try gpa.alloc(Entry, self.entries.len + other.entries.len);
            errdefer gpa.free(entries);
            var left: usize = 0;
            var right: usize = 0;
            var count: usize = 0;
            while (left < self.entries.len or right < other.entries.len) : (count += 1) {
                if (right == other.entries.len) {
                    entries[count] = self.entries[left];
                    left += 1;
                    continue;
                }
                if (left == self.entries.len) {
                    entries[count] = other.entries[right];
                    right += 1;
                    continue;
                }
                const a = self.entries[left];
                const b = other.entries[right];
                const relation = a[0].order(b[0]);
                if (relation != .gt) left += 1;
                if (relation != .lt) right += 1;
                entries[count] = switch (relation) {
                    .lt => a,
                    .gt => b,
                    .eq => .{ a[0], std.math.add(A, a[1], b[1]) catch return error.Overflow },
                };
            }
            assert(left == self.entries.len and right == other.entries.len);
            const shrunk = try gpa.realloc(entries, count);
            return from_sorted(gpa, shrunk);
        }

        /// Returns the position of `account` among the entries, or null if it has no amount.
        pub fn position(self: *const Self, account: *const P) ?usize {
            return std.sort.binarySearch(Entry, self.entries, account.*, compare_key);
        }

        fn compare_key(key: P, entry: Entry) std.math.Order {
            return key.order(entry[0]);
        }

        /// Returns the commitment to the entries.
        pub fn root(self: *const Self, comptime H: type) H.Digest {
            var builder: RootBuilder(H) = .{};
            for (self.entries) |*entry| builder.add(&leaf(H, P, A, &entry[0], entry[1]));
            assert(builder.count == self.entries.len);
            return builder.finish();
        }

        /// Builds the tree committing to the entries.
        pub fn tree(
            self: *const Self,
            comptime H: type,
            gpa: Allocator,
        ) Allocator.Error!bmt.Tree(H.Digest) {
            var builder = try bmt.Builder(H).init(gpa, self.entries.len);
            defer builder.deinit(gpa);
            for (self.entries) |*entry| {
                _ = try builder.add(gpa, &leaf(H, P, A, &entry[0], entry[1]));
            }
            return builder.build(gpa);
        }

        /// Opens the amount of `account` under `committed`, which must come from `tree`.
        pub fn lookup(
            self: *const Self,
            comptime D: type,
            gpa: Allocator,
            committed: *const bmt.Tree(D),
            account: *const P,
        ) Allocator.Error!lookup_module.Lookup(P, A, D) {
            return lookup_module.Lookup(P, A, D).init(gpa, self.entries, committed, account);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write([]const Entry, self.entries, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const Entry, self.entries);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!Self {
            const entries = try codec.read_range([]const Entry, gpa, reader, range);
            return from_sorted(gpa, @constCast(entries)) catch reader.invalid(
                "clearing::bajillion::Amounts",
                "entries must be strictly increasing by account with nonzero amounts",
            );
        }

        /// `Vec<(P, A)>::arbitrary`, then nonzero amounts, sorted by account, first of each.
        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const drawn = try arb.collect(Entry, gpa, u);
            var nonzero: usize = 0;
            for (drawn) |entry| {
                if (entry[1] == 0) continue;
                drawn[nonzero] = entry;
                nonzero += 1;
            }
            const kept = arb.sort_dedup(Entry, drawn[0..nonzero], order_entries);
            return .{ .entries = try gpa.realloc(drawn, kept.len) };
        }

        fn order_entries(a: *const Entry, b: *const Entry) std.math.Order {
            return a[0].order(b[0]);
        }

        /// Arbitrary amounts that pay at least one account (`arbitrary_nonempty`).
        pub fn arbitrary_nonempty(
            gpa: Allocator,
            u: *arb.Unstructured,
        ) arb.Error!Self {
            const result = try arbitrary(gpa, u);
            if (result.is_empty()) return error.IncorrectFormat;
            return result;
        }
    };
}
