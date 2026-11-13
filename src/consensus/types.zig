//! Consensus types shared across the package (commonware `consensus/src/types.rs`).
//!
//! - `Epoch`: a segment of views with one validator set; increments on reconfiguration.
//! - `Height`: a sequential position in a chain.
//! - `View`: a counter within an epoch, one consensus attempt per view.
//! - `Round`: an epoch and a view, ordered by epoch first.
//! - `Delta(T)` (`EpochDelta`, `HeightDelta`, `ViewDelta`): offsets, distinct per point type.
//! - `TermLength`: consecutive views led by one leader.
//! - `Epocher` (comptime interface) and `FixedEpocher`: epoch boundaries by height.
//!
//! `Epoch`, `Height`, `View`, and the deltas are non-exhaustive `enum(u64)` types, so `==`,
//! `switch`, and hashing work on them and they never mix with each other or with a raw `u64`.
//! Each encodes as a `u64` varint (commonware `UInt<u64>`); `Round` is the epoch then the view.
//!
//! Arithmetic never fails silently: only `next`, `View.term_end`, and `View.next_term_start`
//! panic on overflow, like commonware; everything else saturates or returns an optional.
//!
//! `coding::Commitment` waits for the coding lane's `Config`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");

pub const Participant = utils.Participant;

const Kind = enum { epoch, height, view };

/// The shared shape of `Epoch`, `Height`, and `View`.
fn Counter(comptime kind: Kind) type {
    return enum(u64) {
        _,

        const Self = @This();
        const overflow_message = @tagName(kind) ++ " overflow";

        /// The matching offset type (`EpochDelta`, `HeightDelta`, `ViewDelta`).
        pub const Offset = Delta(Self);

        pub fn zero() Self {
            return @fromBackingInt(@intCast(0));
        }

        pub fn new(value: u64) Self {
            return @fromBackingInt(@intCast(value));
        }

        pub fn get(self: Self) u64 {
            return @backingInt(self);
        }

        pub fn is_zero(self: Self) bool {
            return self.get() == 0;
        }

        /// Panics on overflow (commonware `expect("<kind> overflow")`).
        pub fn next(self: Self) Self {
            const value = std.math.add(u64, self.get(), 1) catch @panic(overflow_message);
            assert(value > self.get());
            return new(value);
        }

        /// The previous value, or null at zero.
        pub fn previous(self: Self) ?Self {
            const value = std.math.sub(u64, self.get(), 1) catch return null;
            return new(value);
        }

        pub fn saturating_add(self: Self, delta: Offset) Self {
            return new(self.get() +| delta.get());
        }

        pub fn saturating_sub(self: Self, delta: Offset) Self {
            return new(self.get() -| delta.get());
        }

        /// `self - delta`, or null on underflow.
        pub fn checked_sub(self: Self, delta: Offset) ?Self {
            const value = std.math.sub(u64, self.get(), delta.get()) catch return null;
            return new(value);
        }

        /// The delta from `other` to `self`, or null when `other > self`.
        pub fn delta_from(self: Self, other: Self) ?Offset {
            const value = std.math.sub(u64, self.get(), other.get()) catch return null;
            return Offset.new(value);
        }

        /// The values in `[start, end)`; empty when `start >= end`.
        pub fn range(start: Self, end: Self) Range(Self) {
            return .{ .front = start.get(), .back = @max(start.get(), end.get()) };
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.math.order(a.get(), b.get());
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{d}", .{self.get()});
        }

        pub fn arbitrary(
            _: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return new(u.int(u64));
        }

        pub const max_encode_size: usize = codec.varint.max_size(u64);

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.varint.write(u64, self.get(), writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.varint.size(u64, self.get());
        }

        pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return new(try codec.varint.read(u64, reader));
        }

        // View-only term arithmetic. Each asserts the kind at compile time.

        /// The first view of the term containing this view. View 0 (genesis) is its own
        /// term; later terms are `[1, L]`, `[L + 1, 2L]`, ...
        pub fn term_start(self: Self, term_length: TermLength) Self {
            comptime assert(kind == .view);
            const length = term_length.get();
            if (self.get() == 0) return self;
            // Cannot overflow: base is at most view - 1.
            const base = (self.get() - 1) / length * length;
            assert(base < self.get());
            return new(base + 1);
        }

        pub fn is_term_start(self: Self, term_length: TermLength) bool {
            return self.term_start(term_length) == self;
        }

        pub fn same_term(self: Self, other: Self, term_length: TermLength) bool {
            return self.term_start(term_length) == other.term_start(term_length);
        }

        /// The last view of the term containing this view. Panics on overflow.
        pub fn term_end(self: Self, term_length: TermLength) Self {
            comptime assert(kind == .view);
            if (self.get() == 0) return self;
            const start = self.term_start(term_length).get();
            const end = std.math.add(u64, start, term_length.get() - 1) catch
                @panic("view term_end overflow");
            assert(end >= self.get());
            return new(end);
        }

        /// The first view of the next term. Panics on overflow.
        pub fn next_term_start(self: Self, term_length: TermLength) Self {
            return self.term_end(term_length).next();
        }

        /// The index of the term containing this view (genesis is term 0).
        pub fn term_index(self: Self, term_length: TermLength) u64 {
            comptime assert(kind == .view);
            // Proof: `TermLength` is never zero, the only `divCeil` error.
            return std.math.divCeil(u64, self.get(), term_length.get()) catch unreachable;
        }

        /// Whether a nullification at this view covers `view` (the rest of its term).
        pub fn covers(self: Self, view: Self, term_length: TermLength) bool {
            return self.get() <= view.get() and self.same_term(view, term_length);
        }

        /// The views whose nullifications cover this view: `[term_start, self]`, inclusive.
        pub fn covering_range(self: Self, term_length: TermLength) struct { Self, Self } {
            const start = self.term_start(term_length);
            assert(start.get() <= self.get());
            return .{ start, self };
        }

        /// Whether `pending` is acceptable relative to this view when future views are
        /// bounded: any view at or below this one, the next view, or the first view of the
        /// next term. Total near `u64` max, where no representable view starts the next term.
        pub fn admits(self: Self, pending: Self, term_length: TermLength) bool {
            comptime assert(kind == .view);
            if (pending.get() <= self.get()) return true;
            if (pending.get() == self.get() + 1) return true;
            // Cannot underflow: pending is above self, so it is at least 1.
            const before = new(pending.get() - 1);
            return pending.is_term_start(term_length) and self.same_term(before, term_length);
        }
    };
}

pub const Epoch = Counter(.epoch);
pub const Height = Counter(.height);
pub const View = Counter(.view);

/// An offset or duration measured in `T` (commonware `Delta<T>`); distinct per `T`.
pub fn Delta(comptime T: type) type {
    return enum(u64) {
        _,

        const Self = @This();
        pub const Point = T;

        pub fn zero() Self {
            return @fromBackingInt(@intCast(0));
        }

        pub fn new(value: u64) Self {
            return @fromBackingInt(@intCast(value));
        }

        pub fn get(self: Self) u64 {
            return @backingInt(self);
        }

        pub fn is_zero(self: Self) bool {
            return self.get() == 0;
        }

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.math.order(a.get(), b.get());
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{d}", .{self.get()});
        }
    };
}

pub const EpochDelta = Epoch.Offset;
pub const HeightDelta = Height.Offset;
pub const ViewDelta = View.Offset;

/// An iterator over `[front, back)` of a counter type (commonware `ViewRange`, `HeightRange`).
pub fn Range(comptime T: type) type {
    return struct {
        front: u64,
        back: u64,

        const Self = @This();

        pub fn next(self: *Self) ?T {
            assert(self.front <= self.back);
            if (self.front == self.back) return null;
            defer self.front += 1;
            return T.new(self.front);
        }

        pub fn next_back(self: *Self) ?T {
            assert(self.front <= self.back);
            if (self.front == self.back) return null;
            self.back -= 1;
            return T.new(self.back);
        }

        pub fn len(self: Self) u64 {
            assert(self.front <= self.back);
            return self.back - self.front;
        }
    };
}

pub const ViewRange = Range(View);
pub const HeightRange = Range(Height);

/// Consecutive views led by one leader (a term). Consensus-critical: every participant must
/// configure the same value; nothing on the wire carries it.
pub const TermLength = struct {
    length: u32,

    /// Every view has an independently elected leader.
    pub const one: TermLength = .{ .length = 1 };
    pub const max: TermLength = .{ .length = std.math.maxInt(u32) };

    pub fn new(length: utils.NonZero(u32)) TermLength {
        const result: TermLength = .{ .length = length.get() };
        assert(result.length > 0);
        return result;
    }

    /// The number of views per term.
    pub fn get(self: TermLength) u64 {
        assert(self.length > 0);
        return self.length;
    }

    pub fn format(self: TermLength, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}", .{self.length});
    }

    /// commonware's `int_in_range(1..=u32::MAX)`.
    pub fn arbitrary(
        _: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!TermLength {
        return .{ .length = u.int_in_range(u32, 1, std.math.maxInt(u32)) };
    }
};

/// An epoch and a view: one consensus round, ordered by epoch then view. Packed so `==`
/// compares rounds directly.
pub const Round = packed struct(u128) {
    epoch: Epoch,
    view: View,

    pub fn new(epoch: Epoch, view: View) Round {
        return .{ .epoch = epoch, .view = view };
    }

    pub fn zero() Round {
        return new(.zero(), .zero());
    }

    pub fn order(a: Round, b: Round) std.math.Order {
        const by_epoch = Epoch.order(a.epoch, b.epoch);
        if (by_epoch != .eq) return by_epoch;
        return View.order(a.view, b.view);
    }

    pub fn format(self: Round, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("({f}, {f})", .{ self.epoch, self.view });
    }

    pub fn arbitrary(_: Allocator, u: *codec.arbitrary.Unstructured) codec.arbitrary.Error!Round {
        const epoch = Epoch.new(u.int(u64));
        return new(epoch, View.new(u.int(u64)));
    }

    pub const max_encode_size: usize = Epoch.max_encode_size + View.max_encode_size;

    pub fn write(self: Round, writer: *codec.Writer) void {
        self.epoch.write(writer);
        self.view.write(writer);
    }

    pub fn encode_size(self: Round) usize {
        return self.epoch.encode_size() + self.view.encode_size();
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Round {
        const epoch = try Epoch.read(gpa, reader, {});
        return new(epoch, try View.read(gpa, reader, {}));
    }
};

/// The position of a height within its epoch.
pub const EpochPhase = enum {
    /// First half: `relative < length / 2`.
    early,
    /// Exactly `relative == length / 2`.
    midpoint,
    /// Second half: `relative > length / 2`.
    late,
};

/// An epoch's bounds, relative to a queried height inside it.
pub const EpochInfo = struct {
    epoch: Epoch,
    height: Height,
    first: Height,
    last: Height,

    pub fn new(epoch: Epoch, height: Height, first: Height, last: Height) EpochInfo {
        assert(first.get() <= last.get());
        assert(first.get() <= height.get() and height.get() <= last.get());
        return .{ .epoch = epoch, .height = height, .first = first, .last = last };
    }

    pub fn length(self: EpochInfo) HeightDelta {
        return .new(self.last.get() - self.first.get() + 1);
    }

    /// The queried height's offset from the epoch's first height.
    pub fn relative(self: EpochInfo) Height {
        return .new(self.height.get() - self.first.get());
    }

    pub fn phase(self: EpochInfo) EpochPhase {
        const offset = self.relative().get();
        const midpoint = self.length().get() / 2;
        if (offset < midpoint) return .early;
        if (offset == midpoint) return .midpoint;
        return .late;
    }
};

/// Asserts `E` implements `Epocher`: `containing(Height) ?EpochInfo`, `first(Epoch) ?Height`,
/// and `last(Epoch) ?Height`. Epochs are contiguous and ascend with height, and every epoch
/// holds at least one height above genesis.
pub fn assert_epocher(comptime E: type) void {
    comptime {
        for (.{ "containing", "first", "last" }) |decl| {
            if (!@hasDecl(E, decl)) @compileError(@typeName(E) ++ " lacks Epocher." ++ decl);
        }
    }
}

/// Fixed-length epochs: epoch `e` spans heights `[e * length, (e + 1) * length)`, so epoch
/// zero includes genesis.
pub const FixedEpocher = struct {
    length: u64,

    /// Panics when `length` is one, since epoch zero would hold only genesis.
    pub fn new(length: utils.NonZero(u64)) FixedEpocher {
        if (length.get() <= 1) @panic("epoch length must exceed one");
        return .{ .length = length.get() };
    }

    /// The first and last heights of `epoch`, or null if either overflows.
    fn bounds(self: FixedEpocher, epoch: Epoch) ?struct { Height, Height } {
        assert(self.length > 1);
        const start = std.math.mul(u64, epoch.get(), self.length) catch return null;
        const end = std.math.add(u64, start, self.length - 1) catch return null;
        assert(end > start);
        return .{ .new(start), .new(end) };
    }

    /// The midpoint height of `epoch`, or null if unsupported.
    pub fn midpoint(self: FixedEpocher, epoch: Epoch) ?Height {
        const start, _ = self.bounds(epoch) orelse return null;
        const value = std.math.add(u64, start.get(), self.length / 2) catch return null;
        return .new(value);
    }

    pub fn containing(self: FixedEpocher, height: Height) ?EpochInfo {
        const epoch = Epoch.new(height.get() / self.length);
        const start, const end = self.bounds(epoch) orelse return null;
        return .new(epoch, height, start, end);
    }

    pub fn first(self: FixedEpocher, epoch: Epoch) ?Height {
        const result, _ = self.bounds(epoch) orelse return null;
        return result;
    }

    pub fn last(self: FixedEpocher, epoch: Epoch) ?Height {
        _, const result = self.bounds(epoch) orelse return null;
        return result;
    }

    comptime {
        assert_epocher(FixedEpocher);
    }
};

comptime {
    assert(codec.max_encode_size(Epoch).? == 10);
    assert(codec.max_encode_size(Round).? == 20);
    assert(@sizeOf(Round) == 16);
}

test {
    _ = @import("types_test.zig");
}
