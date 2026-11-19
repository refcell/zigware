//! Atomic reference counts for batches shared across threads (commonware's `Arc` and `Weak`).
//! Forks of one parent may be merkleized, read, and dropped on several threads at once under a
//! shared read guard, so every count a batch chain shares is atomic.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// A count of references, starting at one. The holder that drops the last one frees the
/// object, and sees every other holder's writes first.
pub const RefCount = struct {
    count: std.atomic.Value(u32),

    pub fn init() RefCount {
        return .{ .count = .init(1) };
    }

    /// Adds a reference; the caller already holds one (`Arc::clone`).
    pub fn retain(self: *RefCount) void {
        const before = self.count.fetchAdd(1, .monotonic);
        assert(before > 0);
        assert(before < std.math.maxInt(u32));
    }

    /// Adds a reference unless none is left (`Weak::upgrade`). The object's memory must be
    /// kept alive by another link, such as a weak count.
    pub fn try_retain(self: *RefCount) bool {
        var current = self.count.load(.monotonic);
        // Each failed exchange saw another holder change the count; it reaches zero at most
        // once and never rises from it, so the loop ends.
        while (current > 0) {
            assert(current < std.math.maxInt(u32));
            current = self.count.cmpxchgWeak(current, current + 1, .acquire, .monotonic) orelse
                return true;
        }
        return false;
    }

    /// Drops a reference, returning whether it was the last (the caller then frees).
    pub fn release(self: *RefCount) bool {
        const before = self.count.fetchSub(1, .acq_rel);
        assert(before > 0);
        return before == 1;
    }

    /// The count, for assertions; other threads may change it at once.
    pub fn load(self: *const RefCount) u32 {
        return self.count.load(.acquire);
    }
};

/// Walks the live ancestors above `start` through `T.parent` (a weak link), holding a strong
/// reference to each one while it is visited and dropping it at the next step or `deinit`, as
/// commonware upgrades each `Weak` parent. `T` declares `strong: RefCount`, `parent: ?*T`, and
/// `release` (taking the allocator or not). The caller holds `start`.
pub fn Ancestors(comptime T: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        from: ?*const T,
        held: ?*T = null,
        /// A batch the caller holds, yielded first without a reference of the walk's own.
        first: ?*T = null,

        /// The live ancestors above `start`.
        pub fn init(gpa: Allocator, start: *const T) Self {
            return .{ .gpa = gpa, .from = start };
        }

        /// `first` (if any), then its live ancestors.
        pub fn from_first(gpa: Allocator, first: ?*T) Self {
            return .{ .gpa = gpa, .from = first, .first = first };
        }

        /// The next live batch, held until the following call, or null at the end (after
        /// which the walk is over).
        pub fn next(self: *Self) ?*T {
            if (self.first) |first| {
                self.first = null;
                return first;
            }
            const from: *const T = if (self.held) |held| held else self.from orelse return null;
            // `from` is held, so its parent link (a weak reference) keeps the parent's memory.
            const upgraded: ?*T = if (from.parent) |parent|
                (if (parent.strong.try_retain()) parent else null)
            else
                null;
            if (self.held) |held| drop(self.gpa, held);
            self.held = upgraded;
            return upgraded;
        }

        pub fn deinit(self: *Self) void {
            if (self.held) |held| drop(self.gpa, held);
            self.* = undefined;
        }

        fn drop(gpa: Allocator, batch: *T) void {
            if (@typeInfo(@TypeOf(T.release)).@"fn".param_types.len == 2) {
                batch.release(gpa);
            } else {
                batch.release();
            }
        }
    };
}

test "RefCount: the last release reports itself, and try_retain fails after it" {
    var count: RefCount = .init();
    count.retain();
    try std.testing.expect(count.try_retain());
    try std.testing.expectEqual(@as(u32, 3), count.load());
    try std.testing.expect(!count.release());
    try std.testing.expect(!count.release());
    try std.testing.expect(count.release());
    try std.testing.expect(!count.try_retain());
    try std.testing.expectEqual(@as(u32, 0), count.load());
}

test "RefCount: threads retaining and releasing at once leave exactly the start" {
    const io = std.testing.io;
    var count: RefCount = .init();
    const Task = struct {
        fn run(shared: *RefCount) void {
            for (0..20_000) |_| {
                shared.retain();
                if (shared.try_retain()) assert(!shared.release());
                assert(!shared.release());
            }
        }
    };
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    for (0..4) |_| group.async(io, Task.run, .{&count});
    try group.await(io);
    try std.testing.expectEqual(@as(u32, 1), count.load());
    try std.testing.expect(count.release());
}
