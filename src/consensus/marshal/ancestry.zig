//! Streams of a block's ancestors (commonware `marshal/ancestry.rs`).
//!
//! An ancestry `A` is a comptime interface checked by `assert_ancestry`: `A.Block`,
//! `peek(*const A) ?*const Digested(Block)` (the next block, if already available),
//! `next(*A) !?Digested(Block)` (the next block, waiting for a pending fetch; the caller owns
//! it), `clone(*const A) !A` (an independent stream at the same position), and `deinit(*A)`.
//! Streams yield blocks newest first, each after the first being the parent of the one before.
//!
//! Rust's polled `Stream` becomes a blocking `next` on the runtime's `std.Io`. As in commonware,
//! `AncestorStream` subscribes to a block's parent as soon as it yields the last buffered block,
//! so the fetch overlaps the caller's work, and a parent that is already available is buffered
//! (and visible to `peek`) at once.
//!
//! Commonware panics on a non-contiguous chain; so does this port. `is_contiguous_chain` exposes
//! the check, which the tests use in place of commonware's `should_panic` cases.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../types.zig");

const Height = types.Height;
const Timed = runtime.telemetry.metrics.histogram.Timed;
const Timer = runtime.telemetry.metrics.histogram.Timer;
const oneshot = utils.channel.oneshot;

pub fn assert_ancestry(comptime A: type) void {
    comptime {
        for (.{ "Block", "peek", "next", "clone", "deinit" }) |decl| {
            if (!@hasDecl(A, decl)) @compileError(@typeName(A) ++ " lacks Ancestry." ++ decl);
        }
    }
}

/// Asserts `M` implements `BlockProvider`: `M.Block` and
/// `subscribe_parent(*M, *const Digested(Block)) !oneshot.Receiver(Digested(Block))` (or another
/// receiver of `Digested(Block)` with `recv`, `try_recv`, and `deinit`), whose receiver closes
/// without a value once the provider can no longer obtain the parent. A provider that
/// declares `clone() M` and `deinit(*M)` is cloned with each stream.
pub fn assert_block_provider(comptime M: type) void {
    comptime {
        for (.{ "Block", "subscribe_parent" }) |decl| {
            if (!@hasDecl(M, decl)) @compileError(@typeName(M) ++ " lacks BlockProvider." ++ decl);
        }
    }
}

/// Whether `child` is exactly the successor height of `parent`.
pub fn has_contiguous_height(parent: Height, child: Height) bool {
    const previous = child.previous() orelse return false;
    return previous.get() == parent.get();
}

/// Whether `parent` is the block `child` names, one height below it.
pub fn is_parent(comptime B: type, child: *const B, parent: *const B) bool {
    const child_block = child.inner();
    const parent_block = parent.inner();
    if (!has_contiguous_height(parent_block.height(), child_block.height())) return false;
    return parent.digest().eql(child_block.parent());
}

fn assert_contiguous_parent(comptime B: type, child: *const B, parent: *const B) void {
    const heights = has_contiguous_height(parent.inner().height(), child.inner().height());
    if (!heights) @panic("blocks must be contiguous in height");
    if (!is_parent(B, child, parent)) @panic("blocks must be contiguous in ancestry");
}

/// Whether `blocks`, newest first, form a contiguous chain.
pub fn is_contiguous_chain(comptime B: type, blocks: []const B) bool {
    if (blocks.len < 2) return true;
    for (blocks[0 .. blocks.len - 1], blocks[1..]) |*child, *parent| {
        if (!is_parent(B, child, parent)) return false;
    }
    return true;
}

fn validate_chain(comptime B: type, blocks: []const B) void {
    if (blocks.len < 2) return;
    for (blocks[0 .. blocks.len - 1], blocks[1..]) |*child, *parent| {
        assert_contiguous_parent(B, child, parent);
    }
}

/// Owned block handles yielded front to back.
fn Queue(comptime D: type) type {
    return struct {
        const Self = @This();

        blocks: []D,
        head: usize = 0,

        fn init(gpa: Allocator, blocks: []const D) Allocator.Error!Self {
            return .{ .blocks = try gpa.dupe(D, blocks) };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            for (self.blocks[self.head..]) |*block| block.deinit();
            gpa.free(self.blocks);
            self.* = undefined;
        }

        fn peek(self: *const Self) ?*const D {
            if (self.head == self.blocks.len) return null;
            return &self.blocks[self.head];
        }

        fn pop(self: *Self) ?D {
            if (self.head == self.blocks.len) return null;
            self.head += 1;
            return self.blocks[self.head - 1];
        }

        fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            const remaining = self.blocks[self.head..];
            const blocks = try gpa.alloc(D, remaining.len);
            for (blocks, remaining) |*copy, *block| copy.* = block.clone();
            return .{ .blocks = blocks };
        }
    };
}

/// A fixed ancestry that fetches nothing (commonware `from_iter`'s stream).
pub fn Bounded(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;
        const D = broadcast.Digested(B);

        gpa: Allocator,
        queue: Queue(D),

        pub fn peek(self: *const Self) ?*const D {
            return self.queue.peek();
        }

        pub fn next(self: *Self) Io.Cancelable!?D {
            return self.queue.pop();
        }

        pub fn clone(self: *const Self) Allocator.Error!Self {
            return .{ .gpa = self.gpa, .queue = try self.queue.clone(self.gpa) };
        }

        pub fn deinit(self: *Self) void {
            self.queue.deinit(self.gpa);
            self.* = undefined;
        }
    };
}

/// An ancestry over `blocks`, newest first, taking ownership of the handles. Panics if they do
/// not form a contiguous chain. Useful to bound the ancestry an application sees.
pub fn from_iter(
    comptime B: type,
    gpa: Allocator,
    blocks: []const broadcast.Digested(B),
) Allocator.Error!Bounded(B) {
    validate_chain(broadcast.Digested(B), blocks);
    return .{ .gpa = gpa, .queue = try .init(gpa, blocks) };
}

/// `prefix` blocks, then `tail` (commonware `with_prefix`'s stream). The seam between the
/// oldest prefixed block and the tail's first block is checked when that block is peeked or
/// yielded.
pub fn Prefixed(comptime Tail: type) type {
    comptime assert_ancestry(Tail);
    return struct {
        const Self = @This();
        pub const Block = Tail.Block;
        const D = broadcast.Digested(Block);

        gpa: Allocator,
        prefix: Queue(D),
        tail: Tail,
        /// The oldest prefixed block until the seam is checked.
        boundary_child: ?D,

        pub fn peek(self: *const Self) ?*const D {
            if (self.prefix.peek()) |block| return block;
            const parent = self.tail.peek() orelse return null;
            if (self.boundary_child) |*child| assert_contiguous_parent(D, child, parent);
            return parent;
        }

        pub fn next(self: *Self) !?D {
            if (self.prefix.pop()) |block| return block;
            const parent = try self.tail.next() orelse return null;
            if (self.boundary_child) |*child| {
                assert_contiguous_parent(D, child, &parent);
                child.deinit();
                self.boundary_child = null;
            }
            return parent;
        }

        pub fn clone(self: *const Self) !Self {
            var prefix = try self.prefix.clone(self.gpa);
            errdefer prefix.deinit(self.gpa);
            const tail = try self.tail.clone();
            const boundary_child: ?D = if (self.boundary_child) |child| child.clone() else null;
            return .{
                .gpa = self.gpa,
                .prefix = prefix,
                .tail = tail,
                .boundary_child = boundary_child,
            };
        }

        pub fn deinit(self: *Self) void {
            self.prefix.deinit(self.gpa);
            self.tail.deinit();
            if (self.boundary_child) |*child| child.deinit();
            self.* = undefined;
        }
    };
}

/// `blocks` (newest first) followed by `tail`, taking ownership of both on success. Panics if
/// the prefix is not a contiguous chain.
pub fn with_prefix(
    comptime Tail: type,
    gpa: Allocator,
    blocks: []const broadcast.Digested(Tail.Block),
    tail: Tail,
) Allocator.Error!Prefixed(Tail) {
    validate_chain(broadcast.Digested(Tail.Block), blocks);
    const prefix: Queue(broadcast.Digested(Tail.Block)) = try .init(gpa, blocks);
    const boundary_child = if (blocks.len > 0) blocks[blocks.len - 1].clone() else null;
    return .{ .gpa = gpa, .prefix = prefix, .tail = tail, .boundary_child = boundary_child };
}

/// The receiver `M.subscribe_parent` returns.
pub fn ParentReceiver(comptime M: type) type {
    const D = broadcast.Digested(M.Block);
    const Return = @TypeOf(M.subscribe_parent(@as(*M, undefined), @as(*const D, undefined)));
    return @typeInfo(Return).error_union.payload;
}

/// Yields the ancestors of its initial blocks, including the height-zero genesis block when
/// the provider has it, subscribing to each parent through the provider `M`
/// (commonware `AncestorStream`). The stream ends when the provider cannot obtain a parent or
/// returns a block that is not the parent its child names.
pub fn AncestorStream(comptime M: type) type {
    comptime assert_block_provider(M);
    return struct {
        const Self = @This();
        pub const Block = M.Block;
        const D = broadcast.Digested(Block);

        gpa: Allocator,
        io: Io,
        provider: M,
        fetch_duration: ?*const Timed,
        /// Blocks ready to yield, oldest first (the next block is last).
        buffered: std.ArrayList(D),
        /// The block whose parent is being fetched, and the fetch.
        pending_child: ?D = null,
        /// The provider's parent receiver: `oneshot.Receiver(D)`, or any receiver with the same
        /// `recv`, `try_recv`, and `deinit`.
        pending: ?ParentReceiver(M) = null,
        timer: ?Timer = null,

        /// A stream from `initial` (any order, taking ownership), which must form a contiguous
        /// chain once sorted by height; panics otherwise. Starts only from blocks that are
        /// safe to verify, certify, build on, or repair from.
        pub fn init(
            gpa: Allocator,
            io: Io,
            provider: M,
            initial: []const D,
            fetch_duration: ?*const Timed,
        ) Allocator.Error!Self {
            var buffered: std.ArrayList(D) = try .initCapacity(gpa, initial.len);
            buffered.appendSliceAssumeCapacity(initial);
            std.mem.sort(D, buffered.items, {}, by_height);
            const items = buffered.items;
            if (items.len > 1) {
                for (items[0 .. items.len - 1], items[1..]) |*lower, *upper| {
                    const lower_height = lower.inner().height();
                    if (!has_contiguous_height(lower_height, upper.inner().height())) {
                        @panic("initial blocks must be contiguous in height");
                    }
                    if (!lower.digest().eql(upper.inner().parent())) {
                        @panic("initial blocks must be contiguous in ancestry");
                    }
                }
            }
            return .{
                .gpa = gpa,
                .io = io,
                .provider = provider,
                .fetch_duration = fetch_duration,
                .buffered = buffered,
            };
        }

        fn by_height(_: void, a: D, b: D) bool {
            return a.inner().height().get() < b.inner().height().get();
        }

        pub fn deinit(self: *Self) void {
            for (self.buffered.items) |*block| block.deinit();
            self.buffered.deinit(self.gpa);
            self.clear_pending();
            if (comptime @hasDecl(M, "deinit")) self.provider.deinit();
            self.* = undefined;
        }

        /// The next block, if already available.
        pub fn peek(self: *const Self) ?*const D {
            const items = self.buffered.items;
            if (items.len == 0) return null;
            return &items[items.len - 1];
        }

        fn clear_pending(self: *Self) void {
            if (self.pending) |*receiver| receiver.deinit();
            if (self.pending_child) |*child| child.deinit();
            self.pending = null;
            self.pending_child = null;
            self.timer = null;
        }

        /// Subscribes to the parent of `child`, without waiting.
        fn subscribe(self: *Self, child: *const D) !void {
            assert(self.pending == null and self.pending_child == null);
            assert(child.inner().height().get() > 0);
            self.pending = try self.provider.subscribe_parent(child);
            self.pending_child = child.clone();
            if (self.fetch_duration) |timed| self.timer = timed.timer(self.io);
        }

        /// Takes `parent` from the pending fetch when it is the parent its child names;
        /// otherwise drops it and ends the stream. Clears the pending fetch either way.
        fn accept(self: *Self, parent: D) ?D {
            var owned = parent;
            const child = &self.pending_child.?;
            const matches = is_parent(D, child, &owned);
            if (matches) {
                if (self.timer) |timer| timer.observe(self.io);
            } else {
                owned.deinit();
            }
            self.clear_pending();
            return if (matches) owned else null;
        }

        /// After yielding `block`, the last buffered one: fetches its parent (buffering it at
        /// once when already available), or stops at genesis.
        fn advance(self: *Self, block: *const D) !void {
            if (block.inner().height().get() == 0) return self.clear_pending();
            try self.subscribe(block);
            const parent = self.pending.?.try_recv() catch |err| switch (err) {
                error.Empty => return,
                error.Closed => return self.clear_pending(),
            };
            const accepted = self.accept(parent) orelse return;
            self.buffered.append(self.gpa, accepted) catch |err| {
                var dropped = accepted;
                dropped.deinit();
                return err;
            };
        }

        /// The next ancestor, waiting for a pending parent fetch; null once the stream ends.
        pub fn next(self: *Self) !?D {
            if (self.buffered.pop()) |block| {
                errdefer {
                    var dropped = block;
                    dropped.deinit();
                }
                if (self.buffered.items.len == 0) try self.advance(&block);
                return block;
            }
            if (self.pending == null) return null;
            const parent = self.pending.?.recv() catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => {
                    self.clear_pending();
                    return null;
                },
            };
            const block = self.accept(parent) orelse return null;
            errdefer {
                var dropped = block;
                dropped.deinit();
            }
            try self.advance(&block);
            return block;
        }

        /// An independent stream at the same position; a pending fetch is subscribed again.
        pub fn clone(self: *const Self) !Self {
            const provider = if (comptime @hasDecl(M, "clone"))
                self.provider.clone()
            else
                self.provider;
            var result: Self = .{
                .gpa = self.gpa,
                .io = self.io,
                .provider = provider,
                .fetch_duration = self.fetch_duration,
                .buffered = .empty,
            };
            errdefer result.deinit();
            try result.buffered.ensureTotalCapacity(self.gpa, self.buffered.items.len);
            for (self.buffered.items) |block| result.buffered.appendAssumeCapacity(block.clone());
            if (self.pending_child) |*child| try result.subscribe(child);
            return result;
        }
    };
}

const testing = std.testing;
const Sha256 = @import("cryptography").Sha256;
const mocks_block = @import("mocks/block.zig");

const TestBlock = mocks_block.EmptyBlock(Sha256);
const TestDigested = broadcast.Digested(TestBlock);
const empty = Sha256.Digest.empty;

fn block_at(parent: Sha256.Digest, height: u64, timestamp: u64) TestBlock {
    return .init(parent, .new(height), timestamp);
}

fn digested(block: TestBlock) !TestDigested {
    return TestDigested.compute(testing.allocator, block);
}

/// Serves parents for the tests: the first `pending_first` subscriptions wait for
/// `complete_all`; later ones get `wrong` if set, else the `known` block the child names, else
/// close (commonware's Mock, Pending, PendingThenWrong, and WrongParent providers).
const ProviderState = struct {
    known: []const TestBlock = &.{},
    wrong: ?TestBlock = null,
    pending_first: u32 = 0,
    calls: u32 = 0,
    senders: std.ArrayList(oneshot.Sender(TestDigested)) = .empty,

    fn deinit(self: *ProviderState) void {
        for (self.senders.items) |*sender| sender.deinit();
        self.senders.deinit(testing.allocator);
    }

    fn complete_all(self: *ProviderState, parent: TestDigested) void {
        for (self.senders.items) |*sender| {
            // The streams still hold their receivers.
            sender.send(parent.clone()) catch unreachable;
        }
        self.senders.clearRetainingCapacity();
    }
};

const TestProvider = struct {
    pub const Block = TestBlock;

    state: *ProviderState,

    pub fn subscribe_parent(
        self: *TestProvider,
        child: *const TestDigested,
    ) !oneshot.Receiver(TestDigested) {
        const state = self.state;
        const pair = try oneshot.channel(TestDigested, testing.allocator, testing.io);
        var sender = pair.sender;
        state.calls += 1;
        if (state.calls <= state.pending_first) {
            try state.senders.append(testing.allocator, sender);
            return pair.receiver;
        }
        const served: ?TestBlock = state.wrong orelse for (state.known) |known| {
            if (known.digest().eql(child.inner().parent())) break known;
        } else null;
        if (served) |block| {
            // The receiver is still open.
            sender.send(try digested(block)) catch unreachable;
        } else {
            sender.deinit();
        }
        return pair.receiver;
    }
};

const TestStream = AncestorStream(TestProvider);

fn stream_of(state: *ProviderState, initial: []const TestBlock) !TestStream {
    var handles: [4]TestDigested = undefined;
    assert(initial.len <= handles.len);
    for (initial, handles[0..initial.len]) |block, *handle| handle.* = try digested(block);
    const provider: TestProvider = .{ .state = state };
    const owned = handles[0..initial.len];
    return TestStream.init(testing.allocator, testing.io, provider, owned, null);
}

/// Takes the next block and checks it is `expected` (or that the stream ended).
fn expect_next(stream: anytype, expected: ?TestBlock) !void {
    var got = try stream.next();
    defer if (got) |*block| block.deinit();
    if (expected) |block| {
        try testing.expect(got != null);
        try testing.expect(got.?.inner().eql(block));
    } else {
        try testing.expect(got == null);
    }
}

test "contiguity checks" {
    try testing.expect(has_contiguous_height(.new(6), .new(7)));
    try testing.expect(!has_contiguous_height(.new(6), .new(8)));
    try testing.expect(!has_contiguous_height(.new(std.math.maxInt(u64)), .zero()));

    // The chains commonware's `from_iter` and `with_prefix` reject with a panic.
    const parent = block_at(empty, 1, 1);
    const far_child = block_at(parent.digest(), 3, 3);
    const wrong_parent = block_at(empty, 1, 2);
    const child = block_at(parent.digest(), 2, 2);
    const grandchild = block_at(child.digest(), 3, 3);
    var handles: [3]TestDigested = .{
        try digested(grandchild),
        try digested(child),
        try digested(parent),
    };
    defer for (&handles) |*handle| handle.deinit();
    try testing.expect(is_contiguous_chain(TestDigested, &handles));
    const reordered = [_]TestDigested{ handles[0], handles[2], handles[1] };
    try testing.expect(!is_contiguous_chain(TestDigested, &reordered));
    var far = try digested(far_child);
    defer far.deinit();
    try testing.expect(!is_contiguous_chain(TestDigested, &.{ far, handles[2] }));
    var wrong = try digested(wrong_parent);
    defer wrong.deinit();
    try testing.expect(!is_contiguous_chain(TestDigested, &.{ handles[1], wrong }));
}

test "ends on non contiguous fetched parent height" {
    const parent = block_at(empty, 0, 0);
    const child = block_at(parent.digest(), 3, 3);
    var state: ProviderState = .{ .known = &.{parent} };
    defer state.deinit();
    var stream = try stream_of(&state, &.{child});
    defer stream.deinit();
    try expect_next(&stream, child);
    try expect_next(&stream, null);
}

test "ends on non contiguous fetched parent digest" {
    const expected_parent = block_at(empty, 0, 0);
    const child = block_at(expected_parent.digest(), 1, 2);
    var state: ProviderState = .{ .wrong = block_at(empty, 0, 1) };
    defer state.deinit();
    var stream = try stream_of(&state, &.{child});
    defer stream.deinit();
    try expect_next(&stream, child);
    try expect_next(&stream, null);
}

test "ends on delayed non contiguous fetched parent" {
    const expected_parent = block_at(empty, 0, 0);
    const child = block_at(expected_parent.digest(), 1, 2);
    var state: ProviderState = .{ .pending_first = std.math.maxInt(u32) };
    defer state.deinit();
    var stream = try stream_of(&state, &.{child});
    defer stream.deinit();
    try expect_next(&stream, child);
    try testing.expectEqual(1, state.senders.items.len);
    var fetched = try digested(block_at(empty, 0, 1));
    defer fetched.deinit();
    state.complete_all(fetched);
    try expect_next(&stream, null);
}

test "ends on immediate bad grandparent after delayed parent" {
    const expected_grandparent = block_at(empty, 0, 0);
    const parent = block_at(expected_grandparent.digest(), 1, 2);
    const child = block_at(parent.digest(), 2, 3);
    var state: ProviderState = .{ .pending_first = 1, .wrong = block_at(empty, 0, 1) };
    defer state.deinit();
    var stream = try stream_of(&state, &.{child});
    defer stream.deinit();
    try expect_next(&stream, child);
    var delivered = try digested(parent);
    defer delivered.deinit();
    state.complete_all(delivered);
    try expect_next(&stream, parent);
    try expect_next(&stream, null);
}

test "peek is available through the ancestry interface" {
    const block = block_at(empty, 1, 1);
    var state: ProviderState = .{};
    defer state.deinit();
    var stream = try stream_of(&state, &.{block});
    defer stream.deinit();
    comptime assert_ancestry(TestStream);
    try testing.expectEqual(1, stream.peek().?.inner().height().get());

    var handles = [_]TestDigested{try digested(block)};
    var bounded = try from_iter(TestBlock, testing.allocator, &handles);
    defer bounded.deinit();
    comptime assert_ancestry(Bounded(TestBlock));
    try testing.expectEqual(1, bounded.peek().?.inner().height().get());
}

test "from iter yields blocks in order and peeks next" {
    const parent = block_at(empty, 1, 1);
    const child = block_at(parent.digest(), 2, 2);
    var handles = [_]TestDigested{ try digested(child), try digested(parent) };
    var ancestry = try from_iter(TestBlock, testing.allocator, &handles);
    defer ancestry.deinit();
    var copy = try ancestry.clone();
    defer copy.deinit();

    try testing.expect(ancestry.peek().?.inner().eql(child));
    try expect_next(&ancestry, child);
    try testing.expect(ancestry.peek().?.inner().eql(parent));
    try expect_next(&ancestry, parent);
    try testing.expectEqual(null, ancestry.peek());
    try expect_next(&ancestry, null);
    // A clone advances independently.
    try expect_next(&copy, child);
}

test "with prefix peeks tail when prefix empty" {
    const block = block_at(empty, 1, 1);
    var tail_blocks = [_]TestDigested{try digested(block)};
    const tail = try from_iter(TestBlock, testing.allocator, &tail_blocks);
    var ancestry = try with_prefix(Bounded(TestBlock), testing.allocator, &.{}, tail);
    defer ancestry.deinit();
    try testing.expect(ancestry.peek().?.inner().eql(block));
    try expect_next(&ancestry, block);
    try testing.expectEqual(null, ancestry.peek());
}

test "with prefix peeks tail after prefix consumed" {
    const parent = block_at(empty, 1, 1);
    const child = block_at(parent.digest(), 2, 2);
    var tail_blocks = [_]TestDigested{try digested(parent)};
    const tail = try from_iter(TestBlock, testing.allocator, &tail_blocks);
    var prefix = [_]TestDigested{try digested(child)};
    var ancestry = try with_prefix(Bounded(TestBlock), testing.allocator, &prefix, tail);
    defer ancestry.deinit();
    var copy = try ancestry.clone();
    defer copy.deinit();

    try testing.expect(ancestry.peek().?.inner().eql(child));
    try expect_next(&ancestry, child);
    try testing.expect(ancestry.peek().?.inner().eql(parent));
    try expect_next(&ancestry, parent);
    try testing.expectEqual(null, ancestry.peek());
    // Each clone checks the seam itself.
    try expect_next(&copy, child);
    try expect_next(&copy, parent);
}

test "yields genesis and stops" {
    const genesis = block_at(empty, 0, 0);
    const child = block_at(genesis.digest(), 1, 1);
    var state: ProviderState = .{ .known = &.{genesis} };
    defer state.deinit();
    var stream = try stream_of(&state, &.{child});
    defer stream.deinit();
    try expect_next(&stream, child);
    try expect_next(&stream, genesis);
    try expect_next(&stream, null);
    // Genesis has no parent to fetch.
    try testing.expectEqual(1, state.calls);
}

test "clone preserves pending parent fetch" {
    const parent = block_at(empty, 0, 0);
    const child = block_at(parent.digest(), 1, 1);
    var state: ProviderState = .{ .pending_first = std.math.maxInt(u32) };
    defer state.deinit();
    var stream = try stream_of(&state, &.{child});
    defer stream.deinit();
    try expect_next(&stream, child);
    try testing.expectEqual(1, state.senders.items.len);

    var cloned = try stream.clone();
    defer cloned.deinit();
    try testing.expectEqual(2, state.senders.items.len);
    var delivered = try digested(parent);
    defer delivered.deinit();
    state.complete_all(delivered);

    try expect_next(&stream, parent);
    try expect_next(&cloned, parent);
    try expect_next(&stream, null);
    try expect_next(&cloned, null);
}

test "empty yields none" {
    var state: ProviderState = .{};
    defer state.deinit();
    var stream = try stream_of(&state, &.{});
    defer stream.deinit();
    try expect_next(&stream, null);
}

test "yields ancestors" {
    const block1 = block_at(empty, 1, 1);
    const block2 = block_at(block1.digest(), 2, 2);
    const block3 = block_at(block2.digest(), 3, 3);
    var state: ProviderState = .{ .known = &.{ block1, block2 } };
    defer state.deinit();
    var stream = try stream_of(&state, &.{block3});
    defer stream.deinit();
    try expect_next(&stream, block3);
    try expect_next(&stream, block2);
    try expect_next(&stream, block1);
    try expect_next(&stream, null);
}

test "yields ancestors all buffered" {
    const block1 = block_at(empty, 1, 1);
    const block2 = block_at(block1.digest(), 2, 2);
    const block3 = block_at(block2.digest(), 3, 3);
    var state: ProviderState = .{};
    defer state.deinit();
    // Initial blocks in any order are sorted by height.
    var stream = try stream_of(&state, &.{ block1, block3, block2 });
    defer stream.deinit();
    try expect_next(&stream, block3);
    try expect_next(&stream, block2);
    try expect_next(&stream, block1);
    try expect_next(&stream, null);
}

test "missing parent ends stream" {
    const block1 = block_at(empty, 1, 1);
    const block2 = block_at(block1.digest(), 2, 2);
    const block3 = block_at(block2.digest(), 3, 3);
    var state: ProviderState = .{ .known = &.{block1} };
    defer state.deinit();
    var stream = try stream_of(&state, &.{block3});
    defer stream.deinit();
    try expect_next(&stream, block3);
    try expect_next(&stream, null);
}

const chain_max = 16;

/// A random chain, oldest first: each block names the one before it, its height usually one
/// above, sometimes two (a height gap the stream must stop at). Some blocks are withheld from
/// the provider (a missing parent).
const FuzzChain = struct {
    blocks: [chain_max]TestBlock,
    known: [chain_max]TestBlock,
    len: usize,
    known_len: usize,
    withheld: [chain_max]bool,

    fn draw(draws: @import("codec").fuzz.Draws) FuzzChain {
        var chain: FuzzChain = undefined;
        chain.len = draws.range_at_most(usize, 1, chain_max);
        var height = draws.range_at_most(u64, 0, 3);
        var parent = empty;
        for (chain.blocks[0..chain.len], 0..) |*block, index| {
            if (index > 0) height += if (draws.range_at_most(u8, 0, 7) == 0) 2 else 1;
            block.* = block_at(parent, height, draws.value(u64));
            parent = block.digest();
        }
        chain.known_len = 0;
        // The newest block starts the stream; the rest may be withheld.
        for (chain.blocks[0..chain.len], 0..) |block, index| {
            const top = index == chain.len - 1;
            chain.withheld[index] = !top and draws.range_at_most(u8, 0, 7) == 0;
            if (chain.withheld[index]) continue;
            chain.known[chain.known_len] = block;
            chain.known_len += 1;
        }
        assert(chain.known_len >= 1);
        return chain;
    }

    /// How many blocks the stream yields, newest first: down to genesis, a withheld parent,
    /// or a parent whose height is not one below its child.
    fn expected_yields(chain: *const FuzzChain) usize {
        var count: usize = 1;
        var index = chain.len - 1;
        while (index > 0) : (index -= 1) {
            const child = &chain.blocks[index];
            if (child.height().get() == 0) break;
            if (chain.withheld[index - 1]) break;
            if (!has_contiguous_height(chain.blocks[index - 1].height(), child.height())) break;
            count += 1;
        }
        return count;
    }
};

fn fuzz_ancestor_stream(_: void, smith: *std.testing.Smith) anyerror!void {
    const draws: @import("codec").fuzz.Draws = .init(smith);
    const chain = FuzzChain.draw(draws);
    var state: ProviderState = .{ .known = chain.known[0..chain.known_len] };
    defer state.deinit();
    var stream = try stream_of(&state, &.{chain.blocks[chain.len - 1]});
    defer stream.deinit();
    const expected = chain.expected_yields();
    const clone_at = draws.range_at_most(usize, 0, expected);
    var copy: ?TestStream = null;
    defer if (copy) |*value| value.deinit();
    for (0..expected) |offset| {
        if (offset == clone_at) copy = try stream.clone();
        const want = chain.blocks[chain.len - 1 - offset];
        if (stream.peek()) |peeked| try testing.expect(peeked.inner().eql(want));
        try expect_next(&stream, want);
    }
    try expect_next(&stream, null);
    // A clone taken partway yields the same remaining blocks, then ends.
    if (copy) |*value| {
        for (clone_at..expected) |offset| {
            try expect_next(value, chain.blocks[chain.len - 1 - offset]);
        }
        try expect_next(value, null);
    }
}

test "fuzz ancestor stream against a chain model" {
    try @import("codec").fuzz.run({}, fuzz_ancestor_stream, 0xA5CE, 256);
}
