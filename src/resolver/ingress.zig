//! Mailbox ingress helpers for resolver implementations (commonware
//! `resolver/src/ingress.rs`).
//!
//! The common actor-facing message shape for resolvers that coalesce fetches by key and prune
//! queued work with retain predicates. `Message(K, S, M)` is an `actor.mailbox` message with a
//! reliable policy: when the mailbox is full, duplicate fetches for a key merge their
//! subscribers and metadata, and retain predicates prune queued fetches at once and drain
//! before them.
//!
//! Ownership: a fetch batch, its fetches, their subscriber lists, and their metadata are
//! allocated with the mailbox's allocator (`Batch.gpa`); the receiver frees a batch with
//! `Batch.deinit`, and the mailbox frees dropped ones through `discard`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const resolver = @import("root.zig");

/// Metadata carried by a coalesced fetch: `void`, or a type with
/// `merge(*M, gpa, incoming: M) Allocator.Error!void` and `deinit(*M, gpa)`.
fn assert_metadata(comptime M: type) void {
    if (M == void) return;
    comptime assert(@hasDecl(M, "merge"));
    comptime assert(@hasDecl(M, "deinit"));
}

/// Target peers of a fetch: null is unrestricted (commonware `Option<NonEmptyVec<P>>`).
pub fn Targets(comptime P: type) type {
    return struct {
        const Self = @This();

        /// Distinct peers in insertion order, never empty; null means any peer.
        peers: ?std.ArrayList(P) = null,

        pub const unrestricted: Self = .{};

        /// Targets restricted to `peers` (copied; duplicates dropped).
        pub fn init(gpa: Allocator, peers: []const P) Allocator.Error!Self {
            assert(peers.len > 0);
            var list: std.ArrayList(P) = try .initCapacity(gpa, peers.len);
            for (peers) |peer| {
                if (!contains(list.items, peer)) list.appendAssumeCapacity(peer);
            }
            assert(list.items.len > 0);
            return .{ .peers = list };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.peers) |*peers| peers.deinit(gpa);
            self.* = undefined;
        }

        /// Unrestricted dominates: a non-targeted fetch clears existing restrictions.
        /// Otherwise new peers are appended. Takes ownership of `incoming`.
        pub fn merge(self: *Self, gpa: Allocator, incoming: Self) Allocator.Error!void {
            var incoming_owned = incoming;
            defer incoming_owned.deinit(gpa);
            const incoming_peers = incoming_owned.peers orelse {
                if (self.peers) |*peers| peers.deinit(gpa);
                self.peers = null;
                return;
            };
            const existing = if (self.peers) |*peers| peers else return;
            for (incoming_peers.items) |peer| {
                if (!contains(existing.items, peer)) try existing.append(gpa, peer);
            }
            assert(existing.items.len > 0);
        }

        fn contains(peers: []const P, peer: P) bool {
            for (peers) |item| if (resolver.eql(P, item, peer)) return true;
            return false;
        }
    };
}

/// A peer-visible key plus local subscribers waiting on it.
pub fn FetchKey(comptime K: type, comptime S: type, comptime M: type) type {
    comptime assert_metadata(M);
    return struct {
        const Self = @This();

        /// The key to fetch.
        key: K,
        /// Subscribers used to decide whether the fetch is retained: distinct, insertion
        /// order, never empty.
        subscribers: std.ArrayList(S),
        /// Fetch metadata merged when duplicate fetches are coalesced.
        metadata: M,

        /// A fetch with one subscriber (Rust `From<Fetch>`); takes ownership of `metadata`.
        pub fn init(gpa: Allocator, key: K, subscriber: S, metadata: M) Allocator.Error!Self {
            var subscribers: std.ArrayList(S) = try .initCapacity(gpa, 1);
            subscribers.appendAssumeCapacity(subscriber);
            assert(subscribers.items.len == 1);
            return .{ .key = key, .subscribers = subscribers, .metadata = metadata };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.subscribers.deinit(gpa);
            if (M != void) self.metadata.deinit(gpa);
            self.* = undefined;
        }

        /// Adds incoming subscribers not already attached, then merges metadata. Takes
        /// ownership of `incoming`.
        fn merge(self: *Self, gpa: Allocator, incoming: Self) Allocator.Error!void {
            var incoming_owned = incoming;
            defer incoming_owned.subscribers.deinit(gpa);
            assert(resolver.eql(K, self.key, incoming.key));
            for (incoming_owned.subscribers.items) |subscriber| {
                if (has_subscriber(self.subscribers.items, subscriber)) continue;
                self.subscribers.append(gpa, subscriber) catch |err| {
                    if (M != void) incoming_owned.metadata.deinit(gpa);
                    return err;
                };
            }
            if (M != void) try self.metadata.merge(gpa, incoming_owned.metadata);
        }

        /// Keeps the subscribers `predicate` accepts. Returns false if none remain.
        fn retain(self: *Self, predicate: *const resolver.Predicate(K, S)) bool {
            var kept: usize = 0;
            for (self.subscribers.items) |subscriber| {
                if (!predicate.call(self.key, subscriber)) continue;
                self.subscribers.items[kept] = subscriber;
                kept += 1;
            }
            self.subscribers.shrinkRetainingCapacity(kept);
            return kept > 0;
        }

        fn has_subscriber(items: []const S, subscriber: S) bool {
            for (items) |item| if (resolver.eql(S, item, subscriber)) return true;
            return false;
        }
    };
}

/// Hash-map context for keys: hashes the codec encoding, compares with `order`.
fn KeyContext(comptime K: type) type {
    const size_max = comptime codec.max_encode_size(K) orelse
        @compileError("resolver: keys need a bounded encoding: " ++ @typeName(K));
    return struct {
        pub fn hash(_: @This(), key: K) u64 {
            var buffer: [size_max]u8 = undefined;
            const encoded = codec.encode_to(K, key, &buffer);
            assert(encoded.len <= size_max);
            return std.hash.Wyhash.hash(0, encoded);
        }

        pub fn eql(_: @This(), a: K, b: K) bool {
            return resolver.eql(K, a, b);
        }
    };
}

/// Actor message for fetch and retain ingress.
pub fn Message(comptime K: type, comptime S: type, comptime M: type) type {
    return union(enum) {
        const Self = @This();
        pub const Fetch = FetchKey(K, S, M);
        pub const Predicate = resolver.Predicate(K, S);

        /// A batch of fetches, owned by the message.
        pub const Batch = struct {
            gpa: Allocator,
            fetches: std.ArrayList(Fetch),

            pub fn deinit(self: *Batch) void {
                for (self.fetches.items) |*fetch| fetch.deinit(self.gpa);
                self.fetches.deinit(self.gpa);
                self.* = undefined;
            }
        };

        /// Initiate fetches.
        fetch: Batch,
        /// Retain only fetch subscribers that satisfy the predicate.
        retain: Predicate,

        pub const Overflow = Pending(K, S, M);

        /// A message fetching one key for one subscriber; takes ownership of `metadata`.
        pub fn fetch_one(
            gpa: Allocator,
            key: K,
            subscriber: S,
            metadata: M,
        ) Allocator.Error!Self {
            var fetches: std.ArrayList(Fetch) = try .initCapacity(gpa, 1);
            errdefer fetches.deinit(gpa);
            fetches.appendAssumeCapacity(try Fetch.init(gpa, key, subscriber, metadata));
            return .{ .fetch = .{ .gpa = gpa, .fetches = fetches } };
        }

        /// The policy: coalesce fetches by key; prune queued fetches with each retain.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            overflow.gpa = gpa;
            switch (message) {
                .fetch => |batch| {
                    assert(batch.gpa.ptr == gpa.ptr and batch.gpa.vtable == gpa.vtable);
                    try overflow.push_fetches(batch);
                },
                .retain => |predicate| try overflow.push_retain(predicate),
            }
        }

        /// Frees a message the mailbox drops.
        pub fn discard(message: Self) void {
            switch (message) {
                .fetch => |batch| {
                    var owned = batch;
                    owned.deinit();
                },
                .retain => {},
            }
        }
    };
}

/// Pending resolver messages retained after a mailbox fills.
pub fn Pending(comptime K: type, comptime S: type, comptime M: type) type {
    return struct {
        const Self = @This();
        const Msg = Message(K, S, M);
        const Positions = std.HashMapUnmanaged(K, usize, KeyContext(K), 80);

        /// Set by the first `handle`; every message is allocated with it.
        gpa: ?Allocator = null,
        /// Retain predicates waiting to run before fetches are admitted.
        modifications: std.Deque(Msg.Predicate) = .empty,
        /// Coalesced fetches that could not fit in the ready queue.
        fetches: std.ArrayList(Msg.Fetch) = .empty,
        /// Index of each key in `fetches`.
        positions: Positions = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.fetches.items) |*fetch| fetch.deinit(gpa);
            self.fetches.deinit(gpa);
            self.positions.deinit(gpa);
            self.modifications.deinit(gpa);
            self.* = undefined;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.modifications.len == 0 and self.fetches.items.len == 0;
        }

        /// Hands retain predicates, then the coalesced fetch batch, to `pusher` until it
        /// gives one back.
        pub fn drain(self: *Self, pusher: anytype) void {
            // Retain predicates run before pending fetches so the actor never starts work for
            // subscribers already pruned by an older retain.
            while (self.modifications.popFront()) |predicate| {
                if (pusher.push(.{ .retain = predicate })) |rejected| {
                    // The slot just freed by `popFront` holds it, so this never allocates.
                    self.modifications.pushFrontAssumeCapacity(rejected.retain);
                    return;
                }
            }
            if (self.fetches.items.len == 0) return;
            const gpa = self.gpa.?;
            const batch: Msg.Batch = .{ .gpa = gpa, .fetches = self.fetches };
            self.fetches = .empty;
            if (pusher.push(.{ .fetch = batch })) |rejected| {
                // Same list, same order: the index stays valid.
                self.fetches = rejected.fetch.fetches;
                return;
            }
            self.positions.deinit(gpa);
            self.positions = .empty;
            assert(self.is_empty());
        }

        fn push_fetches(self: *Self, batch: Msg.Batch) Allocator.Error!void {
            var owned = batch;
            defer owned.fetches.deinit(owned.gpa);
            const gpa = owned.gpa;
            // Backpressure should not multiply work for the same key: merge subscribers into
            // the retained fetch instead.
            for (owned.fetches.items, 0..) |fetch, index| {
                self.push_fetch(gpa, fetch) catch |err| {
                    for (owned.fetches.items[index + 1 ..]) |*rest| rest.deinit(gpa);
                    return err;
                };
            }
        }

        fn push_fetch(self: *Self, gpa: Allocator, fetch: Msg.Fetch) Allocator.Error!void {
            var owned = fetch;
            const entry = self.positions.getOrPut(gpa, fetch.key) catch |err| {
                owned.deinit(gpa);
                return err;
            };
            if (entry.found_existing) {
                return self.fetches.items[entry.value_ptr.*].merge(gpa, owned);
            }
            entry.value_ptr.* = self.fetches.items.len;
            self.fetches.append(gpa, owned) catch |err| {
                self.positions.removeByPtr(entry.key_ptr);
                owned.deinit(gpa);
                return err;
            };
            assert(self.positions.count() == self.fetches.items.len);
        }

        fn push_retain(self: *Self, predicate: Msg.Predicate) Allocator.Error!void {
            const gpa = self.gpa.?;
            // Keep the predicate first so the actor prunes active work too.
            try self.modifications.pushBack(gpa, predicate);
            // Retain applies immediately to queued fetch subscribers.
            var kept: usize = 0;
            for (self.fetches.items) |*fetch| {
                if (!fetch.retain(&predicate)) {
                    fetch.deinit(gpa);
                    continue;
                }
                self.fetches.items[kept] = fetch.*;
                kept += 1;
            }
            self.fetches.shrinkRetainingCapacity(kept);
            // An emptied batch releases its allocation. The index is rebuilt either way.
            if (kept == 0) {
                self.fetches.deinit(gpa);
                self.fetches = .empty;
            }
            self.positions.deinit(gpa);
            self.positions = .empty;
            try self.positions.ensureTotalCapacity(gpa, @intCast(kept));
            for (self.fetches.items, 0..) |fetch, position| {
                self.positions.putAssumeCapacityNoClobber(fetch.key, position);
            }
            assert(self.positions.count() == kept);
        }
    };
}

const testing = std.testing;
const TestMessage = Message(u8, u16, void);
const TestPending = Pending(u8, u16, void);

const Collect = struct {
    messages: std.ArrayList(TestMessage) = .empty,
    /// Reject (give back) messages of this kind, if set.
    reject: ?std.meta.Tag(TestMessage) = null,

    pub fn push(self: *Collect, message: TestMessage) ?TestMessage {
        if (self.reject) |kind| if (message == kind) return message;
        self.messages.append(testing.allocator, message) catch @panic("test OOM");
        return null;
    }

    fn deinit(self: *Collect) void {
        for (self.messages.items) |message| TestMessage.discard(message);
        self.messages.deinit(testing.allocator);
    }
};

fn handle(pending: *TestPending, message: TestMessage) !void {
    try TestMessage.handle(testing.allocator, pending, message);
}

fn queued(key: u8, subscribers: []const u16) !TestMessage {
    var message = try TestMessage.fetch_one(testing.allocator, key, subscribers[0], {});
    const list = &message.fetch.fetches.items[0].subscribers;
    try list.appendSlice(testing.allocator, subscribers[1..]);
    return message;
}

fn keep_all(_: void, _: u8, _: u16) bool {
    return true;
}

fn keep_none(_: void, _: u8, _: u16) bool {
    return false;
}

fn subscriber_is(value: u16, _: u8, subscriber: u16) bool {
    return subscriber == value;
}

fn expect_fetch(message: TestMessage, keys: []const u8, first_subscribers: []const u16) !void {
    const fetches = message.fetch.fetches.items;
    try testing.expectEqual(keys.len, fetches.len);
    for (keys, fetches) |key, item| try testing.expectEqual(key, item.key);
    try testing.expectEqualSlices(u16, first_subscribers, fetches[0].subscribers.items);
}

test "duplicate fetches for same key merge subscribers" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    try handle(&pending, try queued(1, &.{ 10, 11 }));
    try handle(&pending, try queued(1, &.{ 11, 12 }));
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expectEqual(@as(usize, 1), collect.messages.items.len);
    try expect_fetch(collect.messages.items[0], &.{1}, &.{ 10, 11, 12 });
}

test "retain prunes pending fetch subscribers" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    try handle(&pending, try queued(1, &.{ 10, 11 }));
    try handle(&pending, .{ .retain = .init(@as(u16, 11), subscriber_is) });
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expectEqual(@as(usize, 2), collect.messages.items.len);
    try testing.expect(collect.messages.items[0] == .retain);
    try expect_fetch(collect.messages.items[1], &.{1}, &.{11});
}

test "retain drops pending fetch when all subscribers are dropped" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    try handle(&pending, try queued(1, &.{ 10, 11 }));
    try handle(&pending, .{ .retain = .init(@as(u16, 12), subscriber_is) });
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expectEqual(@as(usize, 1), collect.messages.items.len);
    try testing.expect(collect.messages.items[0] == .retain);
}

test "retain messages drain before fetches" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    try handle(&pending, try queued(1, &.{10}));
    try handle(&pending, .{ .retain = .init({}, keep_all) });
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expectEqual(@as(usize, 2), collect.messages.items.len);
    try testing.expect(collect.messages.items[0] == .retain);
    try expect_fetch(collect.messages.items[1], &.{1}, &.{10});
}

test "draining after a retain releases the fetch buffer" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    for (0..200) |key| try handle(&pending, try queued(@intCast(key), &.{1}));
    try handle(&pending, .{ .retain = .init({}, keep_none) });
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expect(pending.is_empty());
    try testing.expectEqual(@as(usize, 0), pending.fetches.capacity);
    try testing.expectEqual(@as(u32, 0), pending.positions.capacity());
}

fn key_is(value: u8, key: u8, _: u16) bool {
    return key == value;
}

test "retain reindexes fetches before merging new subscribers" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    for (0..100) |key| try handle(&pending, try queued(@intCast(key), &.{10}));
    try handle(&pending, .{ .retain = .init(@as(u8, 99), key_is) });
    try testing.expect(pending.positions.capacity() < 100);
    // Key 99 merges a new subscriber at its new position; key 0 starts a fetch behind it.
    try handle(&pending, try queued(99, &.{11}));
    try handle(&pending, try queued(0, &.{12}));
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expectEqual(@as(usize, 2), collect.messages.items.len);
    try expect_fetch(collect.messages.items[1], &.{ 99, 0 }, &.{ 10, 11 });
    const second = collect.messages.items[1].fetch.fetches.items[1];
    try testing.expectEqualSlices(u16, &.{12}, second.subscribers.items);
}

test "rejected drains preserve fetch order and coalescing" {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    try handle(&pending, try queued(2, &.{10}));
    try handle(&pending, try queued(1, &.{20}));
    try handle(&pending, .{ .retain = .init({}, keep_all) });
    // Reject the retain, then accept it and reject the fetch batch.
    var reject_all: Collect = .{ .reject = .retain };
    pending.drain(&reject_all);
    try testing.expectEqual(@as(usize, 1), pending.modifications.len);
    var reject_fetch: Collect = .{ .reject = .fetch };
    defer reject_fetch.deinit();
    pending.drain(&reject_fetch);
    try testing.expectEqual(@as(usize, 0), pending.modifications.len);
    // The rejected batch keeps its order and coalesces later fetches.
    try handle(&pending, try queued(2, &.{11}));
    try handle(&pending, try queued(3, &.{30}));
    var collect: Collect = .{};
    defer collect.deinit();
    pending.drain(&collect);
    try testing.expectEqual(@as(usize, 1), collect.messages.items.len);
    try expect_fetch(collect.messages.items[0], &.{ 2, 1, 3 }, &.{ 10, 11 });
    try testing.expect(pending.is_empty());
    try testing.expectEqual(@as(usize, 0), pending.fetches.capacity);
    try testing.expectEqual(@as(u32, 0), pending.positions.capacity());
    // A key from the drained batch starts a new batch with only its new subscriber.
    try handle(&pending, try queued(2, &.{12}));
    var again: Collect = .{};
    defer again.deinit();
    pending.drain(&again);
    try expect_fetch(again.messages.items[0], &.{2}, &.{12});
}

test "from fetch creates single subscriber fetch key" {
    var key = try FetchKey(u8, u16, void).init(testing.allocator, 7, 8, {});
    defer key.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 7), key.key);
    try testing.expectEqualSlices(u16, &.{8}, key.subscribers.items);
}

var key_comparisons: usize = 0;

const CountedKey = struct {
    value: u32,
    pub const fixed_size: usize = 4;

    pub fn write(self: CountedKey, writer: *codec.Writer) void {
        writer.write_int(u32, self.value);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!CountedKey {
        return .{ .value = try reader.read_int(u32) };
    }

    pub fn order(a: CountedKey, b: CountedKey) std.math.Order {
        key_comparisons += 1;
        return std.math.order(a.value, b.value);
    }
};

test "queueing distinct keys does not compare every pending fetch" {
    // Distinct keys are compared only on hash collisions, so two comparisons per key is a
    // loose bound.
    const keys = 10_000;
    const M = Message(CountedKey, u16, void);
    var pending: M.Overflow = .empty;
    defer pending.deinit(testing.allocator);
    key_comparisons = 0;
    for (0..keys) |key| {
        const message = try M.fetch_one(testing.allocator, .{ .value = @intCast(key) }, 1, {});
        try M.handle(testing.allocator, &pending, message);
    }
    try testing.expect(key_comparisons <= 2 * keys);
    try testing.expectEqual(@as(usize, keys), pending.fetches.items.len);
}

const TargetMessage = Message(u8, u16, Targets(u8));

fn targeted(key: u8, subscriber: u16, peers: ?[]const u8) !TargetMessage {
    const gpa = testing.allocator;
    const targets: Targets(u8) = if (peers) |list| try .init(gpa, list) else .unrestricted;
    return TargetMessage.fetch_one(gpa, key, subscriber, targets);
}

fn drain_targets(pending: *TargetMessage.Overflow) ?std.ArrayList(u8) {
    const Grab = struct {
        message: ?TargetMessage = null,
        pub fn push(self: *@This(), message: TargetMessage) ?TargetMessage {
            self.message = message;
            return null;
        }
    };
    var grab: Grab = .{};
    pending.drain(&grab);
    var batch = grab.message.?.fetch;
    defer batch.deinit();
    assert(batch.fetches.items.len == 1);
    const peers = batch.fetches.items[0].metadata.peers orelse return null;
    return peers.clone(testing.allocator) catch @panic("test OOM");
}

test "duplicate fetches merge metadata" {
    var pending: TargetMessage.Overflow = .empty;
    defer pending.deinit(testing.allocator);
    try TargetMessage.handle(testing.allocator, &pending, try targeted(1, 10, &.{ 2, 3 }));
    try TargetMessage.handle(testing.allocator, &pending, try targeted(1, 11, &.{ 3, 4 }));
    var peers = drain_targets(&pending).?;
    defer peers.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &.{ 2, 3, 4 }, peers.items);
}

test "unrestricted metadata dominates duplicate fetches" {
    var pending: TargetMessage.Overflow = .empty;
    defer pending.deinit(testing.allocator);
    try TargetMessage.handle(testing.allocator, &pending, try targeted(1, 10, &.{2}));
    try TargetMessage.handle(testing.allocator, &pending, try targeted(1, 11, null));
    try TargetMessage.handle(testing.allocator, &pending, try targeted(1, 12, &.{3}));
    try testing.expect(drain_targets(&pending) == null);
}

test "mailbox discards queued fetches on close" {
    const actor = @import("actor");
    const runtime = @import("runtime");
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    const Root = struct {
        fn run(io: std.Io) !void {
            const gpa = testing.allocator;
            var pair = try actor.mailbox.new(TestMessage, gpa, io, 1);
            defer pair.sender.deinit();
            _ = try pair.sender.enqueue(try queued(1, &.{10}));
            _ = try pair.sender.enqueue(try queued(2, &.{20}));
            _ = try pair.sender.enqueue(try queued(2, &.{21}));
            var first = (try pair.receiver.recv()).?;
            try expect_fetch(first, &.{1}, &.{10});
            first.fetch.deinit();
            var second = (try pair.receiver.recv()).?;
            try expect_fetch(second, &.{2}, &.{ 20, 21 });
            second.fetch.deinit();
            _ = try pair.sender.enqueue(try queued(3, &.{30}));
            _ = try pair.sender.enqueue(try queued(4, &.{40}));
            pair.receiver.deinit(); // the leak checker proves both were freed
        }
    };
    try try runner.start(Root.run, .{runner.io()});
}

/// A naive model of the overflow: queued retains and fetches in first-push order, each with
/// its distinct subscribers in insertion order.
const ModelFetch = struct { key: u8, subscribers: std.ArrayList(u16) = .empty };

const IngressModel = struct {
    retains: usize = 0,
    fetches: std.ArrayList(ModelFetch) = .empty,

    fn deinit(model: *IngressModel) void {
        for (model.fetches.items) |*fetch| fetch.subscribers.deinit(testing.allocator);
        model.fetches.deinit(testing.allocator);
    }

    fn push(model: *IngressModel, key: u8, subscriber: u16) !void {
        const gpa = testing.allocator;
        for (model.fetches.items) |*fetch| {
            if (fetch.key != key) continue;
            if (std.mem.indexOfScalar(u16, fetch.subscribers.items, subscriber) == null) {
                try fetch.subscribers.append(gpa, subscriber);
            }
            return;
        }
        var fetch: ModelFetch = .{ .key = key };
        try fetch.subscribers.append(gpa, subscriber);
        try model.fetches.append(gpa, fetch);
    }

    /// Keeps subscribers at or above `floor`; drops emptied fetches.
    fn retain(model: *IngressModel, floor: u16) void {
        model.retains += 1;
        var kept: usize = 0;
        for (model.fetches.items) |*fetch| {
            var subscribers_kept: usize = 0;
            for (fetch.subscribers.items) |subscriber| {
                if (subscriber < floor) continue;
                fetch.subscribers.items[subscribers_kept] = subscriber;
                subscribers_kept += 1;
            }
            fetch.subscribers.shrinkRetainingCapacity(subscribers_kept);
            if (subscribers_kept == 0) {
                fetch.subscribers.deinit(testing.allocator);
                continue;
            }
            model.fetches.items[kept] = fetch.*;
            kept += 1;
        }
        model.fetches.shrinkRetainingCapacity(kept);
    }
};

fn keep_at_least(floor: u16, _: u8, subscriber: u16) bool {
    return subscriber >= floor;
}

/// Drains `pending` into a collector that rejects `reject`, and checks the drained messages
/// and the model's state after the drain.
fn drain_against_model(
    pending: *TestPending,
    model: *IngressModel,
    reject: ?std.meta.Tag(TestMessage),
) !void {
    var collect: Collect = .{ .reject = reject };
    defer collect.deinit();
    pending.drain(&collect);
    const messages = collect.messages.items;
    if (reject == .retain and model.retains > 0) {
        // The first retain is given back; nothing drains past it.
        try testing.expectEqual(0, messages.len);
        return;
    }
    const fetched = reject != .fetch and model.fetches.items.len > 0;
    try testing.expectEqual(model.retains + @intFromBool(fetched), messages.len);
    for (messages[0..model.retains]) |message| try testing.expect(message == .retain);
    model.retains = 0;
    if (!fetched) {
        try testing.expectEqual(model.fetches.items.len == 0, pending.is_empty());
        return;
    }
    const fetches = messages[messages.len - 1].fetch.fetches.items;
    try testing.expectEqual(model.fetches.items.len, fetches.len);
    for (model.fetches.items, fetches) |expected, actual| {
        try testing.expectEqual(expected.key, actual.key);
        try testing.expectEqualSlices(u16, expected.subscribers.items, actual.subscribers.items);
    }
    for (model.fetches.items) |*fetch| fetch.subscribers.deinit(testing.allocator);
    model.fetches.clearRetainingCapacity();
    try testing.expect(pending.is_empty());
}

/// Model check of the coalescing policy over random fetch, retain, and drain sequences,
/// including drains the mailbox rejects.
fn ingress_model(_: void, smith: *std.testing.Smith) anyerror!void {
    var pending: TestPending = .empty;
    defer pending.deinit(testing.allocator);
    var model: IngressModel = .{};
    defer model.deinit();
    // Operations come from raw bytes: `Smith.value` maps a random 8-byte word outside the
    // type's range to its minimum and `Smith.eos` ends random input almost at once, so the
    // seeded driver would otherwise replay one operation.
    var raw: [3 * 64]u8 = undefined;
    smith.bytes(&raw);
    for (0..raw.len / 3) |step| {
        const key = raw[3 * step] % 8;
        const subscriber: u16 = raw[3 * step + 1] % 16;
        switch (raw[3 * step + 2] % 6) {
            0, 1, 2 => {
                const message = try TestMessage.fetch_one(testing.allocator, key, subscriber, {});
                try handle(&pending, message);
                try model.push(key, subscriber);
            },
            3 => {
                try handle(&pending, .{ .retain = .init(subscriber, keep_at_least) });
                model.retain(subscriber);
            },
            4 => try drain_against_model(&pending, &model, null),
            else => {
                const reject: std.meta.Tag(TestMessage) = if (key % 2 == 0) .retain else .fetch;
                try drain_against_model(&pending, &model, reject);
            },
        }
    }
    try drain_against_model(&pending, &model, null);
}

test "fuzz: ingress coalescing matches a model" {
    const p2p = @import("p2p");
    try p2p.fuzz.run({}, ingress_model, 0x696e677265737321, 500);
}
