//! The `broadcast_engine_operations` fuzz target of commonware's `broadcast/fuzz`: start a
//! buffered engine per peer on a simulated network with fuzzed links and cache size, then run
//! fuzzed broadcasts, subscriptions, gets, and sleeps, checking that every message returned
//! for a digest has that digest.
//!
//! Inputs come from `invariants.minifuzz.Unstructured` in the order of commonware's
//! `FuzzInput::arbitrary`. `Vec<u8>` draws like `arbitrary`'s `arbitrary_iter` (a continue
//! bit before each byte), and `Recipients::Some` shuffles the peers like `rand`'s
//! `SliceRandom::shuffle` on `TestRng`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;

const broadcast = @import("root.zig");
const buffered = broadcast.buffered;

const Unstructured = minifuzz.Unstructured;
const metrics = runtime.telemetry.metrics;
const Sha256 = cryptography.Sha256;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Recipients = p2p.Recipients(Key);

/// High enough to not interfere with normal operation.
const test_quota = p2p.Quota.per_second(1_024);
/// Capped like commonware's, to keep the rate limiter's arithmetic in range.
const sleep_ms_max = 1000;
const peers_max = 5;
const actions_max = 10;
/// Longest fuzzed byte string (`Vec<u8>`); the input runs out long before.
const bytes_max = 4096;

/// A fuzzed message, digested over its encoding.
pub const FuzzMessage = struct {
    commitment: []const u8,
    content: []const u8,

    pub const Digest = Sha256.Digest;
    pub const Cfg = codec.RangeCfg(usize);

    /// SHA-256 of the encoding, hashed in parts so no length bound is needed.
    pub fn digest(message: *const FuzzMessage) Digest {
        assert(message.commitment.len <= std.math.maxInt(u32));
        assert(message.content.len <= std.math.maxInt(u32));
        var hasher = Sha256.init();
        for ([_][]const u8{ message.commitment, message.content }) |part| {
            var prefix: [5]u8 = undefined;
            var writer = codec.Writer.init(&prefix);
            codec.write(usize, part.len, &writer);
            hasher.update(writer.written());
            hasher.update(part);
        }
        return hasher.finalize();
    }

    pub fn write(message: FuzzMessage, writer: *codec.Writer) void {
        codec.write([]const u8, message.commitment, writer);
        codec.write([]const u8, message.content, writer);
    }

    pub fn encode_size(message: FuzzMessage) usize {
        return codec.encode_size([]const u8, message.commitment) +
            codec.encode_size([]const u8, message.content);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!FuzzMessage {
        const commitment = try codec.read_range([]const u8, gpa, reader, range);
        errdefer gpa.free(commitment);
        const content = try codec.read_range([]const u8, gpa, reader, range);
        return .{ .commitment = commitment, .content = content };
    }

    pub fn deinit(message: *FuzzMessage, gpa: Allocator) void {
        gpa.free(message.commitment);
        gpa.free(message.content);
        message.* = undefined;
    }

    fn arbitrary(gpa: Allocator, u: *Unstructured) !FuzzMessage {
        const commitment = try u.arbitrary_bytes(gpa, bytes_max);
        errdefer gpa.free(commitment);
        return .{ .commitment = commitment, .content = try u.arbitrary_bytes(gpa, bytes_max) };
    }
};

const RecipientPattern = union(enum) { all, some: u64, one: u64 };

const Source = union(enum) {
    random: FuzzMessage,
    recent: u8,
};

const Action = union(enum) {
    send: struct { peer_index: u64, recipients: RecipientPattern, message: FuzzMessage },
    subscribe: struct { peer_index: u64, source: Source },
    get: struct { peer_index: u64, source: Source },
    sleep_ms: u64,

    fn deinit(action: *Action, gpa: Allocator) void {
        switch (action.*) {
            .send => |*send| send.message.deinit(gpa),
            .subscribe => |*request| if (request.source == .random) {
                request.source.random.deinit(gpa);
            },
            .get => |*request| if (request.source == .random) request.source.random.deinit(gpa),
            .sleep_ms => {},
        }
    }
};

fn arbitrary_pattern(u: *Unstructured) !RecipientPattern {
    return switch (try u.variant_index(3)) {
        0 => .all,
        1 => .{ .some = try u.arbitrary(u64) },
        else => .{ .one = try u.arbitrary(u64) },
    };
}

fn arbitrary_source(gpa: Allocator, u: *Unstructured) !Source {
    if (try u.variant_index(2) == 0) return .{ .random = try FuzzMessage.arbitrary(gpa, u) };
    return .{ .recent = try u.arbitrary(u8) };
}

fn arbitrary_action(gpa: Allocator, u: *Unstructured) !Action {
    return switch (u.int_in_range(u32, 0, 3)) {
        0 => .{ .send = .{
            .peer_index = try u.arbitrary(u64),
            .recipients = try arbitrary_pattern(u),
            .message = try FuzzMessage.arbitrary(gpa, u),
        } },
        1 => .{ .subscribe = .{
            .peer_index = try u.arbitrary(u64),
            .source = try arbitrary_source(gpa, u),
        } },
        2 => .{ .get = .{
            .peer_index = try u.arbitrary(u64),
            .source = try arbitrary_source(gpa, u),
        } },
        else => .{ .sleep_ms = u.int_in_range(u64, 0, sleep_ms_max) },
    };
}

/// commonware's `FuzzInput`.
const Input = struct {
    peers: u64,
    success_percent: u64,
    latency_ms: u64,
    jitter_ms: u64,
    cache_size: usize,
    actions: [actions_max]Action = undefined,
    action_count: usize = 0,

    fn arbitrary(gpa: Allocator, u: *Unstructured) !Input {
        var input: Input = .{
            .peers = u.int_in_range(u64, 1, peers_max),
            .success_percent = u.int_in_range(u64, 30, 100),
            .latency_ms = u.int_in_range(u64, 1, 100),
            .jitter_ms = u.int_in_range(u64, 0, 50),
            .cache_size = u.int_in_range(usize, 5, 10),
        };
        const count = u.int_in_range(usize, 1, actions_max);
        errdefer input.deinit(gpa);
        while (input.action_count < count) {
            input.actions[input.action_count] = try arbitrary_action(gpa, u);
            input.action_count += 1;
        }
        return input;
    }

    fn deinit(input: *Input, gpa: Allocator) void {
        for (input.actions[0..input.action_count]) |*action| action.deinit(gpa);
        input.action_count = 0;
    }
};

/// `SliceRandom::shuffle` (rand 0.10): Fisher-Yates with `IncreasingUniform`, which draws one
/// `u32` per run of indices whose product of ranges fits in it.
fn shuffle(comptime T: type, rng: *utils.rng.TestRng, items: []T) void {
    if (items.len <= 1) return;
    var n: u32 = 0;
    var chunk: u32 = 0;
    var chunk_remaining: u8 = 1; // `n == 0` starts with one free index.
    for (0..items.len) |i| {
        const next_n = n + 1;
        var next_remaining: u8 = undefined;
        if (chunk_remaining == 0) {
            const bound, const remaining = bound_u32(next_n);
            chunk = utils.rng.range_less_than(rng, u32, 0, bound);
            next_remaining = remaining - 1;
        } else {
            next_remaining = chunk_remaining - 1;
        }
        const index = if (next_remaining == 0) chunk else index: {
            const result = chunk % next_n;
            chunk /= next_n;
            break :index result;
        };
        assert(index <= i);
        std.mem.swap(T, &items[i], &items[index]);
        chunk_remaining = next_remaining;
        n = next_n;
    }
}

/// The product `m * (m + 1) * ...` while it fits in a `u32`, and how many factors it has.
fn bound_u32(m: u32) struct { u32, u8 } {
    var product = m;
    var current = m + 1;
    while (true) : (current += 1) {
        product = std.math.mul(u32, product, current) catch {
            return .{ product, @intCast(current - m) };
        };
    }
}

fn resolve_recipients(gpa: Allocator, pattern: RecipientPattern, peers: []const Key) !Recipients {
    switch (pattern) {
        .all => return .all,
        .one => |seed| return .{ .one = peers[seed % peers.len] },
        .some => |seed| {
            var rng = utils.rng.TestRng.init(seed);
            const shuffled = try gpa.dupe(Key, peers);
            defer gpa.free(shuffled);
            shuffle(Key, &rng, shuffled);
            const count = @max(seed % peers.len, 1);
            return .{ .some = try gpa.dupe(Key, shuffled[0..count]) };
        },
    }
}

const Engine = buffered.Engine(FuzzMessage, Net.Manager, Net.Control, Net);
const Item = broadcast.Digested(FuzzMessage);
const Subscription = struct {
    digest: FuzzMessage.Digest,
    receiver: utils.channel.oneshot.Receiver(Item),
};

/// The running network and engines of one case.
const Harness = struct {
    gpa: Allocator,
    io: Io,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: metrics.Registry,
    peers: [peers_max]Key = undefined,
    count: usize,
    mailboxes: [peers_max]?Engine.Mailbox = @splat(null),
    engines: [peers_max]?Io.Future(Engine.Error!void) = @splat(null),
    /// Digests broadcast so far, oldest first. commonware bounds these at 256 (indexed by a
    /// `u8`); a case has at most `actions_max` broadcasts, so the bound is never reached.
    recent: [actions_max]FuzzMessage.Digest = undefined,
    recent_count: usize = 0,
    pending: std.ArrayList(Subscription) = .empty,

    fn start(harness: *Harness, input: *const Input) !void {
        const oracle = harness.network.oracle();
        for (harness.peers[0..harness.count], 0..) |peer, index| {
            var registered = try oracle.control(peer).register(0, test_quota);
            const scope = metrics.Scope.init(&harness.registry).child("peer")
                .with_attribute("index", index);
            const created = Engine.init(harness.gpa, harness.io, &scope, .{
                .public_key = peer,
                .mailbox_size = 1024,
                .deque_size = input.cache_size,
                .priority = false,
                .codec_config = .full(),
                .peer_provider = oracle.manager(),
                .blocker = oracle.control(peer),
            }) catch |err| {
                registered.deinit();
                return err;
            };
            harness.mailboxes[index] = created.mailbox;
            const engine = created.engine;
            harness.engines[index] = try engine.start(registered.sender, registered.receiver);
        }
        const link: p2p.simulated.Link = .{
            .latency = utils.Duration.from_millis(input.latency_ms),
            .jitter = utils.Duration.from_millis(input.jitter_ms),
            .success_rate = @as(f64, @floatFromInt(input.success_percent)) / 100.0,
        };
        for (harness.peers[0..harness.count]) |from| {
            for (harness.peers[0..harness.count]) |to| {
                if (!from.eql(to)) oracle.add_link(from, to, link) catch {};
            }
        }
    }

    fn mailbox(harness: *const Harness, peer_index: u64) Engine.Mailbox {
        return harness.mailboxes[peer_index % harness.count].?;
    }

    fn resolve(harness: *const Harness, source: Source) ?FuzzMessage.Digest {
        return switch (source) {
            .random => |message| message.digest(),
            .recent => |index| if (harness.recent_count == 0)
                null
            else
                harness.recent[index % harness.recent_count],
        };
    }

    fn push_recent(harness: *Harness, digest: FuzzMessage.Digest) void {
        assert(harness.recent_count < actions_max);
        harness.recent[harness.recent_count] = digest;
        harness.recent_count += 1;
    }

    fn act(harness: *Harness, action: *Action) !void {
        const gpa = harness.gpa;
        switch (action.*) {
            .send => |send| {
                const peers = harness.peers[0..harness.count];
                const recipients = try resolve_recipients(gpa, send.recipients, peers);
                defer recipients.deinit(gpa);
                const digest = send.message.digest();
                harness.push_recent(digest);
                const item = try Item.precomputed(gpa, send.message, digest);
                action.* = .{ .sleep_ms = 0 }; // The item owns the message now.
                _ = try harness.mailbox(send.peer_index).broadcast(recipients, item);
            },
            .subscribe => |request| {
                const digest = harness.resolve(request.source) orelse return;
                var receiver = try harness.mailbox(request.peer_index).subscribe(digest);
                const subscription: Subscription = .{ .digest = digest, .receiver = receiver };
                harness.pending.append(gpa, subscription) catch |err| {
                    receiver.deinit();
                    return err;
                };
            },
            .get => |request| {
                const digest = harness.resolve(request.source) orelse return;
                var message = try harness.mailbox(request.peer_index).get(digest) orelse return;
                defer message.deinit();
                try testing.expect(message.inner().digest().eql(digest));
            },
            .sleep_ms => |ms| try harness.io.sleep(.fromMilliseconds(@intCast(ms)), .awake),
        }
    }

    /// Checks completed subscriptions; unresolved ones stay pending.
    fn drain_ready(harness: *Harness) !void {
        var index: usize = 0;
        while (index < harness.pending.items.len) {
            const pending = &harness.pending.items[index];
            var message = pending.receiver.try_recv() catch |err| switch (err) {
                error.Empty => {
                    index += 1;
                    continue;
                },
                error.Closed => {
                    pending.receiver.deinit();
                    _ = harness.pending.swapRemove(index);
                    continue;
                },
            };
            defer message.deinit();
            try testing.expect(message.inner().digest().eql(pending.digest));
            pending.receiver.deinit();
            _ = harness.pending.swapRemove(index);
        }
    }

    fn deinit(harness: *Harness) void {
        for (harness.pending.items) |*pending| pending.receiver.deinit();
        harness.pending.deinit(harness.gpa);
        for (0..harness.count) |index| {
            if (harness.engines[index]) |*future| {
                future.cancel(harness.io) catch |err| std.debug.panic("engine: {t}", .{err});
            }
            if (harness.mailboxes[index]) |*value| value.deinit();
        }
        harness.network.close();
        harness.network_task.await(harness.io) catch |err| std.debug.panic("run: {t}", .{err});
        harness.network.deinit();
        harness.registry.deinit();
    }
};

fn run_case(gpa: Allocator, io: Io, input: *Input) !void {
    var peers: [peers_max]Key = undefined;
    const count: usize = @intCast(input.peers);
    for (peers[0..count], 0..) |*peer, seed| {
        peer.* = cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
    }
    var sorted = peers;
    std.sort.pdq(Key, sorted[0..count], {}, Key.less_than);
    const tracked: p2p.TrackedPeers(Key) = .init_primary(.init(sorted[0..count]));
    const network = try Net.init_with_peers(gpa, io, .{
        .max_size = 1024 * 1024,
        .max_peers_per_set = count,
        .disconnect_on_block = false,
        .tracked_peer_sets = 1,
    }, tracked);
    var harness: Harness = .{
        .gpa = gpa,
        .io = io,
        .network = network,
        .network_task = io.concurrent(Net.run, .{network}) catch |err| {
            network.deinit();
            return err;
        },
        .registry = .init(gpa),
        .peers = peers,
        .count = count,
    };
    defer harness.deinit();
    try harness.start(input);
    for (input.actions[0..input.action_count]) |*action| {
        try harness.act(action);
        try harness.drain_ready();
    }
}

/// Runs one input on a fresh deterministic runtime.
pub fn run(gpa: Allocator, u: *Unstructured) !void {
    var input = try Input.arbitrary(gpa, u);
    defer input.deinit(gpa);
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try (try runner.start(run_case, .{ gpa, runner.io(), &input }));
}

/// Runs `bytes` as one input, as the coverage-guided target does.
pub fn run_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    run(gpa, &u) catch |err| switch (err) {
        error.NotEnoughData, error.IncorrectFormat => {},
        else => return err,
    };
}

fn body(_: void, u: *Unstructured) !void {
    return run(testing.allocator, u);
}

test "fuzz broadcast engine operations (minifuzz)" {
    const limit = 16 * @as(u64, build_options.fuzz_soak);
    try (minifuzz.Builder{}).with_seed(build_options.fuzz_seed).with_search_limit(limit)
        .run(testing.allocator, {}, body);
}

// minifuzz grows its inputs only when one runs out, which these generators never report, so
// random inputs reach the deeper actions.
test "fuzz broadcast engine operations (random inputs)" {
    const cases = 32 * @as(u64, build_options.fuzz_soak);
    for (0..cases) |case| {
        var rng = utils.rng.TestRng.init(build_options.fuzz_seed +% case);
        var bytes: [512]u8 = undefined;
        rng.fill_bytes(&bytes);
        try run_input(testing.allocator, &bytes);
    }
}

test "fuzz broadcast engine operations (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn fuzz(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [4096]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_input(testing.allocator, bytes[0..length]);
        }
    }.fuzz, .{});
}

test "shuffle matches rand 0.10" {
    // From `StdRng::seed_from_u64(seed)`, `v.shuffle(&mut rng)`, then `rng.random::<u32>()`.
    const cases = [_]struct { seed: u64, expected: []const usize, next: u32 }{
        .{ .seed = 12345, .expected = &.{ 1, 4, 0, 2, 3 }, .next = 1313969190 },
        .{
            .seed = 7,
            .expected = &.{ 1, 3, 4, 6, 11, 7, 2, 5, 13, 9, 10, 12, 0, 8 },
            .next = 612261766,
        },
        .{
            .seed = 0,
            .expected = &.{ 16, 14, 7, 3, 6, 13, 10, 19, 8, 11, 12, 15, 5, 18, 0, 2, 17, 1, 4, 9 },
            .next = 3476097558,
        },
    };
    for (cases) |case| {
        var items: [20]usize = undefined;
        for (&items, 0..) |*item, index| item.* = index;
        var rng = utils.rng.TestRng.init(case.seed);
        shuffle(usize, &rng, items[0..case.expected.len]);
        try testing.expectEqualSlices(usize, case.expected, items[0..case.expected.len]);
        try testing.expectEqual(case.next, rng.next_u32());
    }
}

test "fuzz message digests its encoding" {
    const message: FuzzMessage = .{ .commitment = "commitment", .content = "content" };
    const encoded = try codec.encode(FuzzMessage, testing.allocator, message);
    defer testing.allocator.free(encoded);
    try testing.expect(message.digest().eql(Sha256.hash(&.{encoded})));
}
