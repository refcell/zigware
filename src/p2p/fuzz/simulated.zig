//! The `simulated` fuzz target (commonware `p2p/fuzz/fuzz_targets/simulated.rs`): a random
//! sequence of channel registrations, sends, receives, and link changes on the simulated
//! network, checking that every delivered message was sent to that receiver on that channel,
//! in order (unreliable links may drop messages, never reorder or invent them).
//!
//! `FuzzInput` decodes from an `invariants.minifuzz.Unstructured` exactly as commonware's
//! `Arbitrary` derive does. The seeded run in `zig build test` uses a small search limit: each
//! case runs a whole network, and a drawn message size is usually the 1 MiB maximum.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const cryptography = @import("cryptography");
const invariants = @import("invariants");
const runtime = @import("runtime");
const utils_pkg = @import("utils");

const p2p = @import("../root.zig");
const network_mod = @import("../simulated/network.zig");
const IoRng = @import("../utils/io_rng.zig").IoRng;

const minifuzz = invariants.minifuzz;
const Unstructured = minifuzz.Unstructured;
const Key = cryptography.ed25519.PublicKey;
const Net = network_mod.Network(Key);
const Message = p2p.Message(Key);

const operations_max = 50;
const peers_max = 16;
const peers_min = 2;
const message_size_max: u32 = 1024 * 1024;
const channel_size = 8; // `Channel::SIZE`: a u64.
const sleep_duration_max_ms = 1000;

/// Default rate limit set high enough to not interfere with normal operation.
const test_quota = p2p.Quota.per_second(std.math.maxInt(u32));

/// Operations on the simulated network (commonware's `Operation`, `derive(Arbitrary)`).
const RegisterChannel = @FieldType(Operation, "register_channel");

pub const Operation = union(enum) {
    register_channel: struct { peer_idx: u8, channel_id: u8 },
    send_message: struct { peer_idx: u8, channel_id: u8, to_idx: u8, msg_size: usize },
    receive_messages,
    add_link: struct {
        from_idx: u8,
        to_idx: u8,
        latency_ms: u16,
        jitter: u16,
        success_rate: u64,
    },
    remove_link: struct { from_idx: u8, to_idx: u8 },

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!Operation {
        // derive(Arbitrary): a u32 scaled into the variant count, then the fields in order.
        const raw: u64 = try u.arbitrary(u32);
        const variants = @typeInfo(Operation).@"union".field_names.len;
        const index = (raw * variants) >> 32;
        assert(index < variants);
        return switch (index) {
            0 => .{ .register_channel = try u.arbitrary(RegisterChannel) },
            1 => .{ .send_message = try u.arbitrary(@FieldType(Operation, "send_message")) },
            2 => .receive_messages,
            3 => .{ .add_link = try u.arbitrary(@FieldType(Operation, "add_link")) },
            4 => .{ .remove_link = try u.arbitrary(@FieldType(Operation, "remove_link")) },
            else => unreachable, // Proof: index < variants == 5.
        };
    }
};

/// commonware's `FuzzInput`: seed, operations, then the peer count.
pub const FuzzInput = struct {
    seed: u64,
    operations: [operations_max + dense_setup_max]Operation,
    operation_count: usize,
    num_peers: usize,

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!FuzzInput {
        var input: FuzzInput = undefined;
        input.seed = try u.arbitrary(u64);
        input.operation_count = u.int_in_range(usize, 1, operations_max);
        for (input.operations[0..input.operation_count]) |*operation| {
            operation.* = try u.arbitrary(Operation);
        }
        input.num_peers = u.int_in_range(usize, peers_min, peers_max);
        return input;
    }
};

/// Setup operations `densify` prepends: two channels per peer and every directed link.
const dense_setup_max = 2 * peers_max + peers_max * (peers_max - 1);
const dense_peers_max = 4;
const dense_message_size_max = 64;

/// The seeded run's input: commonware's uniform operations rarely line up a registered
/// channel at both ends, a link, a send, and a receive (libFuzzer finds them by coverage), so
/// the seeded run uses at most four peers and two channels, registers both channels on every
/// peer, links every pair reliably, and sends short messages before the random operations.
pub fn densify(input: *FuzzInput) void {
    assert(input.operation_count <= operations_max);
    input.num_peers = peers_min + input.num_peers % (dense_peers_max - peers_min + 1);
    const n = input.num_peers;
    var setup: [dense_setup_max]Operation = undefined;
    var count: usize = 0;
    for (0..n) |peer| {
        for ([_]u8{ 0, 1 }) |channel| {
            const op: RegisterChannel = .{ .peer_idx = @intCast(peer), .channel_id = channel };
            setup[count] = .{ .register_channel = op };
            count += 1;
        }
    }
    for (0..n) |from| {
        for (0..n) |to| {
            if (from == to) continue;
            setup[count] = .{ .add_link = .{
                .from_idx = @intCast(from),
                .to_idx = @intCast(to),
                .latency_ms = 10,
                .jitter = 0,
                .success_rate = std.math.maxInt(u64),
            } };
            count += 1;
        }
    }
    const ops = input.operations[0..input.operation_count];
    for (ops) |*operation| switch (operation.*) {
        .register_channel => |*op| op.channel_id &= 1,
        .send_message => |*op| {
            op.channel_id &= 1;
            op.msg_size %= dense_message_size_max + 1;
        },
        .add_link => |*op| op.latency_ms %= 100,
        else => {},
    };
    std.mem.copyBackwards(Operation, input.operations[count..][0..ops.len], ops);
    @memcpy(input.operations[0..count], setup[0..count]);
    input.operation_count += count;
}

/// A registered channel slot, keyed by `(peer_idx, channel_id)`.
const Slot = ?Net.Registered;
const slot_count = peers_max * 256;

fn slot_index(peer: usize, channel: u8) usize {
    assert(peer < peers_max);
    return peer * 256 + channel;
}

/// Expected messages for one `(to_idx, sender, channel_id)`, oldest first.
const Expected = struct {
    to_idx: usize,
    from_idx: usize,
    channel_id: u8,
    queue: std.Deque([]u8) = .empty,
};

const State = struct {
    gpa: Allocator,
    io: Io,
    oracle: Net.Oracle,
    keys: []const Key,
    slots: []Slot,
    expected: std.ArrayList(Expected) = .empty,

    fn deinit(state: *State) void {
        for (state.expected.items) |*entry| {
            while (entry.queue.popFront()) |message| state.gpa.free(message);
            entry.queue.deinit(state.gpa);
        }
        state.expected.deinit(state.gpa);
        for (state.slots) |*slot| {
            if (slot.*) |*registered| registered.deinit();
        }
    }

    fn expected_for(state: *State, to: usize, from: usize, channel: u8) !*Expected {
        for (state.expected.items) |*entry| {
            if (entry.to_idx == to and entry.from_idx == from and entry.channel_id == channel) {
                return entry;
            }
        }
        const entry: Expected = .{ .to_idx = to, .from_idx = from, .channel_id = channel };
        try state.expected.append(state.gpa, entry);
        return &state.expected.items[state.expected.items.len - 1];
    }

    fn register(state: *State, peer_idx: u8, channel_id: u8) !void {
        const idx = peer_idx % state.keys.len;
        const slot = &state.slots[slot_index(idx, channel_id)];
        if (slot.* != null) return;
        const control = state.oracle.control(state.keys[idx]);
        slot.* = control.register(channel_id, test_quota) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => null,
        };
    }

    fn send(state: *State, op: @FieldType(Operation, "send_message")) !void {
        const from = op.peer_idx % state.keys.len;
        const to = op.to_idx % state.keys.len;
        const size = @min(op.msg_size, message_size_max - channel_size);
        // Skip unless both ends registered the channel.
        if (state.slots[slot_index(to, op.channel_id)] == null) return;
        const sender_slot = &state.slots[slot_index(from, op.channel_id)];
        const registered = if (sender_slot.*) |*registered| registered else return;
        const message = try state.gpa.alloc(u8, size);
        errdefer state.gpa.free(message);
        state.io.random(message);
        const sent = try registered.sender.send(.{ .one = state.keys[to] }, &.{message}, true);
        defer state.gpa.free(sent);
        if (sent.len == 0) return state.gpa.free(message);
        const entry = try state.expected_for(to, from, op.channel_id);
        try entry.queue.pushBack(state.gpa, message);
    }

    /// Receives at most one message on each receiver channel with pending messages.
    fn receive(state: *State) !void {
        var index: usize = 0;
        while (index < state.expected.items.len) : (index += 1) {
            const entry = state.expected.items[index];
            // One receive per distinct (to_idx, channel_id) mailbox.
            const first = for (state.expected.items[0..index]) |earlier| {
                if (earlier.to_idx == entry.to_idx and earlier.channel_id == entry.channel_id) {
                    break false;
                }
            } else true;
            if (!first) continue;
            const slot = &state.slots[slot_index(entry.to_idx, entry.channel_id)];
            const registered = if (slot.*) |*registered| registered else continue;
            var message = (try recv_timeout(state.io, &registered.receiver)) orelse continue;
            defer message.deinit();
            try state.check(entry.to_idx, entry.channel_id, &message);
        }
    }

    /// A delivered message must be queued for its sender, receiver, and channel; messages
    /// queued before it were dropped.
    fn check(state: *State, to: usize, channel: u8, message: *const Message) !void {
        const from = for (state.keys, 0..) |key, idx| {
            if (key.eql(message.peer)) break idx;
        } else return error.UnknownSender;
        const position = for (state.expected.items, 0..) |entry, position| {
            if (entry.to_idx == to and entry.from_idx == from and entry.channel_id == channel) {
                break position;
            }
        } else return error.ExpectedQueueNotFound;
        const entry = &state.expected.items[position];
        var found: ?usize = null;
        for (0..entry.queue.len) |i| {
            if (std.mem.eql(u8, entry.queue.at(i), message.payload)) {
                found = i;
                break;
            }
        }
        const pos = found orelse return error.UnexpectedMessage;
        for (0..pos + 1) |_| state.gpa.free(entry.queue.popFront().?);
        if (entry.queue.len > 0) return;
        entry.queue.deinit(state.gpa);
        _ = state.expected.orderedRemove(position);
    }

    fn add_link(state: *State, op: @FieldType(Operation, "add_link")) !void {
        const from = op.from_idx % state.keys.len;
        const to = op.to_idx % state.keys.len;
        const probability: utils_pkg.Probability = .{ .threshold = op.success_rate };
        const link: network_mod.Link = .{
            .latency = utils_pkg.Duration.from_millis(op.latency_ms),
            .jitter = utils_pkg.Duration.from_millis(op.jitter),
            .success_rate = probability.as_f64(),
        };
        state.oracle.add_link(state.keys[from], state.keys[to], link) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };
    }

    fn remove_link(state: *State, op: @FieldType(Operation, "remove_link")) !void {
        const from = op.from_idx % state.keys.len;
        const to = op.to_idx % state.keys.len;
        // A missing link or closed network is expected; the operation is a no-op then.
        state.oracle.remove_link(state.keys[from], state.keys[to]) catch {};
    }
};

/// The next message on `receiver` (any p2p receiver), or null after
/// `sleep_duration_max_ms` of (simulated) time.
pub fn recv_timeout(io: Io, receiver: anytype) !?Message {
    const Receiver = @typeInfo(@TypeOf(receiver)).pointer.child;
    const Outcome = union(enum) {
        received: @typeInfo(@TypeOf(Receiver.recv)).@"fn".return_type.?,
        timeout: Io.Cancelable!void,
    };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    try select.concurrent(.received, Receiver.recv, .{receiver});
    const duration: Io.Duration = .fromMilliseconds(sleep_duration_max_ms);
    select.concurrent(.timeout, Io.sleep, .{ io, duration, .awake }) catch |err| {
        select.cancelDiscard();
        return err;
    };
    const first = try select.await();
    while (select.cancel()) |rest| {
        // A message that lands as the timeout fires counts as dropped.
        if (rest == .received) if (rest.received) |value| {
            var late = value;
            late.deinit();
        } else |_| {};
    }
    return switch (first) {
        .received => |result| result catch null,
        .timeout => null,
    };
}

fn run_network(io: Io, input: *const FuzzInput) !void {
    const gpa = testing.allocator;
    const rng: IoRng = .{ .io = io };
    var keys: [peers_max]Key = undefined;
    for (keys[0..input.num_peers]) |*key| {
        key.* = cryptography.ed25519.PrivateKey.from_seed(rng.next_u64()).public_key();
    }
    const network = try Net.init(gpa, io, .{
        .max_size = message_size_max,
        .max_peers_per_set = input.num_peers,
        .disconnect_on_block = false,
        .tracked_peer_sets = 1,
    });
    var task = try io.concurrent(Net.run, .{network});
    defer {
        network.close();
        task.await(io) catch |err| std.debug.panic("network run: {t}", .{err});
        network.deinit();
    }
    // commonware's `new_with_peers`: every peer tracked network-wide.
    const sorted = try gpa.dupe(Key, keys[0..input.num_peers]);
    defer gpa.free(sorted);
    p2p.TrackedPeers(Key).PeerSet.sort(sorted);
    const tracked: p2p.TrackedPeers(Key) = .init_primary(.init(sorted));
    if (network.oracle().manager().track(0, tracked) != .ok) return error.TrackFailed;
    const slots = try gpa.alloc(Slot, slot_count);
    defer gpa.free(slots);
    @memset(slots, null);
    var state: State = .{
        .gpa = gpa,
        .io = io,
        .oracle = network.oracle(),
        .keys = keys[0..input.num_peers],
        .slots = slots,
    };
    defer state.deinit();
    for (input.operations[0..input.operation_count]) |operation| switch (operation) {
        .register_channel => |op| try state.register(op.peer_idx, op.channel_id),
        .send_message => |op| try state.send(op),
        .receive_messages => try state.receive(),
        .add_link => |op| try state.add_link(op),
        .remove_link => |op| try state.remove_link(op),
    };
}

/// Runs one fuzz input on a deterministic runtime seeded with its seed.
pub fn fuzz(input: *const FuzzInput) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{ .seed = input.seed });
    defer runner.deinit();
    try (try runner.start(run_network, .{ runner.io(), input }));
}

fn body(_: void, u: *Unstructured) !void {
    const input = try u.arbitrary(FuzzInput);
    try fuzz(&input);
}

fn dense_body(_: void, u: *Unstructured) !void {
    var input = try u.arbitrary(FuzzInput);
    densify(&input);
    try fuzz(&input);
}

test "fuzz simulated network" {
    try (minifuzz.Builder{}).with_search_limit(24).run(testing.allocator, {}, dense_body);
}

test "fuzz simulated network (coverage-guided)" {
    const math = @import("math");
    try testing.fuzz({}, math.testing.smith_body(void, body), .{});
}
