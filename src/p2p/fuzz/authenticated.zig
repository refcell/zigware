//! The `discovery` and `lookup` fuzz targets (commonware `p2p/fuzz/src/lib.rs` and
//! `fuzz_targets/{discovery,lookup}.rs`): a cluster of authenticated peers on the deterministic
//! runtime runs a random sequence of sends, receives, peer-set registrations, and blocks,
//! checking that every delivered message was sent by that sender to that receiver, in order
//! (a message may be dropped, never reordered or invented).
//!
//! `FuzzInput` decodes from an `invariants.minifuzz.Unstructured` exactly as commonware's
//! `Arbitrary` impl does, and both schemes share one harness, as commonware's `NetworkScheme`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const invariants = @import("invariants");
const runtime = @import("runtime");
const stream = @import("stream");
const metrics = runtime.telemetry.metrics;

const p2p = @import("../root.zig");
const discovery = @import("../authenticated/discovery/network.zig");
const discovery_config = @import("../authenticated/discovery/config.zig");
const lookup = @import("../authenticated/lookup/network.zig");
const IoRng = @import("../utils/io_rng.zig").IoRng;
const shuffle = @import("../utils/shuffle.zig").shuffle;
const simulated = @import("simulated.zig");

const minifuzz = invariants.minifuzz;
const Unstructured = minifuzz.Unstructured;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Upgrader = stream.SakeCups(PrivateKey, cryptography.ChaCha20Poly1305);
const Transport = runtime.network.deterministic.Network;
const Message = p2p.Message(PublicKey);

const operations_max = 30;
const peers_max = 8;
const peers_min = 4;
const message_size_max: u32 = 1024 * 1024;
const channel_size = 8; // `Channel::SIZE`: a u64.
const index_max: u8 = 10;
const tracked_peer_sets = 5;
const base_port: u16 = 63000;
const namespace = "fuzz_namespace";

/// Operations on the network (commonware's `NetworkOperation`, `derive(Arbitrary)`).
pub const Operation = union(enum) {
    send_message: struct { from_idx: u8, num_recipients: u8, msg_size: usize },
    receive_messages,
    register_peers: struct { peer_idx: u8, index: u8, peer_set_size: u8 },
    block_peer: struct { peer_idx: u8, target_idx: u8 },

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!Operation {
        // derive(Arbitrary): a u32 scaled into the variant count, then the fields in order.
        const raw: u64 = try u.arbitrary(u32);
        const variants = @typeInfo(Operation).@"union".field_names.len;
        const index = (raw * variants) >> 32;
        assert(index < variants);
        return switch (index) {
            0 => .{ .send_message = try u.arbitrary(@FieldType(Operation, "send_message")) },
            1 => .receive_messages,
            2 => .{ .register_peers = try u.arbitrary(@FieldType(Operation, "register_peers")) },
            3 => .{ .block_peer = try u.arbitrary(@FieldType(Operation, "block_peer")) },
            else => unreachable, // Proof: index < variants == 4.
        };
    }
};

/// commonware's `FuzzInput`: seed, operations, then the peer count.
pub const FuzzInput = struct {
    seed: u64,
    operations: [operations_max]Operation,
    operation_count: usize,
    peers: usize,
    /// Simulated time the cluster runs before the operations; 0 as commonware (`densify`).
    settle_ms: u64 = 0,

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!FuzzInput {
        var input: FuzzInput = .{
            .seed = try u.arbitrary(u64),
            .operations = undefined,
            .operation_count = u.int_in_range(usize, 1, operations_max),
            .peers = undefined,
        };
        for (input.operations[0..input.operation_count]) |*operation| {
            operation.* = try u.arbitrary(Operation);
        }
        input.peers = u.int_in_range(usize, peers_min, peers_max);
        return input;
    }
};

const dense_peers_max = 5;
const dense_message_size_max = 64;
const dense_settle_ms = 60_000;

/// The seeded run's input: commonware's draws send to a cluster that has not connected yet
/// (libFuzzer reaches later operations by coverage), so the seeded run lets the cluster
/// connect for a simulated minute first, keeps four or five peers, and sends short messages.
pub fn densify(input: *FuzzInput) void {
    assert(input.operation_count <= operations_max);
    input.peers = peers_min + input.peers % (dense_peers_max - peers_min + 1);
    input.settle_ms = dense_settle_ms;
    for (input.operations[0..input.operation_count]) |*operation| switch (operation.*) {
        .send_message => |*op| op.msg_size %= dense_message_size_max + 1,
        else => {},
    };
}

fn local_socket(port: u16) codec.SocketAddr {
    return .{ .ip = .{ .v4 = codec.Ipv4.init(127, 0, 0, 1) }, .port = port };
}

fn port_of(id: usize) u16 {
    assert(id < peers_max);
    return base_port + @as(u16, @intCast(id));
}

fn upgrader(signer: PrivateKey) Upgrader {
    return .init(.{
        .signer = signer,
        .synchrony_bound_ms = 5_000,
        .max_handshake_age_ms = 10_000,
        .version = .v1,
    }, .v1);
}

/// The whole cluster: every peer's key, indexed by peer id.
const Topology = struct {
    signers: []const PrivateKey,
    keys: []const PublicKey,

    fn id_of(topology: *const Topology, key: PublicKey) ?usize {
        for (topology.keys, 0..) |candidate, id| {
            if (candidate.eql(key)) return id;
        }
        return null;
    }
};

/// commonware's `Discovery` scheme: peers bootstrap from peer 0 and learn addresses by gossip.
pub const Discovery = struct {
    pub const Net = discovery.Network(Upgrader, Transport);
    pub const scope_name = "fuzzed_discovery_network";
    const Bootstrapper = discovery_config.Bootstrapper(PublicKey);

    pub fn config(
        topology: *const Topology,
        id: usize,
        bootstrap: []const Bootstrapper,
    ) Net.Config {
        const socket = local_socket(port_of(id));
        var result = Net.Config.recommended(.{
            .upgrader = upgrader(topology.signers[id]),
            .namespace = namespace,
            .listen = discovery.to_address(socket),
            .dialable = .{ .socket = socket },
            .bootstrappers = if (id > 0) bootstrap else &.{},
            .max_peers_per_set = topology.keys.len,
            .max_message_size = message_size_max,
            .mailbox_size = 100, // Small mailbox to encourage backpressure.
        });
        result.allow_private_ips = true;
        result.tracked_peer_sets = tracked_peer_sets;
        return result;
    }

    /// Seeds each tracked index with a random three-peer subset.
    pub fn seed_sets(oracle: Net.Oracle, topology: *const Topology, rng: IoRng) void {
        for (0..tracked_peer_sets) |index| {
            var keys: [peers_max]PublicKey = undefined;
            @memcpy(keys[0..topology.keys.len], topology.keys);
            shuffle(PublicKey, keys[0..topology.keys.len], rng);
            track_keys(oracle, index, keys[0..3]);
        }
    }

    pub fn register_peers(
        oracle: Net.Oracle,
        index: u64,
        topology: *const Topology,
        ids: []const usize,
    ) void {
        var keys: [peers_max]PublicKey = undefined;
        for (ids, 0..) |id, at| keys[at] = topology.keys[id];
        track_keys(oracle, index, keys[0..ids.len]);
    }

    fn track_keys(oracle: Net.Oracle, index: u64, keys: []PublicKey) void {
        std.sort.pdq(PublicKey, keys, {}, PublicKey.less_than);
        _ = oracle.track(index, .init_primary(.init(keys)));
    }
};

/// commonware's `Lookup` scheme: every peer set carries each peer's address.
pub const Lookup = struct {
    pub const Net = lookup.Network(Upgrader, Transport);
    pub const scope_name = "fuzzed_lookup_network";
    const Entry = Net.Tracker.PeerMap.Entry;
    const Bootstrapper = void;

    pub fn config(topology: *const Topology, id: usize, _: []const Bootstrapper) Net.Config {
        var result = Net.Config.recommended(.{
            .upgrader = upgrader(topology.signers[id]),
            .namespace = namespace,
            .listen = lookup.to_address(local_socket(port_of(id))),
            .max_peers_per_set = topology.keys.len,
            .max_message_size = message_size_max,
            .mailbox_size = 1_000,
        });
        result.allow_private_ips = true;
        result.tracked_peer_sets = 2 * tracked_peer_sets;
        return result;
    }

    /// Tracks every peer at the first indices, then random three-peer subsets at the next.
    pub fn seed_sets(oracle: Net.Oracle, topology: *const Topology, rng: IoRng) void {
        const n = topology.keys.len;
        var all: [peers_max]usize = undefined;
        for (all[0..n], 0..) |*id, value| id.* = value;
        for (0..tracked_peer_sets) |index| register_peers(oracle, index, topology, all[0..n]);
        for (tracked_peer_sets..2 * tracked_peer_sets) |index| {
            var ids = all;
            shuffle(usize, ids[0..n], rng);
            register_peers(oracle, index, topology, ids[0..3]);
        }
    }

    pub fn register_peers(
        oracle: Net.Oracle,
        index: u64,
        topology: *const Topology,
        ids: []const usize,
    ) void {
        var entries: [peers_max]Entry = undefined;
        for (ids, entries[0..ids.len]) |id, *entry| {
            const address: p2p.Address = .{ .symmetric = local_socket(port_of(id)) };
            entry.* = .{ .key = topology.keys[id], .value = address };
        }
        std.sort.pdq(Entry, entries[0..ids.len], {}, struct {
            fn less(_: void, a: Entry, b: Entry) bool {
                return PublicKey.order(a.key, b.key) == .lt;
            }
        }.less);
        _ = oracle.track(index, .init_primary(.init(entries[0..ids.len])));
    }
};

fn Node(comptime Scheme: type) type {
    return struct {
        network: *Scheme.Net,
        registered: Scheme.Net.Registered,
        task: Io.Future(anyerror!void),

        fn run(network: *Scheme.Net) anyerror!void {
            return network.run();
        }
    };
}

/// Expected messages for one `(to_idx, from_idx)`, oldest first.
const Expected = struct {
    to_idx: usize,
    from_idx: usize,
    queue: std.Deque([]u8) = .empty,
};

fn State(comptime Scheme: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: Io,
        topology: *const Topology,
        nodes: []Node(Scheme),
        expected: std.ArrayList(Expected) = .empty,

        fn deinit(state: *Self) void {
            for (state.expected.items) |*entry| {
                while (entry.queue.popFront()) |message| state.gpa.free(message);
                entry.queue.deinit(state.gpa);
            }
            state.expected.deinit(state.gpa);
        }

        fn rng(state: *const Self) IoRng {
            return .{ .io = state.io };
        }

        fn expected_for(state: *Self, to: usize, from: usize) !*Expected {
            for (state.expected.items) |*entry| {
                if (entry.to_idx == to and entry.from_idx == from) return entry;
            }
            try state.expected.append(state.gpa, .{ .to_idx = to, .from_idx = from });
            return &state.expected.items[state.expected.items.len - 1];
        }

        fn send(state: *Self, op: @FieldType(Operation, "send_message")) !void {
            const n = state.nodes.len;
            const from = op.from_idx % n;
            const size = @min(op.msg_size, message_size_max - channel_size);
            const message = try state.gpa.alloc(u8, size);
            defer state.gpa.free(message);
            state.io.random(message);
            var available: [peers_max]usize = undefined;
            var count: usize = 0;
            for (0..n) |id| if (id != from) {
                available[count] = id;
                count += 1;
            };
            assert(count == n - 1);
            shuffle(usize, available[0..count], state.rng());
            const chosen = std.math.clamp(@as(usize, op.num_recipients), 1, count);
            var keys: [peers_max]PublicKey = undefined;
            for (available[0..chosen], keys[0..chosen]) |id, *key| key.* = state.topology.keys[id];
            const recipients: p2p.Recipients(PublicKey) = if (chosen == count)
                .all
            else if (chosen == 1) .{ .one = keys[0] } else .{ .some = keys[0..chosen] };
            // Always low priority, so each sender-receiver pair delivers in order.
            const sender = &state.nodes[from].registered.sender;
            const accepted = try sender.send(recipients, &.{message}, false);
            defer state.gpa.free(accepted);
            for (accepted) |key| {
                const to = state.topology.id_of(key) orelse continue;
                const entry = try state.expected_for(to, from);
                const copy = try state.gpa.dupe(u8, message);
                errdefer state.gpa.free(copy);
                try entry.queue.pushBack(state.gpa, copy);
            }
        }

        /// Receives at most one message on each receiver with pending messages.
        fn receive(state: *Self) !void {
            var pending: [peers_max]bool = @splat(false);
            for (state.expected.items) |entry| pending[entry.to_idx] = true;
            for (pending[0..state.nodes.len], 0..) |has_pending, to| {
                if (!has_pending) continue;
                const receiver = &state.nodes[to].registered.receiver;
                var message = (try simulated.recv_timeout(state.io, receiver)) orelse continue;
                defer message.deinit();
                try state.check(to, &message);
            }
        }

        /// A delivered message must be queued for its sender and receiver; messages queued
        /// before it were dropped.
        fn check(state: *Self, to: usize, message: *const Message) !void {
            const from = state.topology.id_of(message.peer) orelse return error.UnknownSender;
            const position = for (state.expected.items, 0..) |entry, position| {
                if (entry.to_idx == to and entry.from_idx == from) break position;
            } else return error.ExpectedQueueNotFound;
            const entry = &state.expected.items[position];
            const found = for (0..entry.queue.len) |i| {
                if (std.mem.eql(u8, entry.queue.at(i), message.payload)) break i;
            } else return error.UnexpectedMessage;
            for (0..found + 1) |_| state.gpa.free(entry.queue.popFront().?);
            if (entry.queue.len > 0) return;
            entry.queue.deinit(state.gpa);
            _ = state.expected.orderedRemove(position);
        }

        fn register(state: *Self, op: @FieldType(Operation, "register_peers")) void {
            const n = state.nodes.len;
            const size = std.math.clamp(@as(usize, op.peer_set_size), 1, n);
            var member: [peers_max]bool = @splat(false);
            for (0..size) |_| member[@intCast(state.rng().next_u64() % n)] = true;
            var ids: [peers_max]usize = undefined;
            var count: usize = 0;
            for (member[0..n], 0..) |is_member, id| if (is_member) {
                ids[count] = id;
                count += 1;
            };
            const oracle = state.nodes[op.peer_idx % n].network.oracle();
            Scheme.register_peers(oracle, op.index % index_max, state.topology, ids[0..count]);
        }

        fn block(state: *Self, op: @FieldType(Operation, "block_peer")) void {
            const n = state.nodes.len;
            const target = state.topology.keys[op.target_idx % n];
            _ = state.nodes[op.peer_idx % n].network.oracle().block(target);
        }
    };
}

fn start_nodes(
    comptime Scheme: type,
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    topology: *const Topology,
    nodes: []Node(Scheme),
) !void {
    const gpa = testing.allocator;
    const bootstrap = [_]Scheme.Bootstrapper{if (Scheme == Discovery)
        .{ .peer = topology.keys[0], .ingress = .{ .socket = local_socket(base_port) } }
    else {}};
    for (nodes, 0..) |*node, id| {
        const peer_scope = scope.child("peer").with_attribute("id", id).child(Scheme.scope_name);
        const config = Scheme.config(topology, id, &bootstrap);
        const network = try Scheme.Net.create(gpa, io, transport, peer_scope, config);
        errdefer network.destroy();
        Scheme.seed_sets(network.oracle(), topology, .{ .io = io });
        node.* = .{
            .network = network,
            .registered = try network.register(0, .per_second(100)),
            .task = undefined,
        };
        node.task = try io.concurrent(Node(Scheme).run, .{network});
    }
}

fn stop_nodes(comptime Scheme: type, io: Io, nodes: []Node(Scheme)) void {
    for (nodes) |*node| {
        node.task.cancel(io) catch {};
        node.registered.sender.deinit();
    }
    for (nodes) |*node| {
        // Receivers drain, then report the closed network.
        while (node.registered.receiver.try_recv()) |message| {
            var owned = message;
            owned.deinit();
        } else |_| {}
        node.registered.receiver.deinit();
        node.network.destroy();
    }
}

fn run_cluster(
    comptime Scheme: type,
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    input: *const FuzzInput,
) !void {
    assert(input.peers >= peers_min and input.peers <= peers_max);
    const rng: IoRng = .{ .io = io };
    var signers: [peers_max]PrivateKey = undefined;
    var keys: [peers_max]PublicKey = undefined;
    for (signers[0..input.peers], keys[0..input.peers]) |*signer, *key| {
        signer.* = PrivateKey.from_seed(rng.next_u64());
        key.* = signer.public_key();
    }
    const n = input.peers;
    const topology: Topology = .{ .signers = signers[0..n], .keys = keys[0..n] };
    var nodes: [peers_max]Node(Scheme) = undefined;
    try start_nodes(Scheme, io, transport, scope, &topology, nodes[0..input.peers]);
    defer stop_nodes(Scheme, io, nodes[0..input.peers]);
    if (input.settle_ms > 0) try io.sleep(.fromMilliseconds(@intCast(input.settle_ms)), .awake);
    var state: State(Scheme) = .{
        .gpa = testing.allocator,
        .io = io,
        .topology = &topology,
        .nodes = nodes[0..input.peers],
    };
    defer state.deinit();
    for (input.operations[0..input.operation_count]) |operation| switch (operation) {
        .send_message => |op| try state.send(op),
        .receive_messages => try state.receive(),
        .register_peers => |op| state.register(op),
        .block_peer => |op| state.block(op),
    };
}

/// Runs one fuzz input against `Scheme` on a deterministic runtime seeded with its seed.
pub fn fuzz(comptime Scheme: type, input: *const FuzzInput) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{ .seed = input.seed });
    defer runner.deinit();
    const args = .{ runner.io(), runner.network(), runner.metrics(), input };
    try (try runner.start(Bodies(Scheme).cluster, args));
}

fn Bodies(comptime Scheme: type) type {
    return struct {
        fn cluster(
            io: Io,
            transport: *Transport,
            scope: metrics.Scope,
            input: *const FuzzInput,
        ) !void {
            return run_cluster(Scheme, io, transport, scope, input);
        }

        fn plain(_: void, u: *Unstructured) !void {
            const input = try u.arbitrary(FuzzInput);
            try fuzz(Scheme, &input);
        }

        fn dense(_: void, u: *Unstructured) !void {
            var input = try u.arbitrary(FuzzInput);
            densify(&input);
            try fuzz(Scheme, &input);
        }
    };
}

const search_limit = 8;

test "fuzz discovery network" {
    const body = Bodies(Discovery).dense;
    try (minifuzz.Builder{}).with_search_limit(search_limit).run(testing.allocator, {}, body);
}

test "fuzz lookup network" {
    const body = Bodies(Lookup).dense;
    try (minifuzz.Builder{}).with_search_limit(search_limit).run(testing.allocator, {}, body);
}

test "fuzz discovery network (coverage-guided)" {
    const math = @import("math");
    try testing.fuzz({}, math.testing.smith_body(void, Bodies(Discovery).plain), .{});
}

test "fuzz lookup network (coverage-guided)" {
    const math = @import("math");
    try testing.fuzz({}, math.testing.smith_body(void, Bodies(Lookup).plain), .{});
}
