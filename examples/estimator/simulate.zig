//! One simulation per proposer on the deterministic runtime and p2p's simulated network
//! (commonware `examples/estimator/src/main.rs`, `run_single_simulation` through
//! `process_simulation_results`).
//!
//! Every peer is a task that walks the task's commands: it sends on `propose`, `broadcast`,
//! and `reply`, and blocks on `wait`/`collect` until enough distinct peers have sent the
//! message id, recording the virtual time each gate opened. Links carry the region-to-region
//! latency and jitter, and per-peer bandwidth limits come from the distribution.
//!
//! Messages are `Vec<u8>` encoded with codec (a varint length, then the bytes) as commonware's
//! wrapped sender does, so bandwidth sees the same sizes. A peer that finishes stops reading
//! its channel instead of draining it until shutdown; nothing it would read changes a result.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const dsl = lib.dsl;
const rust = @import("rust.zig");

const p2p = zigware.p2p;
const codec = zigware.codec;
const ed25519 = zigware.cryptography.ed25519;
const Duration = zigware.utils.Duration;

pub const Key = ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Tracked = p2p.TrackedPeers(Key);

/// The channel every message uses.
const default_channel: p2p.Channel = 0;
/// Rate limit high enough to not interfere with normal operation.
const default_quota = p2p.Quota.per_second(std.math.maxInt(u32));
/// Virtual time to let messages settle after every peer finishes.
const settle_ns: u64 = 10 * std.time.ns_per_s;

/// Latencies observed for one simulation: per command, per region (distribution order), the
/// milliseconds at which each peer passed it, and the proposer's own.
pub const Steps = struct {
    commands: usize,
    regions: usize,
    all: []std.ArrayList(f64),
    proposer: []?f64,

    pub fn init(gpa: Allocator, commands: usize, regions: usize) Allocator.Error!Steps {
        const all = try gpa.alloc(std.ArrayList(f64), commands * regions);
        errdefer gpa.free(all);
        @memset(all, .empty);
        const proposer = try gpa.alloc(?f64, commands);
        @memset(proposer, null);
        return .{ .commands = commands, .regions = regions, .all = all, .proposer = proposer };
    }

    pub fn deinit(steps: *Steps, gpa: Allocator) void {
        for (steps.all) |*list| list.deinit(gpa);
        gpa.free(steps.all);
        gpa.free(steps.proposer);
        steps.* = undefined;
    }

    pub fn at(steps: *const Steps, command: usize, region: usize) *std.ArrayList(f64) {
        assert(command < steps.commands and region < steps.regions);
        return &steps.all[command * steps.regions + region];
    }

    /// Whether any peer passed `command` (a key of commonware's `steps.all`).
    pub fn observed(steps: *const Steps, command: usize) bool {
        for (0..steps.regions) |region| {
            if (steps.at(command, region).items.len > 0) return true;
        }
        return false;
    }
};

pub const Simulation = struct {
    proposer: u64,
    proposer_region: []const u8,
    steps: Steps,
};

pub const Input = struct {
    distribution: *const lib.Distribution,
    task: *const lib.Task,
    latencies: *const lib.Latencies,
};

pub const Error = error{
    /// The runtime ran out of work before every peer finished (commonware "runtime stalled").
    Stalled,
    /// A region of the distribution has no latency data for another one.
    MissingLatency,
} || Allocator.Error || Io.Cancelable;

/// A command passed by a peer: its index and the virtual time since the peer started.
const Completion = struct { command: usize, elapsed_ns: u64 };

const Job = struct {
    gpa: Allocator,
    io: Io,
    task: *const lib.Task,
    peers: u64,
    index: usize,
    proposer: usize,
    keys: []const Key,
    /// `keys` in ascending order, and the index in `keys` of each.
    sorted: []const Key,
    order: []const u32,
    sender: Net.Sender,
    receiver: Net.Receiver,
    completions: std.ArrayList(Completion) = .empty,
    failure: ?anyerror = null,
};

/// Runs the task with `proposer` proposing, on a deterministic runtime seeded with its index.
pub fn run_single_simulation(gpa: Allocator, proposer: u64, input: Input) Error!Simulation {
    const peers = lib.count_peers(input.distribution) catch unreachable; // Checked by main.
    assert(proposer < peers);
    var runner = zigware.runtime.deterministic.Runner.init(gpa, .{
        .seed = proposer,
        .cycle_ns = std.time.ns_per_us,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Stalled, error.Timeout => unreachable, // `init` only allocates.
    };
    defer runner.deinit();
    const regions = input.distribution.entries.items.len;
    var steps = try Steps.init(gpa, input.task.commands.len, regions);
    errdefer steps.deinit(gpa);
    const args = .{ gpa, runner.io(), proposer, input, &steps };
    const outcome = runner.start(simulate, args) catch |err|
        switch (err) {
            error.Stalled => return error.Stalled,
            error.Timeout => unreachable, // No timeout is configured.
            error.OutOfMemory => return error.OutOfMemory,
        };
    outcome catch |err| switch (err) {
        // The root is canceled only while the runtime shuts down after a stall.
        error.Canceled => return error.Stalled,
        else => |other| return other,
    };
    return .{
        .proposer = proposer,
        .proposer_region = lib.calculate_proposer_region(proposer, input.distribution),
        .steps = steps,
    };
}

/// The root task: build the network, run every peer, and collect their completions.
fn simulate(gpa: Allocator, io: Io, proposer: u64, input: Input, steps: *Steps) Error!void {
    const peers: usize = @intCast(lib.count_peers(input.distribution) catch unreachable);
    const keys = try gpa.alloc(Key, peers);
    defer gpa.free(keys);
    const region_of = try gpa.alloc(u32, peers);
    defer gpa.free(region_of);
    var next: usize = 0;
    for (input.distribution.entries.items, 0..) |entry, region| {
        for (0..entry.config.count) |_| {
            keys[next] = ed25519.PrivateKey.from_seed(next).public_key();
            region_of[next] = @intCast(region);
            next += 1;
        }
    }
    assert(next == peers);
    const order = try gpa.alloc(u32, peers);
    defer gpa.free(order);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    std.sort.pdq(u32, order, keys, struct {
        fn less(context: []const Key, a: u32, b: u32) bool {
            return Key.order(context[a], context[b]) == .lt;
        }
    }.less);
    const sorted = try gpa.alloc(Key, peers);
    defer gpa.free(sorted);
    for (sorted, order) |*key, index| key.* = keys[index];

    const tracked: Tracked = .init_primary(.init(sorted));
    const network = try Net.init_with_peers(gpa, io, network_config(peers), tracked);
    defer network.deinit();
    var run = io.concurrent(Net.run, .{network}) catch return error.OutOfMemory;
    defer {
        network.close();
        run.await(io) catch {};
    }
    const jobs = try gpa.alloc(Job, peers);
    defer gpa.free(jobs);
    var registered: usize = 0;
    defer for (jobs[0..registered]) |*job| {
        job.completions.deinit(gpa);
        job.sender.deinit();
        job.receiver.deinit();
    };
    const oracle = network.oracle();
    for (jobs, 0..) |*job, index| {
        const channel = oracle.control(keys[index]).register(default_channel, default_quota) catch
            return error.OutOfMemory;
        job.* = .{
            .gpa = gpa,
            .io = io,
            .task = input.task,
            .peers = peers,
            .index = index,
            .proposer = @intCast(proposer),
            .keys = keys,
            .sorted = sorted,
            .order = order,
            .sender = channel.sender,
            .receiver = channel.receiver,
        };
        registered += 1;
    }
    try setup_network(oracle, keys, region_of, input);
    try run_jobs(io, jobs);
    try io.sleep(.fromNanoseconds(settle_ns), .awake);
    try collect(gpa, jobs, region_of, @intCast(proposer), steps);
}

fn network_config(peers: usize) p2p.simulated.network.Config {
    return .{
        .max_size = p2p.simulated.network.max_size_limit,
        .max_peers_per_set = peers,
        .disconnect_on_block = true,
        .tracked_peer_sets = 1,
    };
}

/// Bandwidth limits per peer, then a link for every ordered pair of distinct peers.
fn setup_network(
    oracle: Net.Oracle,
    keys: []const Key,
    region_of: []const u32,
    input: Input,
) Error!void {
    const regions = input.distribution.entries.items;
    for (keys, region_of) |key, region| {
        const config = regions[region].config;
        oracle.limit_bandwidth(key, config.egress_cap, config.ingress_cap) catch
            return error.OutOfMemory;
    }
    for (keys, region_of, 0..) |key, region, i| {
        for (keys, region_of, 0..) |other, other_region, j| {
            if (i == j) continue;
            const from = regions[region].region;
            const to = regions[other_region].region;
            const behavior = input.latencies.get(from, to) orelse return error.MissingLatency;
            const link: p2p.simulated.network.Link = .{
                .latency = Duration.from_micros(rust.f64_to_u64(behavior.latency_ms * 1000.0)),
                .jitter = Duration.from_micros(rust.f64_to_u64(behavior.jitter_ms * 1000.0)),
                .success_rate = 1.0,
            };
            oracle.add_link(key, other, link) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => unreachable, // Distinct, new, and the network is open.
            };
        }
    }
}

fn run_jobs(io: Io, jobs: []Job) Error!void {
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (jobs) |*job| group.concurrent(io, peer_job, .{job}) catch return error.OutOfMemory;
    try group.await(io);
    for (jobs) |job| {
        const failure = job.failure orelse continue;
        if (failure == error.OutOfMemory) return error.OutOfMemory;
        std.debug.panic("peer {d} failed: {t}", .{ job.index, failure });
    }
}

/// Moves completions into `steps` in peer order (commonware `process_simulation_results`).
fn collect(
    gpa: Allocator,
    jobs: []const Job,
    region_of: []const u32,
    proposer: usize,
    steps: *Steps,
) Allocator.Error!void {
    for (jobs, region_of) |job, region| {
        for (job.completions.items) |completion| {
            const milliseconds: f64 = @floatFromInt(completion.elapsed_ns / std.time.ns_per_ms);
            try steps.at(completion.command, region).append(gpa, milliseconds);
        }
    }
    for (jobs[proposer].completions.items) |completion| {
        const milliseconds: f64 = @floatFromInt(completion.elapsed_ns / std.time.ns_per_ms);
        steps.proposer[completion.command] = milliseconds;
    }
}

fn peer_job(job: *Job) Io.Cancelable!void {
    run_peer(job) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => job.failure = err,
    };
}

fn now_ns(io: Io) u64 {
    return @intCast(Io.Clock.real.now(io).nanoseconds);
}

fn run_peer(job: *Job) !void {
    const gpa = job.gpa;
    const task = job.task;
    var received = try dsl.Received.init(gpa, task.ids, job.peers);
    defer received.deinit(gpa);
    const scratch = try gpa.alloc(bool, 2 * task.leaves_max);
    defer gpa.free(scratch);
    try job.completions.ensureTotalCapacity(gpa, task.commands.len);
    const start_ns = now_ns(job.io);
    var index: usize = 0;
    // Each pass but the last reads one message, and each peer sends each id at most once.
    const passes_max = job.peers * (task.commands.len + 1) + 1;
    for (0..passes_max) |_| {
        while (index < task.commands.len) {
            const command = task.commands[index];
            if (!try process_command(job, command, index, &received, scratch, start_ns)) break;
            index += 1;
        }
        if (index >= task.commands.len) return;
        var message = try job.receiver.recv();
        defer message.deinit();
        received.insert(try extract_id(gpa, message.payload), peer_index(job, message.peer));
    }
    unreachable; // See `passes_max`.
}

/// The id at the front of a codec-encoded `Vec<u8>` message.
fn extract_id(gpa: Allocator, payload: []const u8) !u32 {
    const bytes = try codec.decode_range([]const u8, gpa, payload, .full());
    defer codec.free([]const u8, gpa, bytes);
    assert(bytes.len >= 4); // Messages are at least four bytes by construction.
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn sleep(io: Io, duration: Duration) Io.Cancelable!void {
    const nanos = duration.as_nanos();
    assert(nanos <= std.math.maxInt(i96));
    try io.sleep(.fromNanoseconds(@intCast(nanos)), .awake);
}

/// Runs one command; returns whether the peer advances past it (commonware
/// `process_command`). Gates sleep their message delay before checking and their completion
/// delay after passing; a compound command sleeps each gate leaf's message delay in turn.
fn process_command(
    job: *Job,
    command: dsl.Command,
    command_index: usize,
    received: *dsl.Received,
    scratch: []bool,
    start_ns: u64,
) !bool {
    const is_proposer = job.index == job.proposer;
    const leaf = command.single() orelse {
        var leaves: usize = 0;
        for (command.items) |item| {
            if (item != .leaf) continue;
            if (item.leaf.gate()) |gate| if (gate.delay) |delay| try sleep(job.io, delay.message);
            scratch[leaves] = dsl.can_leaf_advance(item.leaf, is_proposer, job.peers, received);
            leaves += 1;
        }
        const results = scratch[0..leaves];
        const passed = dsl.combine(command.items, results, scratch[leaves .. 2 * leaves]);
        if (passed) complete(job, command_index, start_ns);
        return passed;
    };
    switch (leaf) {
        .propose => |send| if (is_proposer) {
            try send_message(job, .all, send);
            received.insert(send.id, job.index);
        },
        .broadcast => |send| {
            try send_message(job, .all, send);
            received.insert(send.id, job.index);
        },
        .reply => |send| if (is_proposer) {
            received.insert(send.id, job.index);
        } else {
            try send_message(job, .{ .one = job.keys[job.proposer] }, send);
        },
        .collect, .wait => |gate| {
            if (leaf == .collect and !is_proposer) return true;
            const count = received.count(gate.id);
            const required = dsl.calculate_threshold(gate.threshold, job.peers);
            if (gate.delay) |delay| try sleep(job.io, delay.message);
            if (count < required) return false;
            complete(job, command_index, start_ns);
            if (gate.delay) |delay| try sleep(job.io, delay.completion);
        },
    }
    return true;
}

fn complete(job: *Job, command_index: usize, start_ns: u64) void {
    const elapsed_ns = now_ns(job.io) - start_ns;
    job.completions.appendAssumeCapacity(.{ .command = command_index, .elapsed_ns = elapsed_ns });
}

/// Sends the id as a big-endian `u32` padded with zeros to `size`, encoded as `Vec<u8>`.
fn send_message(job: *Job, recipients: p2p.Recipients(Key), message: dsl.Send) !void {
    const size: usize = @intCast(@max(message.size orelse 4, 4));
    var prefix: [codec.varint.max_size(u32)]u8 = undefined;
    var prefix_writer = codec.Writer.init(&prefix);
    codec.write(usize, size, &prefix_writer);
    const body = try job.gpa.alloc(u8, size);
    defer job.gpa.free(body);
    @memset(body, 0);
    std.mem.writeInt(u32, body[0..4], message.id, .big);
    const sent = try job.sender.send(recipients, &.{ prefix_writer.written(), body }, true);
    job.gpa.free(sent);
}

fn peer_index(job: *const Job, key: Key) usize {
    const position = std.sort.binarySearch(Key, job.sorted, key, struct {
        fn compare(context: Key, item: Key) std.math.Order {
            return Key.order(context, item);
        }
    }.compare) orelse unreachable; // Messages come only from registered peers.
    const index = job.order[position];
    assert(Key.order(job.keys[index], key) == .eq);
    return index;
}
