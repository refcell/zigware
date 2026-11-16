//! Maintains requests for data from other peers (commonware `resolver/src/p2p/fetcher.rs`).
//!
//! Fetches are either active (sent to a peer, waiting for a response until the request
//! deadline) or pending (waiting to be sent, now or after the retry delay). An unresolved
//! attempt returns to the pending queue after the retry delay.
//!
//! # Peer selection
//!
//! A fetch without targets may use any peer of the latest tracked peer set. A fetch with
//! targets may use only those targets in that set; a target outside it is skipped until a later
//! set includes it. The first attempt samples in proportion to throughput scores. After `r`
//! unresolved requests, sampling uses those weights with probability `4 / (r + 4)` and is
//! uniform otherwise. When a send fails or the selected peer is rate-limited, the fetcher tries
//! another eligible peer until the request is sent or every eligible peer has been tried. Local
//! send failures and rate limits do not change scores or advance the retry count.
//!
//! # Targets
//!
//! Targets are "the only peers who might eventually have the data": there is no fallback to
//! other peers. They persist through transient failures (timeout, "no data", send failure) and
//! are cleared when the fetch ends. A blocked target is skipped until the network unblocks it.
//!
//! zigware: peers and keys are plain values ordered by `codec.order` (sorted arrays stand in
//! for commonware's hash maps), the sender is any `p2p` limited sender (`check(recipients)`
//! returning a checked sender with `send(parts, priority)`), and randomness and time come
//! from `std.Io`, so runs are deterministic under the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const p2p = @import("p2p");
const metrics = @import("runtime").telemetry.metrics;
const wire = @import("wire.zig");
const Score = @import("score.zig").Score;

const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const WeightedIndex = utils.sampling.WeightedIndex;
const WithoutReplacement = utils.sampling.WithoutReplacement;
const PrioritySet = utils.PrioritySet;
const Status = metrics.status.Status;

/// Unique identifier for a request. The first send draws a random starting ID; each later
/// send increments it, wrapping to zero after `u64` max, so a response to a request sent
/// before a restart is unlikely to match a new request.
pub const ID = u64;

/// Configuration for the fetcher.
pub fn Config(comptime P: type) type {
    return struct {
        /// Local identity of the participant (if any).
        me: ?P,
        /// Maximum wait for a response (non-zero).
        fetch_timeout: Duration,
        /// Delay before retrying an unresolved fetch or a failed send. Zero permits immediate
        /// retries, subject to the sender's rate limit.
        retry_delay: Duration,
        /// Whether requests are sent with priority over other network messages.
        priority_requests: bool,
    };
}

/// The order in which pending keys are tried: fresh before retries, then deadline, then
/// arrival.
pub const Order = struct {
    /// Whether the key was already attempted.
    retry: bool,
    /// The earliest time the key may be attempted.
    deadline: SystemTime,
    /// The key's arrival position.
    sequence: u64,

    pub fn order(a: Order, b: Order) std.math.Order {
        const retry = std.math.order(@intFromBool(a.retry), @intFromBool(b.retry));
        if (retry != .eq) return retry;
        const deadline = a.deadline.order(b.deadline);
        if (deadline != .eq) return deadline;
        return std.math.order(a.sequence, b.sequence);
    }
};

/// Draws from `std.Io`'s randomness (the deterministic runtime's seeded RNG).
pub const IoRng = struct {
    io: Io,

    pub fn next_u64(rng: IoRng) u64 {
        var bytes: [8]u8 = undefined;
        rng.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    pub fn next_u32(rng: IoRng) u32 {
        var bytes: [4]u8 = undefined;
        rng.io.random(&bytes);
        return std.mem.readInt(u32, &bytes, .little);
    }

    pub fn fill_bytes(rng: IoRng, dest: []u8) void {
        rng.io.random(dest);
    }
};

/// The current wall-clock time from `io`.
pub fn current(io: Io) SystemTime {
    return SystemTime.from_timestamp(Io.Clock.real.now(io));
}

/// `later - earlier`, or zero when `later` precedes `earlier` (Rust
/// `duration_since(..).unwrap_or_default()`).
pub fn duration_since(later: SystemTime, earlier: SystemTime) Duration {
    if (later.nanos_since_epoch <= earlier.nanos_since_epoch) return Duration.zero;
    const nanos = later.nanos_since_epoch - earlier.nanos_since_epoch;
    assert(nanos > 0);
    return Duration.from_nanos_saturating(@intCast(nanos));
}

/// Rust `Duration::as_secs_f64`.
pub fn as_secs_f64(duration: Duration) f64 {
    const secs: f64 = @floatFromInt(duration.secs);
    const nanos: f64 = @floatFromInt(duration.nanos);
    return secs + nanos / @as(f64, @floatFromInt(utils.time.NANOS_PER_SEC));
}

/// `time + delta`, panicking on overflow like Rust's `SystemTime + Duration`.
fn add_time(time: SystemTime, delta: Duration) SystemTime {
    return time.checked_add(delta) orelse @panic("time overflowed");
}

fn min_time(a: SystemTime, b: SystemTime) SystemTime {
    return if (a.order(b) == .gt) b else a;
}

/// An ordered map over a sorted array, keyed by `codec.order` (Rust `HashMap` for the
/// fetcher's per-key state, which is bounded by its in-flight keys).
fn KeyMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Entry = struct { key: K, value: V };

        entries: std.ArrayList(Entry) = .empty,

        pub fn deinit(map: *Self, gpa: Allocator) void {
            map.entries.deinit(gpa);
            map.* = undefined;
        }

        pub fn get(map: *const Self, key: K) ?*V {
            const found = map.search(key);
            if (!found.found) return null;
            return &map.entries.items[found.index].value;
        }

        pub fn get_or_put(map: *Self, gpa: Allocator, key: K, default: V) Allocator.Error!*V {
            const found = map.search(key);
            if (!found.found) {
                try map.entries.insert(gpa, found.index, .{ .key = key, .value = default });
            }
            assert(codec.order(K, map.entries.items[found.index].key, key) == .eq);
            return &map.entries.items[found.index].value;
        }

        pub fn remove(map: *Self, key: K) ?V {
            const found = map.search(key);
            if (!found.found) return null;
            return map.entries.orderedRemove(found.index).value;
        }

        fn search(map: *const Self, key: K) struct { index: usize, found: bool } {
            const index = std.sort.lowerBound(Entry, map.entries.items, key, compare);
            const found = index < map.entries.items.len and
                codec.order(K, map.entries.items[index].key, key) == .eq;
            return .{ .index = index, .found = found };
        }

        fn compare(key: K, entry: Entry) std.math.Order {
            return codec.order(K, key, entry.key);
        }
    };
}

/// Inserts `item` into the sorted, duplicate-free `list` unless present.
fn insert_sorted(comptime T: type, gpa: Allocator, list: *std.ArrayList(T), item: T) !void {
    const index = std.sort.lowerBound(T, list.items, item, codec_order(T));
    if (index < list.items.len and codec.order(T, list.items[index], item) == .eq) return;
    try list.insert(gpa, index, item);
    assert(codec.order(T, list.items[index], item) == .eq);
}

fn contains_sorted(comptime T: type, list: []const T, item: T) bool {
    const index = std.sort.lowerBound(T, list, item, codec_order(T));
    return index < list.len and codec.order(T, list[index], item) == .eq;
}

fn codec_order(comptime T: type) fn (T, T) std.math.Order {
    return struct {
        fn compare(a: T, b: T) std.math.Order {
            return codec.order(T, a, b);
        }
    }.compare;
}

fn less_than(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn less(_: void, a: T, b: T) bool {
            return codec.order(T, a, b) == .lt;
        }
    }.less;
}

/// Sorted, duplicate-free copy of `items`, owned by the caller.
fn sorted_unique(comptime T: type, gpa: Allocator, items: []const T) ![]T {
    const copy = try gpa.dupe(T, items);
    std.mem.sort(T, copy, {}, less_than(T));
    var length: usize = 0;
    for (copy) |item| {
        if (length > 0 and codec.order(T, copy[length - 1], item) == .eq) continue;
        copy[length] = item;
        length += 1;
    }
    assert(length <= items.len);
    if (length == copy.len) return copy;
    const shrunk = try gpa.realloc(copy, length);
    return shrunk;
}

/// A send loop's remaining candidates, with temporary exclusions owned by the sampler.
const Selection = struct {
    /// Participant index for each target-local position, or null for the shared index.
    peers: ?[]usize,
    /// Draws that cannot repeat a peer within this selection.
    draws: WithoutReplacement,

    fn deinit(selection: *Selection, gpa: Allocator) void {
        selection.draws.deinit();
        if (selection.peers) |peers| gpa.free(peers);
        selection.* = undefined;
    }

    /// Draws an eligible participant using the retry mixture, without repeating a draw.
    fn next(selection: *Selection, rng: IoRng, retries: u32) Allocator.Error!?usize {
        if (selection.draws.is_empty()) return null;
        // After `r` unresolved requests, each remaining peer has probability
        // 4 * w / ((r + 4) * sum(w)) + r / ((r + 4) * eligible_peers).
        const mixture = utils.rng.range_less_than(rng, u64, 0, @as(u64, retries) + 4);
        const drawn = if (mixture < 4)
            try selection.draws.sample(rng)
        else
            try selection.draws.sample_uniform(rng);
        const index = drawn orelse return null;
        const peers = selection.peers orelse return index;
        assert(index < peers.len);
        return peers[index];
    }
};

pub fn Fetcher(comptime P: type, comptime Key: type) type {
    comptime assert(!codec.owns_memory(Key));
    comptime assert(!codec.owns_memory(P));
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Message = wire.Message(Key);

        /// Throughput score of a peer of the latest tracked set.
        pub const Participant = struct { peer: P, score: Score };
        /// An active request that has been sent to a peer.
        pub const ActiveRequest = struct { key: Key, peer: P, start: SystemTime };
        /// The `peer_performance` label.
        pub const PeerLabel = struct { peer: P };
        const Performance = metrics.Registered(metrics.raw.Family(PeerLabel, metrics.raw.Gauge));

        /// A request that was sent during a `fetch` scan.
        const Sent = struct { key: Key, id: ID, peer: P, start: SystemTime };
        /// When an unsuccessful `fetch` scan can try again.
        const Scan = struct {
            next_deadline: SystemTime,
            earliest_rate_limit: ?SystemTime = null,
            found_eligible_peers: bool = false,
        };
        /// The eligible pool for a key, either shared participants or a target subset.
        const Candidates = union(enum) {
            all,
            /// An index over the eligible targets listed in `peers`, in the same order.
            targets: struct { peers: []usize, weights: WeightedIndex },
        };
        const Found = struct { candidates: Candidates, retries: u32 };

        gpa: Allocator,
        io: Io,

        /// Local identity (excluded from requests).
        me: ?P,
        /// Peers the network currently blocks (sorted), replaced wholesale on every update.
        blocked: std.ArrayList(P) = .empty,
        /// Peers of the latest tracked peer set and their scores, in public-key order.
        participants: std.ArrayList(Participant) = .empty,
        /// Sampling weights of `participants`; local and blocked peers weigh zero.
        weights: WeightedIndex = .empty,

        /// Next request ID, or null until the first send attempt draws a random one.
        request_id: ?ID = null,
        /// Active requests ordered by deadline.
        active: PrioritySet(ID, SystemTime) = .empty,
        /// Request data for active requests.
        requests: std.AutoArrayHashMapUnmanaged(ID, ActiveRequest) = .empty,

        fetch_timeout: Duration,
        /// Keys waiting to be sent, in `Order`.
        pending: PrioritySet(Key, Order) = .empty,
        /// Next sequence number for pending requests.
        pending_sequence: u64 = 0,
        /// When no peer could take a request, the next time to try.
        waiter: ?SystemTime = null,
        retry_delay: Duration,
        priority_requests: bool,

        /// Per-key target peers (sorted), restricting which peers are used to fetch each key.
        targets: KeyMap(Key, std.ArrayList(P)) = .{},
        /// Dispatched requests that left each key unresolved, saturating at `u32` max.
        retries: KeyMap(Key, u32) = .{},

        /// Sampling weight from the throughput score of each peer in the latest set.
        performance: Performance,
        /// Request creation attempts (success when eligible peers exist, dropped otherwise).
        requests_created: metrics.status.Counter,
        /// Individual network requests sent to peers.
        requests_sent: metrics.status.Counter,
        /// Number and duration of useful responses.
        resolves: metrics.Histogram,

        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            config: Config(P),
        ) Allocator.Error!Self {
            assert(!config.fetch_timeout.is_zero());
            var performance = try scope.family(
                PeerLabel,
                metrics.raw.Gauge,
                "peer_performance",
                "Per-peer throughput score expressed as a sampling weight",
            );
            errdefer performance.deinit();
            var requests_created = try metrics.status.Counter.register(
                scope,
                "requests_created",
                "Status of request creation attempts",
            );
            errdefer requests_created.deinit();
            var requests_sent = try metrics.status.Counter.register(
                scope,
                "requests_sent",
                "Status of individual network requests sent to peers",
            );
            errdefer requests_sent.deinit();
            const resolves = try scope.histogram(
                "resolves",
                "Number and duration of useful responses",
                &metrics.Buckets.network,
            );
            return .{
                .gpa = gpa,
                .io = io,
                .me = config.me,
                .fetch_timeout = config.fetch_timeout,
                .retry_delay = config.retry_delay,
                .priority_requests = config.priority_requests,
                .performance = performance,
                .requests_created = requests_created,
                .requests_sent = requests_sent,
                .resolves = resolves,
            };
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.blocked.deinit(gpa);
            self.participants.deinit(gpa);
            self.weights.deinit(gpa);
            self.active.deinit(gpa);
            self.requests.deinit(gpa);
            self.pending.deinit(gpa);
            for (self.targets.entries.items) |*entry| entry.value.deinit(gpa);
            self.targets.deinit(gpa);
            self.retries.deinit(gpa);
            self.performance.deinit();
            self.requests_created.deinit();
            self.requests_sent.deinit();
            self.resolves.deinit();
            self.* = undefined;
        }

        fn now(self: *const Self) SystemTime {
            return current(self.io);
        }

        fn is_me(self: *const Self, peer: P) bool {
            const me = self.me orelse return false;
            return codec.order(P, me, peer) == .eq;
        }

        /// The participant index of `peer`, if it is in the latest tracked set.
        pub fn index(self: *const Self, peer: P) ?usize {
            const items = self.participants.items;
            const position = std.sort.lowerBound(Participant, items, peer, compare_participant);
            if (position == items.len) return null;
            if (codec.order(P, items[position].peer, peer) != .eq) return null;
            return position;
        }

        fn compare_participant(peer: P, participant: Participant) std.math.Order {
            return codec.order(P, peer, participant.peer);
        }

        /// Records useful bytes and their charged duration. Failures contribute zero bytes.
        pub fn update_performance(
            self: *Self,
            peer: P,
            elapsed: Duration,
            bytes: u64,
        ) Allocator.Error!void {
            const position = self.index(peer) orelse return;
            const participant = &self.participants.items[position];
            participant.score.record(elapsed, bytes);
            const next_weight = participant.score.weight();
            assert(next_weight > 0);
            // A score change must not make a local or blocked peer selectable.
            if (self.weights.weight(position) != 0) _ = self.weights.set(position, next_weight);
            const gauge = try self.performance.metric().get_or_create(.{ .peer = peer });
            _ = gauge.try_set(next_weight) catch {};
        }

        /// Participant indices of eligible `targets` (sorted), in public-key order.
        fn eligible_subset(self: *const Self, targets: []const P) Allocator.Error![]usize {
            var subset: std.ArrayList(usize) = .empty;
            errdefer subset.deinit(self.gpa);
            var target: usize = 0;
            for (self.participants.items, 0..) |participant, position| {
                while (target < targets.len and
                    codec.order(P, targets[target], participant.peer) == .lt) target += 1;
                if (target == targets.len) break;
                if (codec.order(P, targets[target], participant.peer) != .eq) continue;
                if (self.weights.weight(position) == 0) continue;
                try subset.append(self.gpa, position);
            }
            assert(subset.items.len <= targets.len);
            return subset.toOwnedSlice(self.gpa);
        }

        /// The key's eligible pool and retry count, or null when no peer can be tried. A
        /// target pool is owned by the caller until a selection consumes it.
        pub fn candidates(self: *const Self, key: Key) Allocator.Error!?Found {
            const retries = if (self.retries.get(key)) |count| count.* else 0;
            const targets = self.targets.get(key) orelse {
                // Eligible peers always have positive weight, so a zero total means the set
                // is empty or holds only self and blocked peers.
                if (self.weights.total() == 0) return null;
                return .{ .candidates = .all, .retries = retries };
            };
            const peers = try self.eligible_subset(targets.items);
            if (peers.len == 0) {
                self.gpa.free(peers);
                return null;
            }
            errdefer self.gpa.free(peers);
            // Sample targets from their own index so weighted and uniform draws both stay
            // within the target set and leave the shared index unchanged.
            const target_weights = try self.gpa.alloc(u64, peers.len);
            defer self.gpa.free(target_weights);
            for (peers, target_weights) |position, *weight| {
                weight.* = self.weights.weight(position);
                assert(weight.* > 0);
            }
            const weights = try WeightedIndex.init(self.gpa, target_weights);
            return .{
                .candidates = .{ .targets = .{ .peers = peers, .weights = weights } },
                .retries = retries,
            };
        }

        /// Starts one send loop, borrowing the shared index or consuming the target index.
        fn select(self: *Self, candidates_found: Candidates) Selection {
            return switch (candidates_found) {
                .all => .{ .peers = null, .draws = self.weights.without_replacement(self.gpa) },
                .targets => |targets| .{
                    .peers = targets.peers,
                    .draws = targets.weights.into_without_replacement(self.gpa),
                },
            };
        }

        /// Every eligible peer for `key` in selection order (commonware's test-only
        /// `get_eligible_peers`). Caller owns the slice.
        pub fn eligible_peers(self: *Self, key: Key) Allocator.Error![]P {
            var peers: std.ArrayList(P) = .empty;
            errdefer peers.deinit(self.gpa);
            const found = try self.candidates(key) orelse return peers.toOwnedSlice(self.gpa);
            var selection = self.select(found.candidates);
            defer selection.deinit(self.gpa);
            const rng: IoRng = .{ .io = self.io };
            while (try selection.next(rng, found.retries)) |position| {
                try peers.append(self.gpa, self.participants.items[position].peer);
            }
            assert(peers.items.len <= self.participants.items.len);
            return peers.toOwnedSlice(self.gpa);
        }

        /// Attempts to send a fetch request for a pending key.
        ///
        /// Tries due keys in priority order until a send succeeds. For each key, tries eligible
        /// peers in selection order. On success, the key moves from pending to active. On
        /// failure, the key stays pending and the waiter is set: the earliest peer rate-limit
        /// expiry, or `retry_delay` after failed sends, or an earlier pending deadline. With no
        /// eligible peers or future deadlines, it waits for an external change.
        ///
        /// `sender` is a pointer to a `p2p` limited sender.
        pub fn fetch(self: *Self, sender: anytype) !void {
            self.waiter = null;
            const scan_start = self.now();
            var scan: Scan = .{ .next_deadline = SystemTime.limit() };
            var sent: ?Sent = null;
            // Sending never changes `pending`, so its entries stay valid during the scan.
            for (self.pending.items()) |entry| {
                // Each key waits for its own deadline. Keep scanning: fresh keys precede
                // retries, so later keys may already be due.
                if (entry.priority.deadline.order(scan_start) == .gt) {
                    scan.next_deadline = min_time(scan.next_deadline, entry.priority.deadline);
                    continue;
                }
                sent = try self.try_key(sender, entry.item, &scan);
                if (sent != null) break;
            }
            if (sent) |request| {
                const deadline = add_time(request.start, self.fetch_timeout);
                try self.requests.ensureUnusedCapacity(self.gpa, 1);
                try self.active.put(self.gpa, request.id, deadline);
                self.requests.putAssumeCapacity(request.id, .{
                    .key = request.key,
                    .peer = request.peer,
                    .start = request.start,
                });
                assert(self.pending.remove(request.key));
                return;
            }
            // Keep future keys reachable even when every due key is unavailable.
            if (scan.earliest_rate_limit) |rate_limit_time| {
                scan.next_deadline = min_time(scan.next_deadline, rate_limit_time);
            } else if (scan.found_eligible_peers) {
                const retry_at = add_time(self.now(), self.retry_delay);
                scan.next_deadline = min_time(scan.next_deadline, retry_at);
            }
            self.waiter = scan.next_deadline;
        }

        /// Tries every eligible peer for `key` until one accepts the request.
        fn try_key(self: *Self, sender: anytype, key: Key, scan: *Scan) !?Sent {
            const found = try self.candidates(key) orelse {
                try self.requests_created.inc(.dropped);
                return null;
            };
            try self.requests_created.inc(.success);
            scan.found_eligible_peers = true;
            var selection = self.select(found.candidates);
            defer selection.deinit(self.gpa);
            const rng: IoRng = .{ .io = self.io };
            while (try selection.next(rng, found.retries)) |position| {
                const peer = self.participants.items[position].peer;
                // Checking consumes a rate-limit token unless the peer is limited.
                const checked = switch (try sender.check(.{ .one = peer })) {
                    .limited => |not_until| {
                        const earliest = scan.earliest_rate_limit orelse not_until;
                        scan.earliest_rate_limit = min_time(earliest, not_until);
                        continue;
                    },
                    .checked => |checked| checked,
                };
                const id = self.request_id orelse rng.next_u64();
                self.request_id = id +% 1;
                if (try self.send_request(checked, id, key)) {
                    try self.requests_sent.inc(.success);
                    return .{ .key = key, .id = id, .peer = peer, .start = self.now() };
                }
                // The send was not handled, so try the next peer.
                try self.requests_sent.inc(.dropped);
            }
            // Every eligible peer was tried: rate-limited or not accepting the request.
            assert(selection.draws.is_empty());
            return null;
        }

        /// Sends a request through a checked sender; true when the network accepted it.
        fn send_request(self: *Self, checked: anytype, id: ID, key: Key) !bool {
            const message: Message = .{ .id = id, .payload = .{ .request = key } };
            const bytes = codec.encode(Message, self.gpa, message) catch |err| {
                checked.deinit();
                return err;
            };
            defer self.gpa.free(bytes);
            assert(bytes.len == codec.encode_size(Message, message));
            return checked.send(&.{bytes}, self.priority_requests).accepted();
        }

        /// Retains only the fetches whose keys satisfy `predicate.call(key)`.
        pub fn retain(self: *Self, predicate: anytype) void {
            var position = self.requests.count();
            while (position > 0) {
                position -= 1;
                const request = self.requests.values()[position];
                if (predicate.call(request.key)) continue;
                const id = self.requests.keys()[position];
                _ = self.active.remove(id);
                self.requests.swapRemoveAt(position);
            }
            assert(self.active.len() == self.requests.count());
            self.pending.retain(predicate);
            position = self.targets.entries.items.len;
            while (position > 0) {
                position -= 1;
                const entry = &self.targets.entries.items[position];
                if (predicate.call(entry.key)) continue;
                entry.value.deinit(self.gpa);
                _ = self.targets.entries.orderedRemove(position);
            }
            position = self.retries.entries.items.len;
            while (position > 0) {
                position -= 1;
                if (predicate.call(self.retries.entries.items[position].key)) continue;
                _ = self.retries.entries.orderedRemove(position);
            }
            // The key that set the waiter may have been removed.
            self.waiter = null;
        }

        /// Enqueues `key` as a fresh request or a retry due at `deadline`.
        fn add_pending(
            self: *Self,
            key: Key,
            retry: bool,
            deadline: SystemTime,
        ) Allocator.Error!void {
            assert(!self.pending.contains(key));
            // Each key takes the next sequence number, so keys of one class and deadline are
            // tried in arrival order.
            const sequence = self.pending_sequence;
            self.pending_sequence = std.math.add(u64, sequence, 1) catch
                @panic("pending sequence must not overflow");
            // A previous key may have pushed the waiter far out because no eligible peer could
            // serve it. A newly queued key can still be fetchable, so wake immediately.
            self.waiter = null;
            const order: Order = .{ .retry = retry, .deadline = deadline, .sequence = sequence };
            try self.pending.put(self.gpa, key, order);
            assert(self.pending.contains(key));
        }

        /// Adds a fresh key to the pending queue, ahead of retries. The key must not be
        /// pending.
        pub fn add_ready(self: *Self, key: Key) Allocator.Error!void {
            try self.add_pending(key, false, self.now());
        }

        /// Schedules another attempt after a dispatched request did not resolve the key,
        /// advancing its retry count. The key must not be pending.
        pub fn add_retry(self: *Self, key: Key) Allocator.Error!void {
            assert(!self.pending.contains(key));
            const retries = try self.retries.get_or_put(self.gpa, key, 0);
            retries.* +|= 1;
            const deadline = add_time(self.now(), self.retry_delay);
            try self.add_pending(key, true, deadline);
        }

        /// The deadline for the next pending retry: the later of the waiter and the next
        /// pending deadline.
        pub fn get_pending_deadline(self: *const Self) ?SystemTime {
            // Pending may be emptied by retain.
            const next = self.pending.peek() orelse return null;
            const waiter = self.waiter orelse return next.priority.deadline;
            const deadline = next.priority.deadline;
            return if (waiter.order(deadline) == .gt) waiter else deadline;
        }

        /// The deadline for the next active request timeout.
        pub fn get_active_deadline(self: *const Self) ?SystemTime {
            const next = self.active.peek() orelse return null;
            return next.priority;
        }

        /// Removes and returns the key with the next request timeout, charging its peer for
        /// failing to serve it. Targets are not removed on timeout.
        pub fn pop_active(self: *Self) Allocator.Error!?Key {
            const next = self.active.pop() orelse return null;
            const request = (self.requests.fetchSwapRemove(next.item) orelse return null).value;
            const charge = self.fetch_timeout.saturating_add(self.retry_delay);
            try self.update_performance(request.peer, charge, 0);
            return request.key;
        }

        pub const Response = struct { key: Key, elapsed: Duration };

        /// Removes the request `id` sent to `peer`, returning its key and network response
        /// time. For a data response, the caller reports it with `record_response` once the
        /// consumer decides it should be attributed to the peer. Targets are not removed.
        ///
        /// This matches responses against the peer a request was already sent to; a later
        /// `reconcile` does not invalidate an in-flight request.
        pub fn pop_response(self: *Self, id: ID, peer: P) ?Response {
            const request = self.requests.get(id) orelse return null;
            if (codec.order(P, request.peer, peer) != .eq) return null;
            assert(self.requests.swapRemove(id));
            _ = self.active.remove(id);
            return .{ .key = request.key, .elapsed = duration_since(self.now(), request.start) };
        }

        /// Attributes a received data response to its serving peer. Record only responses the
        /// consumer judged complete or partially useful, once per network response.
        pub fn record_response(
            self: *Self,
            peer: P,
            elapsed: Duration,
            bytes: u64,
        ) Allocator.Error!void {
            try self.update_performance(peer, elapsed, bytes);
            self.resolves.metric().observe(as_secs_f64(elapsed));
        }

        /// Processes a response indicating that the peer does not have the requested data:
        /// records zero useful bytes and charges the elapsed wait plus the retry delay.
        pub fn pop_missing(self: *Self, id: ID, peer: P) Allocator.Error!?Key {
            const response = self.pop_response(id, peer) orelse return null;
            const charge = response.elapsed.saturating_add(self.retry_delay);
            try self.update_performance(peer, charge, 0);
            return response.key;
        }

        /// Reconciles the peers available to future fetches with the latest tracked set.
        pub fn reconcile(self: *Self, peers: []const P) Allocator.Error!void {
            // A stable, duplicate-free order makes both sampling modes reproducible.
            const sorted = try sorted_unique(P, self.gpa, peers);
            defer self.gpa.free(sorted);
            var merged: std.ArrayList(Participant) = try .initCapacity(self.gpa, sorted.len);
            errdefer merged.deinit(self.gpa);
            const weights = try self.gpa.alloc(u64, sorted.len);
            defer self.gpa.free(weights);
            // One pass over both sorted rosters: retained peers keep their history, new peers
            // start at the minimum weight, departed peers leave the performance metric.
            const previous = self.participants.items;
            var cursor: usize = 0;
            for (sorted, weights) |peer, *weight| {
                while (cursor < previous.len and
                    codec.order(P, previous[cursor].peer, peer) == .lt) : (cursor += 1)
                {
                    _ = self.performance.metric().remove(.{ .peer = previous[cursor].peer });
                }
                var score: Score = .{};
                if (cursor < previous.len and codec.order(P, previous[cursor].peer, peer) == .eq) {
                    score = previous[cursor].score;
                    cursor += 1;
                }
                merged.appendAssumeCapacity(.{ .peer = peer, .score = score });
                // Local and blocked peers keep their entries but are never sampled.
                const excluded = self.is_me(peer) or contains_sorted(P, self.blocked.items, peer);
                weight.* = if (excluded) 0 else score.weight();
            }
            for (previous[cursor..]) |departed| {
                _ = self.performance.metric().remove(.{ .peer = departed.peer });
            }
            var index_new = try WeightedIndex.init(self.gpa, weights);
            std.mem.swap(WeightedIndex, &self.weights, &index_new);
            index_new.deinit(self.gpa);
            self.participants.deinit(self.gpa);
            self.participants = merged;
            assert(self.weights.len() == self.participants.items.len);
            // The waiter may no longer apply.
            self.waiter = null;
        }

        /// Replaces the set of peers the network currently blocks. Blocked peers keep their
        /// place in target sets and are skipped until a later update no longer lists them.
        pub fn set_blocked(self: *Self, blocked: []const P) Allocator.Error!void {
            const sorted = try sorted_unique(P, self.gpa, blocked);
            const next: std.ArrayList(P) = .fromOwnedSlice(sorted);
            for (self.blocked.items) |peer| {
                if (!contains_sorted(P, next.items, peer)) self.refresh_weight(peer, false);
            }
            for (next.items) |peer| {
                if (!contains_sorted(P, self.blocked.items, peer)) self.refresh_weight(peer, true);
            }
            self.blocked.deinit(self.gpa);
            self.blocked = next;
            assert(self.blocked.items.len <= blocked.len);
            // An unblocked peer may make a waiting fetch servable.
            self.waiter = null;
        }

        fn refresh_weight(self: *Self, peer: P, blocked: bool) void {
            if (self.is_me(peer)) return;
            const position = self.index(peer) orelse return;
            const weight = if (blocked) 0 else self.participants.items[position].score.weight();
            _ = self.weights.set(position, weight);
            assert(self.weights.weight(position) == weight);
        }

        /// Adds target peers for fetching a key (to any existing targets), clearing the waiter
        /// so a fetch waiting for targets retries immediately.
        pub fn add_targets(self: *Self, key: Key, peers: []const P) Allocator.Error!void {
            const targets = try self.targets.get_or_put(self.gpa, key, .empty);
            for (peers) |peer| try insert_sorted(P, self.gpa, targets, peer);
            self.waiter = null;
        }

        /// Clears targeting for a key: an ongoing fetch may try any available peer. Its retry
        /// count is preserved.
        pub fn clear_targets(self: *Self, key: Key) void {
            if (self.targets.remove(key)) |targets| {
                var owned = targets;
                owned.deinit(self.gpa);
            }
            self.waiter = null;
        }

        /// Drops the targets and peer-selection history of a key whose fetch has ended.
        pub fn clear(self: *Self, key: Key) void {
            if (self.targets.remove(key)) |targets| {
                var owned = targets;
                owned.deinit(self.gpa);
            }
            _ = self.retries.remove(key);
        }

        pub fn has_targets(self: *const Self, key: Key) bool {
            return self.targets.get(key) != null;
        }

        /// The targets of `key` in public-key order, if it has any.
        pub fn targets_of(self: *const Self, key: Key) ?[]const P {
            const targets = self.targets.get(key) orelse return null;
            return targets.items;
        }

        /// The number of fetches (pending and active).
        pub fn len(self: *const Self) usize {
            return self.pending.len() + self.requests.count();
        }

        pub fn len_pending(self: *const Self) usize {
            return self.pending.len();
        }

        pub fn len_active(self: *const Self) usize {
            return self.requests.count();
        }

        /// Whether a fetch for `key` is pending or active.
        pub fn contains(self: *const Self, key: Key) bool {
            if (self.pending.contains(key)) return true;
            for (self.requests.values()) |request| {
                if (codec.order(Key, request.key, key) == .eq) return true;
            }
            return false;
        }

        /// The retry count of `key` (0 when it has none).
        pub fn retry_count(self: *const Self, key: Key) u32 {
            const count = self.retries.get(key) orelse return 0;
            return count.*;
        }

        /// The weight `peer`'s throughput score gives it (ignoring local/blocked exclusion).
        pub fn peer_weight(self: *const Self, peer: P) ?u64 {
            const position = self.index(peer) orelse return null;
            return self.participants.items[position].score.weight();
        }
    };
}

test {
    _ = @import("fetcher_test.zig");
    _ = @import("fetcher_fuzz_test.zig");
}
