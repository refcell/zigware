//! `Plan`: the keys a batch of transfers changes, each once, with each key's debit and credit
//! sums and its effects in transfer order (commonware `transfers::Plan`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const utils = @import("utils");
const transfers = @import("mod.zig");

const handles = utils.handles;
const amount = utils.amount;
const Lookahead = utils.prefetch.Lookahead;
const max_chunks = parallel.max_chunks;
const partitions = transfers.partitions;

/// The plan of a batch whose keys are `K` and accounts `A`. The key order is unspecified and
/// may differ between plans of the same transfers; only the set of keys and each key's changes
/// are fixed. Read the accounts in `keys` order and pass them to `settle`.
pub fn Plan(comptime K: type, comptime A: type) type {
    transfers.assert_account(A);
    return struct {
        const Self = @This();
        pub const Rejection = transfers.Rejection(K);
        const Amount = A.Amount;
        const Effect = transfers.StoredEffect(A);
        const Touch = transfers.Touch(K, A);
        const Rejections = transfers.Rejections(K);
        const Placed = struct { position: usize, effect: Effect };

        /// Every key the batch changes, each once.
        keys: []K,
        /// The sum of each key's debits, in `keys` order.
        debits: []Amount,
        /// The sum of each key's credits, in `keys` order.
        credits: []Amount,
        /// Where each key's effects start in `effects`, then where the last key's end, or
        /// empty when no key has one.
        effect_offsets: []usize,
        /// Each key's effects in transfer order, grouped in `keys` order.
        effects: []Effect,

        pub const empty: Self = .{
            .keys = &.{},
            .debits = &.{},
            .credits = &.{},
            .effect_offsets = &.{},
            .effects = &.{},
        };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.keys);
            gpa.free(self.debits);
            gpa.free(self.credits);
            gpa.free(self.effect_offsets);
            gpa.free(self.effects);
            self.* = undefined;
        }

        /// The number of keys the batch changes.
        pub fn len(self: *const Self) usize {
            return self.keys.len;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.keys.len == 0;
        }

        /// Plans `list`, a slice of transfers, gathering their changes for each key with keys
        /// placed by a hash keyed with `seed` (commonware `Plan::with_seed`; `Plan::new` draws
        /// the seed at random). Debits and credits are summed, effects keep their transfer
        /// order, and keys touched only by empty changes are left out. Fails with
        /// `error.Rejected` (filling `rejection`) if a key's debits or credits sum past the
        /// largest amount. `strategy` splits the hashing and deduplication among its workers.
        pub fn init(
            gpa: Allocator,
            list: anytype,
            seed: u64,
            strategy: anytype,
            rejection: *Rejection,
        ) transfers.Error!Self {
            const hasher: transfers.SeededHasher = .{ .seed = seed };
            return init_with_hasher(gpa, list, hasher, strategy, rejection);
        }

        /// Plans `list` with `hasher` (`hash(bytes) u64`) placing the keys.
        pub fn init_with_hasher(
            gpa: Allocator,
            list: anytype,
            hasher: anytype,
            strategy: anytype,
            rejection: *Rejection,
        ) transfers.Error!Self {
            const T = @typeInfo(@TypeOf(list)).pointer.child;
            comptime assert(T.Key == K and T.Account == A);
            var rejections: Rejections = .{};
            const result = if (list.len < 2 * transfers.hash_batch_min)
                plan_short(gpa, list, hasher, strategy, &rejections)
            else
                plan_long(gpa, list, hasher, strategy, &rejections);
            return result catch |err| reject_with(err, &rejections, rejection);
        }

        /// No strategy splits the hashing of fewer than two hash batches, so such an input
        /// hashes its touches on the calling thread. Unless they are few, the strategy then
        /// decides whether to bucket them by partition and split the partitions.
        fn plan_short(
            gpa: Allocator,
            list: anytype,
            hasher: anytype,
            strategy: anytype,
            rejections: *Rejections,
        ) transfers.Error!Self {
            var touches = try std.ArrayList(Touch).initCapacity(
                gpa,
                transfers.estimated_changes(list),
            );
            defer touches.deinit(gpa);
            try transfers.for_each_touch(list, hasher, Collect{ .gpa = gpa, .touches = &touches });
            if (touches.items.len < transfers.split_touches_min) {
                return build(gpa, &.{touches.items}, hasher, rejections, 0);
            }
            const per_partition = std.math.divCeil(usize, touches.items.len, partitions) catch
                unreachable; // The divisor is a nonzero constant.
            const op: ShortOp(@TypeOf(hasher)) = .{
                .gpa = gpa,
                .touches = touches.items,
                .hasher = hasher,
                .rejections = rejections,
            };
            const batch_min = transfers.partition_batch_min;
            return strategy.try_run_batches(partitions, batch_min, per_partition, op);
        }

        /// Hashes the key of each change in parallel over the transfers, bucketing the touches
        /// by partition, then deduplicates each range of partitions on its own worker, so no
        /// two workers hold the same key and the shards concatenate into the plan.
        fn plan_long(
            gpa: Allocator,
            list: anytype,
            hasher: anytype,
            strategy: anytype,
            rejections: *Rejections,
        ) transfers.Error!Self {
            const hashing: HashOp(@TypeOf(list), @TypeOf(hasher)) = .{
                .gpa = gpa,
                .list = list,
                .hasher = hasher,
            };
            const batch_min = transfers.hash_batch_min;
            var hashed = try strategy.try_run_batches(list.len, batch_min, 1, hashing);
            defer for (hashed.batches[0..hashed.count]) |*buckets| buckets.deinit(gpa);
            var total: usize = 0;
            for (hashed.batches[0..hashed.count]) |*buckets| total += buckets.touches();
            const per_partition = std.math.divCeil(usize, total, partitions) catch unreachable;
            const op: PartitionOp(@TypeOf(hasher)) = .{
                .gpa = gpa,
                .buckets = hashed.batches[0..hashed.count],
                .hasher = hasher,
                .rejections = rejections,
            };
            const partition_min = transfers.partition_batch_min;
            return strategy.try_run_batches(partitions, partition_min, per_partition, op);
        }

        fn reject_with(
            err: anytype,
            rejections: *const Rejections,
            out: *Rejection,
        ) transfers.Error {
            if (err == error.Rejected) out.* = rejections.first();
            return err;
        }

        const Collect = struct {
            gpa: Allocator,
            touches: *std.ArrayList(Touch),

            pub fn touch(collect: Collect, touch_value: Touch) Allocator.Error!void {
                try collect.touches.append(collect.gpa, touch_value);
            }
        };

        /// The touches of one range of transfers, bucketed by partition.
        const Buckets = struct {
            lists: []std.ArrayList(Touch),

            /// An empty bucket per partition, sized for `expected` touches spread over them
            /// with a margin for uneven hashing, so most buckets never grow.
            fn init(gpa: Allocator, expected: usize) Allocator.Error!Buckets {
                const lists = try gpa.alloc(std.ArrayList(Touch), partitions);
                @memset(lists, .empty);
                var buckets: Buckets = .{ .lists = lists };
                errdefer buckets.deinit(gpa);
                const share = std.math.divCeil(usize, expected, partitions) catch unreachable;
                const capacity = share + share / transfers.bucket_margin_divisor +
                    transfers.bucket_spare;
                for (lists) |*list| try list.ensureTotalCapacity(gpa, capacity);
                return buckets;
            }

            fn deinit(buckets: *Buckets, gpa: Allocator) void {
                for (buckets.lists) |*list| list.deinit(gpa);
                gpa.free(buckets.lists);
                buckets.* = undefined;
            }

            fn touches(buckets: *const Buckets) usize {
                var count: usize = 0;
                for (buckets.lists) |list| count += list.items.len;
                return count;
            }

            fn add(buckets: *Buckets, gpa: Allocator, touch: Touch) Allocator.Error!void {
                try buckets.lists[handles.partition(touch.hash, partitions)].append(gpa, touch);
            }
        };

        const BucketSink = struct {
            gpa: Allocator,
            buckets: *Buckets,

            pub fn touch(sink: BucketSink, touch_value: Touch) Allocator.Error!void {
                try sink.buckets.add(sink.gpa, touch_value);
            }
        };

        fn ShortOp(comptime H: type) type {
            return struct {
                gpa: Allocator,
                touches: []const Touch,
                hasher: H,
                rejections: *Rejections,

                pub fn run(op: @This(), batches: anytype) transfers.Error!Self {
                    if (batches.is_whole()) {
                        return build(op.gpa, &.{op.touches}, op.hasher, op.rejections, 0);
                    }
                    // Bucket the touches by partition, so each worker reads only its own.
                    var buckets = try Buckets.init(op.gpa, op.touches.len);
                    defer buckets.deinit(op.gpa);
                    for (op.touches) |touch| try buckets.add(op.gpa, touch);
                    const shards: PartitionOp(H) = .{
                        .gpa = op.gpa,
                        .buckets = (&buckets)[0..1],
                        .hasher = op.hasher,
                        .rejections = op.rejections,
                    };
                    return shards.run(batches);
                }
            };
        }

        /// The hash batches' buckets.
        const Hashed = struct { batches: [max_chunks]Buckets, count: usize };

        fn HashOp(comptime L: type, comptime H: type) type {
            return struct {
                gpa: Allocator,
                list: L,
                hasher: H,

                pub fn run(op: @This(), batches: anytype) Allocator.Error!Hashed {
                    var hashed: Hashed = .{ .batches = undefined, .count = batches.count() };
                    try batches.try_map_collect(hashed.batches[0..hashed.count], op);
                    return hashed;
                }

                pub fn map(op: @This(), _: usize, range: parallel.Range) Allocator.Error!Buckets {
                    const list = op.list[range.start..range.end];
                    var buckets = try Buckets.init(op.gpa, transfers.estimated_changes(list));
                    errdefer buckets.deinit(op.gpa);
                    const sink: BucketSink = .{ .gpa = op.gpa, .buckets = &buckets };
                    try transfers.for_each_touch(list, op.hasher, sink);
                    return buckets;
                }

                pub fn discard(op: @This(), buckets: Buckets) void {
                    var owned = buckets;
                    owned.deinit(op.gpa);
                }
            };
        }

        /// Deduplicates each batch's range of partitions over every hash batch's buckets.
        fn PartitionOp(comptime H: type) type {
            return struct {
                gpa: Allocator,
                buckets: []const Buckets,
                hasher: H,
                rejections: *Rejections,

                pub fn run(op: @This(), batches: anytype) transfers.Error!Self {
                    const count = batches.count();
                    var shards: [max_chunks]Self = undefined;
                    try batches.try_map_collect(shards[0..count], op);
                    defer for (shards[0..count]) |*shard| shard.deinit(op.gpa);
                    return from_shards(op.gpa, shards[0..count]);
                }

                /// Each key's touches arrive in transfer order, one hash batch after another.
                pub fn map(op: @This(), index: usize, range: parallel.Range) transfers.Error!Self {
                    const width = range.end - range.start;
                    const runs = try op.gpa.alloc([]const Touch, op.buckets.len * width);
                    defer op.gpa.free(runs);
                    var next: usize = 0;
                    for (op.buckets) |buckets| {
                        for (buckets.lists[range.start..range.end]) |list| {
                            runs[next] = list.items;
                            next += 1;
                        }
                    }
                    assert(next == runs.len);
                    return build(op.gpa, runs, op.hasher, op.rejections, index);
                }

                pub fn discard(op: @This(), shard: Self) void {
                    var owned = shard;
                    owned.deinit(op.gpa);
                }
            };
        }

        /// Deduplicates `runs` of touches, sums their debits and credits, and groups their
        /// effects by key. The index is sized for every touch, so it never grows.
        fn build(
            gpa: Allocator,
            runs: []const []const Touch,
            hasher: anytype,
            rejections: *Rejections,
            batch: usize,
        ) transfers.Error!Self {
            var expected: usize = 0;
            for (runs) |run| expected += run.len;
            var index = try transfers.KeyIndex(K).init_capacity(gpa, expected);
            defer index.deinit(gpa);
            var sums: Sums = .{
                .debits = try .initCapacity(gpa, expected),
                .credits = try .initCapacity(gpa, expected),
            };
            defer sums.deinit(gpa);
            for (runs) |run| {
                // Prefetch the home slot of each touch a fixed distance ahead of its lookup.
                var ahead = Lookahead.init(transfers.prefetch_distance);
                for (run, 0..) |*touch, i| {
                    for (ahead.advance(Touch, run[i..])) |later| index.prefetch(later.hash);
                    const position, const inserted =
                        try index.find_or_insert(gpa, touch.key, touch.hash, hasher);
                    try sums.add(gpa, touch, position, inserted, rejections, batch);
                }
            }
            assert(sums.debits.items.len == index.len());
            const keys = try index.keys.toOwnedSlice(gpa);
            errdefer gpa.free(keys);
            const offsets, const effects = try group_effects(gpa, keys.len, sums.effects.items);
            return .{
                .keys = keys,
                .debits = try sums.debits.toOwnedSlice(gpa),
                .credits = try sums.credits.toOwnedSlice(gpa),
                .effect_offsets = offsets,
                .effects = effects,
            };
        }

        /// One shard's sums, and its effects set aside with their key's position.
        const Sums = struct {
            debits: std.ArrayList(Amount),
            credits: std.ArrayList(Amount),
            effects: std.ArrayList(Placed) = .empty,

            fn deinit(sums: *Sums, gpa: Allocator) void {
                sums.debits.deinit(gpa);
                sums.credits.deinit(gpa);
                sums.effects.deinit(gpa);
            }

            /// Adds `touch` to the sums of the key at `position`. No balance can afford debits
            /// that sum past the largest amount, and credits that do overflow every balance.
            fn add(
                sums: *Sums,
                gpa: Allocator,
                touch: *const Touch,
                position: usize,
                inserted: bool,
                rejections: *Rejections,
                batch: usize,
            ) transfers.Error!void {
                if (inserted) {
                    sums.debits.appendAssumeCapacity(0);
                    sums.credits.appendAssumeCapacity(0);
                }
                assert(position < sums.debits.items.len);
                const change = &touch.change;
                if (change.debit != 0) {
                    const debit = &sums.debits.items[position];
                    debit.* = amount.checked_add(Amount, debit.*, change.debit) orelse
                        return rejections.reject(batch, .insufficient, touch.key.*);
                }
                if (change.credit != 0) {
                    const credit = &sums.credits.items[position];
                    credit.* = amount.checked_add(Amount, credit.*, change.credit) orelse
                        return rejections.reject(batch, .overflow, touch.key.*);
                }
                if (comptime transfers.has_effects(A)) {
                    if (change.effect) |effect| {
                        try sums.effects.append(gpa, .{ .position = position, .effect = effect });
                    }
                }
            }
        };

        /// Groups `placed` effects into one run per key that keeps their order. Returns the
        /// offset of each key's run with a final offset, and the runs, or two empty slices when
        /// there are no effects.
        fn group_effects(
            gpa: Allocator,
            key_count: usize,
            placed: []const Placed,
        ) Allocator.Error!struct { []usize, []Effect } {
            if (placed.len == 0) return .{ &.{}, &.{} };
            // Count each key's effects, then sum the counts so each run follows the ones before.
            const offsets = try gpa.alloc(usize, key_count + 1);
            errdefer gpa.free(offsets);
            @memset(offsets, 0);
            for (placed) |effect| offsets[effect.position + 1] += 1;
            for (0..key_count) |position| offsets[position + 1] += offsets[position];
            assert(offsets[key_count] == placed.len);

            // Fill each run from its end, walking the effects backward to keep their order.
            const next = try gpa.dupe(usize, offsets[1..]);
            defer gpa.free(next);
            const grouped = try gpa.alloc(Effect, placed.len);
            var remaining = placed.len;
            while (remaining > 0) {
                remaining -= 1;
                const effect = placed[remaining];
                next[effect.position] -= 1;
                grouped[next[effect.position]] = effect.effect;
            }
            return .{ offsets, grouped };
        }

        /// Concatenates `shards`, shifting effect offsets past the preceding shards.
        fn from_shards(gpa: Allocator, shards: []const Self) Allocator.Error!Self {
            var key_count: usize = 0;
            var effect_count: usize = 0;
            for (shards) |shard| {
                key_count += shard.keys.len;
                effect_count += shard.effects.len;
            }
            var result: Self = .empty;
            errdefer result.deinit(gpa);
            result.keys = try gpa.alloc(K, key_count);
            result.debits = try gpa.alloc(Amount, key_count);
            result.credits = try gpa.alloc(Amount, key_count);
            if (effect_count != 0) {
                result.effect_offsets = try gpa.alloc(usize, key_count + 1);
                result.effect_offsets[0] = 0;
                result.effects = try gpa.alloc(Effect, effect_count);
            }
            var keys: usize = 0;
            var effects: usize = 0;
            for (shards) |shard| {
                const n = shard.keys.len;
                @memcpy(result.keys[keys..][0..n], shard.keys);
                @memcpy(result.debits[keys..][0..n], shard.debits);
                @memcpy(result.credits[keys..][0..n], shard.credits);
                if (effect_count != 0) {
                    const offsets = result.effect_offsets[keys + 1 ..][0..n];
                    if (shard.effect_offsets.len == 0) @memset(offsets, effects) else {
                        for (offsets, shard.effect_offsets[1..]) |*to, from| to.* = effects + from;
                    }
                    @memcpy(result.effects[effects..][0..shard.effects.len], shard.effects);
                    effects += shard.effects.len;
                }
                keys += n;
            }
            assert(keys == key_count and effects == effect_count);
            return result;
        }

        /// The effects on the key at `index`, in transfer order.
        pub fn effects_of(self: *const Self, index: usize) []const Effect {
            if (self.effect_offsets.len == 0) return &.{};
            return self.effects[self.effect_offsets[index]..self.effect_offsets[index + 1]];
        }

        /// Settles the batch against `reads`, the starting account of each key in `keys` order,
        /// null for a key the database does not hold. Returns one slot per key, in the same
        /// order, for the staged batch to merkleize. Fails with `error.Rejected` (filling
        /// `rejection`) if an account refuses an effect, a key's debits exceed its starting
        /// balance, or its final balance exceeds the largest amount.
        pub fn settle(
            self: *const Self,
            gpa: Allocator,
            reads: []const ?A,
            strategy: anytype,
            rejection: *Rejection,
        ) transfers.Error![]transfers.Slot(A) {
            if (reads.len != self.keys.len) @panic("reads must hold one account per key");
            var rejections: Rejections = .{};
            const op: SettleOp = .{ .plan = self, .reads = reads, .rejections = &rejections };
            return transfers.settle_batches(A, gpa, strategy, self.keys.len, op) catch |err|
                reject_with(err, &rejections, rejection);
        }

        const SettleOp = struct {
            plan: *const Self,
            reads: []const ?A,
            rejections: *Rejections,

            pub fn settle(
                op: SettleOp,
                batch: usize,
                range: parallel.Range,
                slots: []transfers.Slot(A),
            ) error{Rejected}!void {
                const plan = op.plan;
                for (slots, range.start..) |*slot, index| {
                    // A key the database does not hold starts as the default account, and its
                    // effects apply to the starting account in transfer order.
                    const start: A = op.reads[index] orelse A.default;
                    var account = start;
                    if (comptime transfers.has_effects(A)) {
                        for (plan.effects_of(index)) |effect| {
                            if (!account.apply(effect)) {
                                return op.rejections.reject(batch, .refused, plan.keys[index]);
                            }
                        }
                    }
                    // Debits come off the starting balance before credits are added, so
                    // credits never fund debits. The result replaces any balance an effect set.
                    const debit = plan.debits[index];
                    const remaining = amount.checked_sub(Amount, start.balance(), debit) orelse
                        return op.rejections.reject(batch, .insufficient, plan.keys[index]);
                    const credit = plan.credits[index];
                    const balance = amount.checked_add(Amount, remaining, credit) orelse
                        return op.rejections.reject(batch, .overflow, plan.keys[index]);
                    slot.* = transfers.settled_slot(A, account, balance, &start);
                }
            }
        };
    };
}
