//! QMDB floor policies drawn from fuzz input, and a partial oracle for the floor walks they
//! drive (commonware `storage/fuzz/src/floor.rs`).
//!
//! A `Plan` picks the policy one batch walks its floor with: one of the library policies, or a
//! scripted policy whose choice for each update depends only on the update's key and value, so
//! equivalent batches built along different paths decide identically.
//!
//! `Recorder` runs a plan as a floor policy and records every decision. `Recorder.check` checks
//! the record and the floor the batch's commit records against the target's model of the
//! batch's post-write state, then replays the record into that model. It returns an error
//! naming the broken rule where commonware panics. See commonware's module documentation for
//! what the oracle can and cannot see.
//!
//! Keys and values must own no memory: the recorder copies them.

const std = @import("std");
const assert = std.debug.assert;
const fuzz_bytes = @import("../fuzz_bytes.zig");
const floor = @import("floor.zig");

/// A limit that binds within a fuzzed batch, or one that never binds.
pub const Limit = union(enum) {
    /// `n % 8` entries or `n % 32` skips.
    small: u8,
    /// The type's maximum, so the walk's window ends at the tip.
    huge,

    pub fn decode(reader: *fuzz_bytes.Reader) Limit {
        return if (reader.boolean()) .{ .small = reader.int(u8) } else .huge;
    }

    pub fn entries(self: Limit) usize {
        return switch (self) {
            .small => |n| n % 8,
            .huge => std.math.maxInt(usize),
        };
    }

    pub fn skips(self: Limit) u64 {
        return switch (self) {
            .small => |n| n % 32,
            .huge => std.math.maxInt(u64),
        };
    }
};

/// What a scripted policy does with an update it decides.
pub const Choice = union(enum) {
    /// Keep the update, which moves it to the tip.
    keep,
    /// Write the target's replacement value for this seed.
    replace: u8,
    /// Delete the update's key.
    evict,
    /// End the walk at the update.
    stop,

    pub fn decode(reader: *fuzz_bytes.Reader) Choice {
        return switch (reader.int(u8) % 4) {
            0 => .keep,
            1 => .{ .replace = reader.int(u8) },
            2 => .evict,
            3 => .stop,
            else => unreachable, // Proof: `% 4` is in 0..4.
        };
    }
};

/// The floor policy for one batch.
pub const Plan = union(enum) {
    /// The library's `Proportional` policy.
    proportional,
    /// The library's `Hold` policy, which decides nothing.
    hold,
    /// The library's `Bounded` policy, which keeps every update it reaches.
    bounded: struct { entries: Limit, skips: Limit },
    /// Decide each update with the choice its key, value, and `salt` hash to.
    scripted: struct { entries: Limit, skips: Limit, salt: u8, choices: [4]Choice },

    pub fn decode(reader: *fuzz_bytes.Reader) Plan {
        return switch (reader.int(u8) % 4) {
            0 => .proportional,
            1 => .hold,
            2 => .{ .bounded = .{ .entries = .decode(reader), .skips = .decode(reader) } },
            3 => .{ .scripted = .{
                .entries = .decode(reader),
                .skips = .decode(reader),
                .salt = reader.int(u8),
                .choices = .{ .decode(reader), .decode(reader), .decode(reader), .decode(reader) },
            } },
            else => unreachable, // Proof: `% 4` is in 0..4.
        };
    }

    /// The `(entries, skips)` of a plan whose limits do not depend on the batch.
    fn fixed(self: Plan) ?struct { usize, u64 } {
        return switch (self) {
            .proportional => null,
            .hold => .{ 0, 0 },
            inline .bounded, .scripted => |p| .{ p.entries.entries(), p.skips.skips() },
        };
    }
};

/// Hashes the salt, key, and value into an index of a scripted choice table (FNV-1a).
fn script_index(salt: u8, key: []const u8, value: []const u8) usize {
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    hash = (hash ^ salt) *% 0x0100_0000_01b3;
    for (key) |byte| hash = (hash ^ byte) *% 0x0100_0000_01b3;
    for (value) |byte| hash = (hash ^ byte) *% 0x0100_0000_01b3;
    return @intCast(hash % 4);
}

/// The rules of a floor walk the oracle can see, one error per rule.
pub const CheckError = error{
    DecidedNotLive,
    DecidedTwice,
    DecidedOutsideWalk,
    DecidedOutOfOrder,
    DecidedPastSkips,
    ContinuedPastStop,
    DecidedPastEntries,
    FloorDecreased,
    EmptyFloorNotAtCommit,
    FloorReachedCommit,
    FloorPastBudget,
    FloorNotAtStop,
    FloorNotWhereEntriesRanOut,
    WalkEndedEarly,
    FloorNotPastDecisions,
    WalkDependsOnPath,
};

/// Runs a `Plan` as a floor policy over keys `K` and values `V`, recording each decision. A
/// walk decides each live key at most once, so at most `capacity` decisions fit.
pub fn Recorder(comptime K: type, comptime V: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();

        pub const Outcome = union(enum) { keep, replace: V, evict, stop };
        pub const Decided = struct { location: u64, key: K, value: V, outcome: Outcome };
        pub const Model = std.AutoHashMapUnmanaged(K, V);

        plan: Plan,
        replacement: *const fn (u8) V,
        decided: [capacity]Decided = undefined,
        count: usize = 0,

        pub fn init(plan: Plan, replacement: *const fn (u8) V) Self {
            return .{ .plan = plan, .replacement = replacement };
        }

        pub fn decisions(self: *const Self) []const Decided {
            return self.decided[0..self.count];
        }

        pub fn evicts(self: *const Self) bool {
            return self.plan == .scripted;
        }

        pub fn limits(self: *const Self, made_inactive: usize) floor.Limits {
            return switch (self.plan) {
                .proportional => (floor.Proportional{}).limits(made_inactive),
                .hold => (floor.Hold{}).limits(made_inactive),
                inline .bounded, .scripted => |p| .{
                    .entries = p.entries.entries(),
                    .skips = p.skips.skips(),
                },
            };
        }

        pub fn decide(
            self: *Self,
            comptime EK: type,
            comptime EV: type,
            entry: floor.Entry(EK, EV),
        ) floor.Decision(EV) {
            comptime assert(EK == K and EV == V);
            assert(self.count < capacity);
            assert(self.plan != .hold); // Hold's zero entries never reach decide.
            const outcome: Outcome, const decision = switch (self.plan) {
                .proportional, .bounded, .hold => .{ .keep, entry.keep() },
                .scripted => |p| scripted: {
                    const key = std.mem.asBytes(entry.key);
                    const value = std.mem.asBytes(&entry.value);
                    break :scripted switch (p.choices[script_index(p.salt, key, value)]) {
                        .keep => .{ .keep, entry.keep() },
                        .replace => |seed| .{
                            .{ .replace = self.replacement(seed) },
                            entry.replace(self.replacement(seed)),
                        },
                        .evict => .{ .evict, entry.evict()[0] },
                        .stop => .{ .stop, entry.stop() },
                    };
                },
            };
            self.decided[self.count] = .{
                .location = entry.location,
                .key = entry.key.*,
                .value = entry.value,
                .outcome = outcome,
            };
            self.count += 1;
            return decision;
        }

        /// Checks the batch's floor walk and replays its decisions into `model`, which holds the
        /// batch's live keys and values after its writes and before its walk. `inherited` is the
        /// floor the batch walked from, `floor_loc` the floor its commit records, and `commit`
        /// that commit's location.
        pub fn check(
            self: *const Self,
            gpa: std.mem.Allocator,
            model: *Model,
            inherited: u64,
            floor_loc: u64,
            commit: u64,
        ) (CheckError || std.mem.Allocator.Error)!void {
            assert(inherited <= commit);
            try self.check_decisions(model, inherited, commit);
            const live = model.count();
            for (self.decisions()) |d| switch (d.outcome) {
                .replace => |v| try model.put(gpa, d.key, v),
                .evict => assert(model.remove(d.key)),
                .keep, .stop => {},
            };
            try self.check_floor(model.count() == 0, live, inherited, floor_loc, commit);
        }

        /// The walk hands out live updates with their post-write values, each key at most once,
        /// in location order between the inherited floor and the commit. Stop ends it. Under
        /// fixed limits it decides at most `entries` updates, each no further past the
        /// inherited floor than the earlier decisions and every skip could carry the walk.
        fn check_decisions(
            self: *const Self,
            model: *const Model,
            inherited: u64,
            commit: u64,
        ) CheckError!void {
            const fixed = self.plan.fixed();
            const all = self.decisions();
            for (all, 0..) |d, index| {
                const live = model.get(d.key) orelse return error.DecidedNotLive;
                if (!std.meta.eql(live, d.value)) return error.DecidedNotLive;
                for (all[0..index]) |earlier| {
                    if (std.meta.eql(earlier.key, d.key)) return error.DecidedTwice;
                }
                if (d.location < inherited or d.location >= commit) {
                    return error.DecidedOutsideWalk;
                }
                if (index > 0 and all[index - 1].location >= d.location) {
                    return error.DecidedOutOfOrder;
                }
                if (fixed) |fixed_limits| {
                    if (d.location - inherited > @as(u64, index) +| fixed_limits[1]) {
                        return error.DecidedPastSkips;
                    }
                }
                if (d.outcome == .stop and index + 1 != all.len) return error.ContinuedPastStop;
            }
            if (fixed) |fixed_limits| {
                if (all.len > fixed_limits[0]) return error.DecidedPastEntries;
            }
        }

        /// The floor never decreases. An empty final state records the commit's own location;
        /// otherwise the floor stays below the commit. Under fixed limits each location the walk
        /// passes costs an entry or a skip, and the floor lies at a Stop, one past the last
        /// decision when the entries ran out, or wherever spending every skip or deciding every
        /// live key left it.
        fn check_floor(
            self: *const Self,
            empty: bool,
            live: usize,
            inherited: u64,
            floor_loc: u64,
            commit: u64,
        ) CheckError!void {
            if (inherited > floor_loc) return error.FloorDecreased;
            if (empty) {
                if (floor_loc != commit) return error.EmptyFloorNotAtCommit;
                return;
            }
            if (floor_loc >= commit) return error.FloorReachedCommit;
            const entries, const skips = self.plan.fixed() orelse return;
            const all = self.decisions();
            var spent: u64 = 0;
            for (all) |d| spent += @intFromBool(d.outcome != .stop);
            const advanced = floor_loc - inherited;
            const budget = spent +| skips;
            if (advanced > budget) return error.FloorPastBudget;
            const last: ?Decided = if (all.len == 0) null else all[all.len - 1];
            if (last != null and last.?.outcome == .stop) {
                if (floor_loc != last.?.location) return error.FloorNotAtStop;
            } else if (spent == entries) {
                const expected = if (last) |l| l.location + 1 else inherited;
                if (floor_loc != expected) return error.FloorNotWhereEntriesRanOut;
            } else {
                if (advanced != budget and all.len != live) return error.WalkEndedEarly;
                if (last) |l| {
                    if (floor_loc <= l.location) return error.FloorNotPastDecisions;
                }
            }
        }

        /// Checks that this walk made the same decisions as `original`, a walk of the same batch
        /// built along another path.
        pub fn expect_same_walk(self: *const Self, original: *const Self) CheckError!void {
            if (self.count != original.count) return error.WalkDependsOnPath;
            for (self.decisions(), original.decisions()) |a, b| {
                if (!std.meta.eql(a, b)) return error.WalkDependsOnPath;
            }
        }
    };
}

const testing = std.testing;
const test_gpa = testing.allocator;

/// Keys and values of the oracle's tests: one byte, a key's live value equal to the key.
const TestRecorder = Recorder(u8, u8, 8);

fn test_replacement(seed: u8) u8 {
    return seed;
}

fn recorder(plan: Plan, decided: []const struct { u64, u8, TestRecorder.Outcome }) TestRecorder {
    var r = TestRecorder.init(plan, &test_replacement);
    for (decided) |d| {
        r.decided[r.count] = .{ .location = d[0], .key = d[1], .value = d[1], .outcome = d[2] };
        r.count += 1;
    }
    return r;
}

fn check(r: TestRecorder, keys: []const u8, inherited: u64, floor_loc: u64, commit: u64) !void {
    var model: TestRecorder.Model = .empty;
    defer model.deinit(test_gpa);
    for (keys) |key| try model.put(test_gpa, key, key);
    try r.check(test_gpa, &model, inherited, floor_loc, commit);
}

fn scripted(entries: Limit, skips: Limit) Plan {
    const choices: [4]Choice = @splat(.keep);
    return .{ .scripted = .{ .entries = entries, .skips = skips, .salt = 0, .choices = choices } };
}

const one: Limit = .{ .small = 1 };

test "floor oracle accepts legal walks" {
    // A@1 and the commit at 2 with floor 0; the batch deletes A at 3 and commits at 4.
    try check(recorder(.hold, &.{}), &.{}, 0, 4, 4);
    // A@5 lies beyond three skips from floor 0.
    const skipping: Plan = .{ .bounded = .{ .entries = one, .skips = .{ .small = 3 } } };
    try check(recorder(skipping, &.{}), &.{'A'}, 0, 3, 7);
    // A@1, B@2, and the commit at 3 with floor 0; keeping A spends the only entry.
    const keeping: Plan = .{ .bounded = .{ .entries = one, .skips = .huge } };
    try check(recorder(keeping, &.{.{ 1, 'A', .keep }}), &.{ 'A', 'B' }, 0, 2, 5);
}

test "floor oracle rejects illegal walks" {
    const bounded: Plan = .{ .bounded = .{ .entries = one, .skips = .huge } };
    const huge = scripted(.huge, .huge);
    // Evictions that empty the state still spend entries.
    const evicts = &.{ .{ 1, 'A', .evict }, .{ 2, 'B', .evict } };
    const two_evicts = recorder(scripted(one, .huge), evicts);
    try testing.expectError(error.DecidedPastEntries, check(two_evicts, &.{ 'A', 'B' }, 0, 6, 6));
    // A walk with an entry and unbounded skips decides a live key.
    const none = recorder(bounded, &.{});
    try testing.expectError(error.WalkEndedEarly, check(none, &.{ 'A', 'B' }, 0, 0, 4));
    // A walk with entries left that passes live keys without deciding them spends every skip.
    try testing.expectError(error.WalkEndedEarly, check(none, &.{ 'A', 'B' }, 0, 2, 4));
    // Evicting the last key empties the state, so the commit records its own location.
    const evict = recorder(huge, &.{.{ 1, 'A', .evict }});
    try testing.expectError(error.EmptyFloorNotAtCommit, check(evict, &.{'A'}, 0, 3, 4));
    // Stop ends the walk.
    const past_stop = recorder(huge, &.{ .{ 1, 'A', .stop }, .{ 2, 'B', .keep } });
    try testing.expectError(error.ContinuedPastStop, check(past_stop, &.{ 'A', 'B' }, 0, 3, 5));
    // Stop leaves the floor at the stopped update.
    const stop = recorder(huge, &.{.{ 2, 'A', .stop }});
    try testing.expectError(error.FloorNotAtStop, check(stop, &.{'A'}, 0, 3, 4));
}
