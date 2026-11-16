//! The durable startup decision between peer state sync and recovery from marshal (commonware
//! `glue/src/stateful/actor/syncer/plan.rs` and `SyncState` from `syncer/mod.rs`).
//!
//! Startup: load a `SyncPlan` with `init`; if `should_sync` holds, select a finalized floor and
//! persist it with `set_floor`; start marshal from `marshal_start` and pass the same plan to
//! `Stateful`. A persisted floor makes every startup run state sync until completion is
//! recorded, which disables peer state sync for good.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");
const storage = @import("storage");
const utils = @import("utils");

const Height = consensus.types.Height;
const metadata_suffix = "state_sync_metadata";
const Key = utils.sequence.FixedBytes(1);
const state_key: Key = .{ .bytes = .{0xC0} };

/// The tag byte of a persisted `SyncState`.
pub const SyncStateTag = enum(u8) { in_progress = 0, complete = 1 };

/// Durable state sync progress, for scheme `S` and commitment `C`.
pub fn SyncState(comptime S: type, comptime C: type) type {
    return union(SyncStateTag) {
        const Self = @This();
        pub const Finalization = consensus.simplex.types.Finalization(S, C);
        pub const Cfg = Finalization.Cfg;

        /// A floor is selected and state sync has not completed.
        in_progress: Finalization,
        /// Completion is recorded at this height, and peer state sync never runs again.
        complete: Height,

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_byte(@backingInt(std.meta.activeTag(self)));
            switch (self) {
                .in_progress => |finalization| finalization.write(writer),
                .complete => |height| height.write(writer),
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .in_progress => |finalization| finalization.encode_size(),
                .complete => |height| height.encode_size(),
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            return switch (try reader.read_byte()) {
                0 => .{ .in_progress = try Finalization.read(gpa, reader, cfg) },
                1 => .{ .complete = try Height.read(gpa, reader, {}) },
                else => error.InvalidEnum,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .in_progress => |*finalization| finalization.deinit(gpa),
                .complete => {},
            }
            self.* = undefined;
        }
    };
}

/// The persisted plan, for scheme `S` and marshal variant `V`.
pub fn SyncPlan(comptime S: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const State = SyncState(S, V.Commitment);
        pub const Finalization = State.Finalization;
        const Store = storage.metadata.Metadata(Key, State);
        pub const Error = Store.Error;

        gpa: Allocator,
        metadata: Store,

        /// Loads the state sync metadata stored under `partition_prefix`, creating it if needed.
        /// A node that cannot read it cannot choose a startup path, so callers stop on error.
        pub fn init(env: anytype, partition_prefix: []const u8) !Self {
            const parts = [_][]const u8{ partition_prefix, metadata_suffix };
            const partition = try std.mem.concat(env.gpa, u8, &parts);
            defer env.gpa.free(partition);
            const metadata = try Store.init(env.gpa, env.storage, .{
                .partition = partition,
                .codec_config = S.certificate_codec_config_unbounded(),
            });
            return .{ .gpa = env.gpa, .metadata = metadata };
        }

        pub fn deinit(self: *Self) void {
            self.metadata.deinit();
            self.* = undefined;
        }

        /// Whether peer state sync can still run: false once completion is recorded, and then
        /// `set_floor` has no effect.
        pub fn may_sync(self: *const Self) bool {
            return self.completed() == null;
        }

        /// The recorded completion height, if any.
        pub fn completed(self: *const Self) ?Height {
            const state = self.metadata.get(state_key) orelse return null;
            return switch (state.*) {
                .complete => |height| height,
                .in_progress => null,
            };
        }

        /// The persisted state sync floor, if any. It persists from `set_floor` until state
        /// sync completes, across restarts.
        pub fn floor(self: *const Self) ?*const Finalization {
            const state = self.metadata.get(state_key) orelse return null;
            return switch (state.*) {
                .in_progress => |*finalization| finalization,
                .complete => null,
            };
        }

        /// Persists a copy of `finalization` as the state sync floor. Has no effect once
        /// completion is recorded, and ignores a floor not at a later round than the persisted
        /// one, so a lagging selection cannot move it backward.
        pub fn set_floor(self: *Self, finalization: *const Finalization) Error!void {
            if (!self.may_sync()) return;
            if (self.floor()) |persisted| {
                if (finalization.round().order(persisted.round()) != .gt) return;
            }
            const copy = try finalization.clone(self.gpa);
            try self.metadata.put_sync(state_key, .{ .in_progress = copy });
            assert(self.floor() != null);
        }

        /// Records completion at `height`, which permanently disables peer state sync.
        /// `height` may not be below a recorded completion height.
        pub fn set_completed(self: *Self, height: Height) Error!void {
            if (self.completed()) |existing| {
                // commonware panics: completion cannot move backward.
                assert(height.order(existing) != .lt);
            }
            try self.metadata.put_sync(state_key, .{ .complete = height });
            assert(self.completed().?.get() == height.get());
        }

        /// Marshal's startup anchor: the persisted floor (a copy the caller frees), or genesis.
        pub fn marshal_start(
            self: *const Self,
            comptime B: type,
            genesis: B,
        ) Allocator.Error!consensus.marshal.config.Start(S, V.Commitment, B) {
            const persisted = self.floor() orelse return .{ .genesis = genesis };
            return .{ .floor = try persisted.clone(self.gpa) };
        }

        /// Whether this startup should run peer state sync: when it may, and either it was
        /// `requested` or a floor is persisted.
        pub fn should_sync(self: *const Self, requested: bool) bool {
            return self.may_sync() and (requested or self.floor() != null);
        }
    };
}
