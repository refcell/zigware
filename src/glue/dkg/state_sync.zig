//! Durable startup material for DKG actors after application state sync (commonware
//! `glue::dkg::state_sync`).
//!
//! A state-synced node may not have the finalized boundary block that introduced its active
//! epoch. `Plan` persists that public material before the actors start and shares one recovery
//! decision between the reshare and orchestrator actors. A later startup removes the record once
//! marshal's recovered epoch advances beyond the synced epoch.
//!
//! Rust shares a `Plan` through an `Arc` and clones it into each actor; here the owner keeps one
//! `Plan` and passes both actors a pointer to it. Commonware panics when provided material is
//! invalid or storage fails; `init` and `resolve` return those as errors instead.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const types = @import("types.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;
const FixedEpocher = consensus.types.FixedEpocher;
const Processed = consensus.marshal.core.Processed;
const ModeVersion = cryptography.bls12381.primitives.sharing.ModeVersion;
const Storage = runtime.storage.Storage;
const Key = utils.sequence.FixedBytes(1);

const state_sync_key: Key = .init(.{0});
const state_sync_suffix = "_dkg_state_sync";

/// Storage settings for a DKG state-sync recovery plan.
pub const Config = struct {
    /// Stable node-wide partition prefix.
    partition_prefix: []const u8,
    /// Maximum entries accepted in each persisted participant set.
    max_participants: u32,
    /// Maximum sharing mode version accepted in persisted epoch information.
    max_supported_mode: ModeVersion,

    fn info_cfg(config: Config) types.InfoCfg {
        assert(config.max_participants > 0);
        return .{
            .max_participants = config.max_participants,
            .max_supported_mode = config.max_supported_mode,
        };
    }
};

/// Public material needed to start DKG actors in a state-synced epoch. The epoch info replaces
/// the boundary block that may be absent locally. The floor is the finalized block selected for
/// application state sync and gives marshal a block from which to resume delivery. The info
/// must describe the epoch containing the floor.
pub fn StateSync(comptime S: type, comptime D: type, comptime V: type, comptime Dir: type) type {
    return struct {
        const Self = @This();
        pub const Info = types.EpochInfo(V, S.PublicKey, Dir);
        pub const Floor = consensus.simplex.types.Finalization(S, D);
        pub const Cfg = struct { info: types.InfoCfg, certificate: codec.Cfg(S.Certificate) };

        /// Public information for the epoch containing the state-sync floor.
        info: Info,
        /// Finalized floor selected for application state sync.
        floor: Floor,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.info.deinit(gpa);
            self.floor.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var info = try self.info.clone(gpa);
            errdefer info.deinit(gpa);
            const floor = try self.floor.clone(gpa);
            return .{ .info = info, .floor = floor };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.info.eql(b.info) and a.floor.proposal.eql(b.floor.proposal) and
                certificate_eql(S.Certificate, &a.floor.certificate, &b.floor.certificate);
        }

        /// Whether the artifact and the floor are in the same epoch.
        pub fn epochs_match(self: Self) bool {
            return self.info.epoch == self.floor.epoch();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.info.write(writer);
            self.floor.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.info.encode_size() + self.floor.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            var info = try Info.read(gpa, reader, cfg.info);
            errdefer info.deinit(gpa);
            const floor = try Floor.read(gpa, reader, cfg.certificate);
            return .{ .info = info, .floor = floor };
        }
    };
}

/// `a.eql(b)` for certificate types whose `eql` takes the other side by value or by pointer
/// (simplex's `Finalization.eql` assumes the pointer form).
fn certificate_eql(comptime C: type, a: *const C, b: *const C) bool {
    const Other = @typeInfo(@TypeOf(C.eql)).@"fn".param_types[1].?;
    if (comptime @typeInfo(Other) == .pointer) return a.eql(b);
    return a.eql(b.*);
}

/// The epoch containing the first height after `processed`. Panics if `epocher` does not know
/// that height (commonware `recovered_epoch`).
pub fn recovered_epoch(processed: Processed, epocher: FixedEpocher) Epoch {
    const next = processed.height().next();
    const info = epocher.containing(next) orelse @panic("epocher must know recovered height");
    return info.epoch;
}

/// Shared startup recovery plan for DKG actors. Initialize one plan after obtaining optional
/// application state-sync material and before starting either DKG actor; both actors observe
/// the same material while using one durable partition. Use `disabled` for deployments that
/// never use application state sync.
pub fn Plan(comptime S: type, comptime D: type, comptime V: type, comptime Dir: type) type {
    return struct {
        const Self = @This();
        pub const Material = StateSync(S, D, V, Dir);
        const Store = storage.metadata.Metadata(Key, Material);

        pub const InitError = Store.Error || error{
            /// The artifact and the floor are in different epochs.
            EpochMismatch,
            /// Provided material does not satisfy the configured codec limits.
            InvalidMaterial,
        };

        const Pending = struct {
            candidate: ?Material,
            partition: []u8,
            info_cfg: types.InfoCfg,
        };

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        state: union(enum) { pending: Pending, resolved: ?Material },

        /// Initializes and durably records a recovery candidate, taking ownership of `provided`.
        /// Provided material replaces any existing record and is durable when this returns.
        /// Without provided material, the existing record (if any) is loaded.
        pub fn init(
            gpa: Allocator,
            io: Io,
            store_storage: Storage,
            config: Config,
            provided: ?Material,
        ) InitError!Self {
            var owned = provided;
            errdefer if (owned) |*material| material.deinit(gpa);
            const info_cfg = config.info_cfg();
            if (owned) |material| try check_provided(gpa, material, info_cfg);
            const partition = try std.mem.concat(gpa, u8, &.{
                config.partition_prefix,
                state_sync_suffix,
            });
            errdefer gpa.free(partition);
            var store = try open_store(gpa, store_storage, partition, info_cfg);
            defer store.deinit();
            if (owned) |material| {
                owned = null;
                if (try store.put(state_sync_key, material)) |previous| {
                    var stale = previous;
                    stale.deinit(gpa);
                }
                try store.sync();
            }
            const candidate: ?Material = if (store.get(state_sync_key)) |stored|
                try stored.clone(gpa)
            else
                null;
            if (candidate) |material| {
                if (!material.epochs_match()) {
                    var mismatched = material;
                    mismatched.deinit(gpa);
                    return error.EpochMismatch;
                }
            }
            return .{ .gpa = gpa, .io = io, .state = .{ .pending = .{
                .candidate = candidate,
                .partition = partition,
                .info_cfg = info_cfg,
            } } };
        }

        /// A plan that never accesses storage and always resolves to none.
        pub fn disabled(gpa: Allocator, io: Io) Self {
            return .{ .gpa = gpa, .io = io, .state = .{ .resolved = null } };
        }

        pub fn deinit(self: *Self) void {
            switch (self.state) {
                .pending => |*pending| {
                    if (pending.candidate) |*material| material.deinit(self.gpa);
                    self.gpa.free(pending.partition);
                },
                .resolved => |*resolved| if (resolved.*) |*material| material.deinit(self.gpa),
            }
            self.* = undefined;
        }

        /// The persisted material if `recovered` is null or not past the floor's epoch, and
        /// null if there is none; otherwise deletes the material and returns null. The first
        /// call decides the result for every caller. The result is a copy the caller owns.
        pub fn resolve(
            self: *Self,
            store_storage: Storage,
            recovered: ?Epoch,
        ) (Store.Error || Io.Cancelable)!?Material {
            try self.mutex.lock(self.io);
            defer self.mutex.unlock(self.io);
            switch (self.state) {
                .resolved => |resolved| return if (resolved) |material|
                    try material.clone(self.gpa)
                else
                    null,
                .pending => {},
            }
            const pending = self.state.pending;
            const candidate = pending.candidate orelse return self.settle(null);
            const floor_epoch = candidate.floor.epoch();
            if (recovered == null or recovered.?.get() <= floor_epoch.get()) {
                const copy = try candidate.clone(self.gpa);
                _ = self.settle(candidate);
                return copy;
            }
            const gpa = self.gpa;
            var store = try open_store(gpa, store_storage, pending.partition, pending.info_cfg);
            defer store.deinit();
            if (store.remove(state_sync_key)) |removed| {
                var stale = removed;
                stale.deinit(self.gpa);
            }
            try store.sync();
            var stale = candidate;
            stale.deinit(self.gpa);
            return self.settle(null);
        }

        /// Records the resolution, taking ownership of `material`; returns null.
        fn settle(self: *Self, material: ?Material) ?Material {
            assert(self.state == .pending);
            self.gpa.free(self.state.pending.partition);
            self.state = .{ .resolved = material };
            assert(self.state == .resolved);
            return null;
        }

        fn open_store(
            gpa: Allocator,
            store_storage: Storage,
            partition: []const u8,
            info_cfg: types.InfoCfg,
        ) Store.Error!Store {
            return Store.init(gpa, store_storage, .{
                .partition = partition,
                .codec_config = .{
                    .info = info_cfg,
                    .certificate = S.certificate_codec_config_unbounded(),
                },
            });
        }

        fn check_provided(gpa: Allocator, material: Material, info_cfg: types.InfoCfg) !void {
            if (!material.epochs_match()) return error.EpochMismatch;
            const bytes = try codec.encode(Material, gpa, material);
            defer gpa.free(bytes);
            const cfg: Material.Cfg = .{
                .info = info_cfg,
                .certificate = S.certificate_codec_config_unbounded(),
            };
            var decoded = codec.decode_cfg(Material, gpa, bytes, cfg) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidMaterial,
            };
            decoded.deinit(gpa);
        }
    };
}

test {
    _ = @import("state_sync_test.zig");
}
