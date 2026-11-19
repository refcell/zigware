//! The reshare harness's collaborators (commonware `glue::dkg::tests::reshare::harness`'s
//! `DynamicProvider`, `TestRegistrar`, `ScheduleProvider`, and the shared `registrations`,
//! `processed`, and `state_syncs` maps):
//! - `Ledger`: per-participant records that outlive restarts;
//! - `Schemes(S)`: one node's epoch-scoped consensus schemes, both the orchestrator's provider
//!   and the reshare actor's registrar;
//! - `ScheduleParticipants(D)`: future committees from the `CommitteeSchedule`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");
const network = @import("../../network.zig");
const properties = @import("properties.zig");
const lookup = @import("lookup.zig");

const Epoch = consensus.Epoch;
const Key = cryptography.ed25519.PublicKey;
const Set = utils.ordered.Set(Key);
pub const Registration = properties.Registration;

/// What the properties read about each participant across its incarnations.
pub const Ledger = struct {
    gpa: Allocator,
    /// Borrowed; outlive the ledger.
    keys: []const Key,
    registrations: []std.ArrayList(Registration),
    processed: []u64,
    state_syncs: []?u64,
    /// How many startups of each participant chose state sync (commonware
    /// `state_sync_starts`).
    state_sync_starts: []u32,
    /// The participant whose application parks once it processes `height`, until it restarts
    /// (commonware `processed_hold`). Not cleared by `reset`, as commonware's is shared.
    hold: ?Hold = null,
    /// The rounds and leaders of finalized blocks, as processed (every validator's copy), up
    /// to `max_proposals`; later ones are dropped. Checks the elector the engine runs.
    proposals: [max_proposals]Proposal = undefined,
    proposal_count: usize = 0,

    pub const Hold = struct { key: Key, height: u64 };
    pub const Proposal = struct { epoch: u64, view: u64, leader: Key };
    pub const max_proposals = 512;

    pub fn init(gpa: Allocator, keys: []const Key) !Ledger {
        assert(keys.len > 0);
        const registrations = try gpa.alloc(std.ArrayList(Registration), keys.len);
        errdefer gpa.free(registrations);
        for (registrations) |*list| list.* = .empty;
        const processed = try gpa.alloc(u64, keys.len);
        errdefer gpa.free(processed);
        @memset(processed, 0);
        const state_syncs = try gpa.alloc(?u64, keys.len);
        errdefer gpa.free(state_syncs);
        @memset(state_syncs, null);
        const state_sync_starts = try gpa.alloc(u32, keys.len);
        @memset(state_sync_starts, 0);
        return .{
            .gpa = gpa,
            .keys = keys,
            .registrations = registrations,
            .processed = processed,
            .state_syncs = state_syncs,
            .state_sync_starts = state_sync_starts,
        };
    }

    pub fn deinit(self: *Ledger) void {
        for (self.registrations) |*list| list.deinit(self.gpa);
        self.gpa.free(self.registrations);
        self.gpa.free(self.processed);
        self.gpa.free(self.state_syncs);
        self.gpa.free(self.state_sync_starts);
        self.* = undefined;
    }

    /// Empties every record, for the next seed.
    pub fn reset(self: *Ledger) void {
        for (self.registrations) |*list| list.clearRetainingCapacity();
        @memset(self.processed, 0);
        @memset(self.state_syncs, null);
        @memset(self.state_sync_starts, 0);
        self.proposal_count = 0;
    }

    /// The recorded proposals, oldest first.
    pub fn proposals_of(self: *const Ledger) []const Proposal {
        assert(self.proposal_count <= max_proposals);
        return self.proposals[0..self.proposal_count];
    }

    /// Records a processed block's round and leader, while there is room.
    pub fn record_proposal(self: *Ledger, proposal: Proposal) void {
        assert(self.proposal_count <= max_proposals);
        if (self.proposal_count == max_proposals) return;
        self.proposals[self.proposal_count] = proposal;
        self.proposal_count += 1;
    }

    fn index(self: *const Ledger, key: Key) usize {
        for (self.keys, 0..) |item, at| if (item.eql(key)) return at;
        @panic("ledger key must be a participant");
    }

    pub fn registrations_of(self: *const Ledger, key: Key) []const Registration {
        return self.registrations[self.index(key)].items;
    }

    pub fn state_sync_of(self: *const Ledger, key: Key) ?u64 {
        return self.state_syncs[self.index(key)];
    }

    pub fn processed_of(self: *const Ledger, key: Key) u64 {
        return self.processed[self.index(key)];
    }

    pub fn record_registration(self: *Ledger, key: Key, registration: Registration) !void {
        try self.registrations[self.index(key)].append(self.gpa, registration);
    }

    pub fn state_sync_starts_of(self: *const Ledger, key: Key) u32 {
        return self.state_sync_starts[self.index(key)];
    }

    /// Counts a startup of `key` that chose state sync.
    pub fn record_state_sync_start(self: *Ledger, key: Key) void {
        const at = self.index(key);
        self.state_sync_starts[at] += 1;
        assert(self.state_sync_starts[at] > 0);
    }

    /// Records the height of the floor block `key` state-synced to.
    pub fn record_state_sync(self: *Ledger, key: Key, height: u64) void {
        const at = self.index(key);
        self.state_syncs[at] = height;
        assert(self.state_syncs[at] == height);
    }

    /// Whether `key`'s application parks after processing `height`.
    pub fn held(self: *const Ledger, key: Key, height: u64) bool {
        const hold = self.hold orelse return false;
        return hold.key.eql(key) and height >= hold.height;
    }

    /// Releases `key`'s hold, if it has one (commonware's release on restart).
    pub fn release_hold(self: *Ledger, key: Key) void {
        const hold = self.hold orelse return;
        if (hold.key.eql(key)) self.hold = null;
        assert(!self.held(key, std.math.maxInt(u64)));
    }

    /// Records the highest height `key` processed (commonware `App::finalized`).
    pub fn record_processed(self: *Ledger, key: Key, height: u64) void {
        const at = self.index(key);
        self.processed[at] = @max(self.processed[at], height);
        assert(self.processed[at] >= height);
    }
};

/// One node's consensus schemes by epoch (commonware `DynamicProvider` and `TestRegistrar`).
/// Registering an epoch again installs a newer scheme; earlier ones stay allocated until
/// `deinit`, so a running engine's pointer stays valid.
pub fn Schemes(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Variant = S.Variant;
        pub const PublicKey = Key;
        const Entry = struct { epoch: u64, scheme: *S };

        gpa: Allocator,
        /// Borrowed; outlive the provider.
        namespace: []const u8,
        key: Key,
        /// Borrowed; null records no registrations.
        ledger: ?*Ledger,
        entries: std.ArrayList(Entry) = .empty,

        pub fn deinit(self: *Self) void {
            for (self.entries.items) |entry| {
                entry.scheme.deinit(self.gpa);
                self.gpa.destroy(entry.scheme);
            }
            self.entries.deinit(self.gpa);
            self.* = undefined;
        }

        /// The newest scheme installed for `epoch`.
        pub fn scheme(self: *const Self, epoch: Epoch) ?*const S {
            var at = self.entries.items.len;
            while (at > 0) : (at -= 1) {
                const entry = self.entries.items[at - 1];
                if (entry.epoch == epoch.get()) return entry.scheme;
            }
            return null;
        }

        /// Installs the scheme `info` describes for `epoch` (taken) without recording it
        /// (commonware `InitialState::register_epoch_zero`).
        pub fn install(self: *Self, epoch: Epoch, info: types.SchemeInfo(Variant, Key)) !*S {
            const built = try self.gpa.create(S);
            errdefer self.gpa.destroy(built);
            built.* = try self.build(info);
            errdefer built.deinit(self.gpa);
            try self.entries.append(self.gpa, .{ .epoch = epoch.get(), .scheme = built });
            assert(self.scheme(epoch) == built);
            return built;
        }

        /// commonware `TestRegistrar::register`: install, then record the membership.
        pub fn register(
            self: *Self,
            io: Io,
            epoch: Epoch,
            info: types.SchemeInfo(Variant, Key),
        ) !void {
            _ = io;
            const installed = try self.install(epoch, info);
            const ledger = self.ledger orelse return;
            try ledger.record_registration(self.key, .{
                .epoch = epoch,
                .membership = installed.me(),
            });
        }

        /// commonware `scheme`: the signer, member, or verifier `info` describes.
        fn build(self: *Self, info: types.SchemeInfo(Variant, Key)) !S {
            const gpa = self.gpa;
            const namespace = self.namespace;
            switch (info) {
                .signer => |signer| {
                    const made = try S.signer(
                        gpa,
                        namespace,
                        signer.participants,
                        signer.sharing,
                        signer.share,
                    );
                    return made orelse @panic("share must match the sharing");
                },
                .member => |member| {
                    const made = try S.member(
                        gpa,
                        namespace,
                        member.participants,
                        member.sharing,
                        member.public_key,
                    );
                    return made orelse @panic("member must be a participant");
                },
                .verifier => |verifier| {
                    return S.verifier(gpa, namespace, verifier.participants, verifier.sharing);
                },
            }
        }
    };
}

/// Each epoch's players from the schedule, with the directory `D.of` builds for `network`
/// (commonware `ScheduleProvider`).
pub fn ScheduleParticipants(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = Key;
        pub const Directory = D;

        schedule: properties.CommitteeSchedule,
        network: lookup.Network,

        pub fn participants(self: *Self, io: Io, gpa: Allocator, epoch: Epoch) !Set {
            _ = io;
            const players = try self.schedule.players(gpa, epoch.get());
            assert(players.len() > 0);
            return players;
        }

        pub fn directory(self: *Self, io: Io, gpa: Allocator, epoch: Epoch, peers: Set) !D {
            _ = .{ io, epoch };
            const built = try D.of(gpa, self.network, self.schedule.participants, peers);
            assert(built.matches(peers));
            return built;
        }
    };
}
