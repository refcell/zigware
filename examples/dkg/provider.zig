//! The per-epoch certificate schemes (commonware `examples/dkg/src/types.rs`'s
//! `DynamicProvider`, `scheme`, and `Registrar`): the reshare actor registers each epoch's
//! scheme as its ceremony completes, and marshal and the orchestrator read them by epoch.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const types = @import("types.zig");

const Scheme = types.Scheme;
const Epoch = types.Epoch;
const Scoped = zigware.cryptography.certificate.Scoped(Scheme);
pub const SchemeInfo = zigware.glue.dkg.types.SchemeInfo(types.MinSig, types.PublicKey);

/// Builds the scheme `info` describes, taking ownership of it (commonware `scheme`).
pub fn scheme(gpa: Allocator, info: SchemeInfo) !Scheme {
    const namespace = types.namespace;
    return switch (info) {
        .verifier => |v| try Scheme.verifier(gpa, namespace, v.participants, v.sharing),
        .member => |m| (try Scheme.member(
            gpa,
            namespace,
            m.participants,
            m.sharing,
            m.public_key,
        )) orelse @panic("registered member must be a participant"),
        .signer => |s| (try Scheme.signer(
            gpa,
            namespace,
            s.participants,
            s.sharing,
            s.share,
        )) orelse @panic("registered share must match participant set"),
    };
}

/// Certificate provider whose per-epoch schemes are registered as ceremonies complete. A
/// later registration for an epoch replaces the earlier one (commonware's `insert`); every
/// registered scheme stays at its address until `deinit`, so readers may hold its pointer
/// (commonware's `Arc`).
pub const DynamicProvider = struct {
    gpa: Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    schemes: std.AutoHashMapUnmanaged(u64, *Scheme) = .empty,
    /// Replaced schemes, freed at `deinit`.
    retired: std.ArrayList(*Scheme) = .empty,

    pub fn init(gpa: Allocator, io: Io) DynamicProvider {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *DynamicProvider) void {
        var values = self.schemes.valueIterator();
        while (values.next()) |entry| {
            entry.*.deinit(self.gpa);
            self.gpa.destroy(entry.*);
        }
        self.schemes.deinit(self.gpa);
        for (self.retired.items) |entry| {
            entry.deinit(self.gpa);
            self.gpa.destroy(entry);
        }
        self.retired.deinit(self.gpa);
        self.* = undefined;
    }

    /// Registers `epoch`'s scheme (taken), replacing any registered before.
    pub fn register(self: *DynamicProvider, epoch: Epoch, value: Scheme) Allocator.Error!void {
        var owned = value;
        errdefer owned.deinit(self.gpa);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.retired.ensureUnusedCapacity(self.gpa, 1);
        const entry = try self.schemes.getOrPut(self.gpa, epoch.get());
        const stored = self.gpa.create(Scheme) catch |err| {
            if (!entry.found_existing) self.schemes.removeByPtr(entry.key_ptr);
            return err;
        };
        stored.* = owned;
        if (entry.found_existing) self.retired.appendAssumeCapacity(entry.value_ptr.*);
        entry.value_ptr.* = stored;
        assert(self.schemes.get(epoch.get()).? == stored);
    }

    pub fn scheme(self: *DynamicProvider, epoch: Epoch) ?*const Scheme {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.schemes.get(epoch.get());
    }

    pub fn scoped(self: *DynamicProvider, epoch: Epoch) ?Scoped {
        const found = self.scheme(epoch) orelse return null;
        return Scoped.scheme(found);
    }
};

/// Registers reshare outputs with a `DynamicProvider` (commonware `Registrar`).
pub const Registrar = struct {
    pub const Variant = types.MinSig;
    pub const PublicKey = types.PublicKey;

    provider: *DynamicProvider,

    pub fn register(self: *Registrar, io: Io, epoch: Epoch, info: SchemeInfo) !void {
        _ = io;
        const built = try scheme(self.provider.gpa, info);
        try self.provider.register(epoch, built);
        assert(self.provider.scheme(epoch) != null);
    }
};
