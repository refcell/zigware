//! Signature namespaces of one deployment (commonware `bajillion/namespace.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");

/// Suffix of the namespace in which senders sign their states.
const state_suffix = "_COMMONWARE_CLEARING_BAJILLION_STATE";
/// Suffix of the namespace in which the operator countersigns states.
const acknowledgement_suffix = "_COMMONWARE_CLEARING_BAJILLION_ACKNOWLEDGEMENT";
/// Suffix of the namespace in which accounts sign soft withdrawals.
const withdrawal_suffix = "_COMMONWARE_CLEARING_BAJILLION_WITHDRAWAL";
/// Suffix of the namespace in which the operator signs closes.
const close_suffix = "_COMMONWARE_CLEARING_BAJILLION_CLOSE";
/// Suffix of the namespace in which validators certify summaries.
const summary_suffix = "_COMMONWARE_CLEARING_BAJILLION_SUMMARY";

const suffixes = [_][]const u8{
    state_suffix,
    acknowledgement_suffix,
    withdrawal_suffix,
    close_suffix,
    summary_suffix,
};

/// Signature namespaces of one deployment.
///
/// Each kind of signed message has its own namespace, so a signature on one kind never verifies
/// as another. All namespaces derive from the deployment's namespace with `union_unique`, so
/// deployments with different namespaces cannot replay each other's signatures. The five
/// namespaces share one allocation, owned by the value.
pub const Namespace = struct {
    /// Namespace in which senders sign their states.
    state: []const u8,
    /// Namespace in which the operator countersigns states.
    acknowledgement: []const u8,
    /// Namespace in which accounts sign soft withdrawals.
    withdrawal: []const u8,
    /// Namespace in which the operator signs closes.
    close: []const u8,
    /// Namespace in which validators certify summaries.
    summary: []const u8,
    /// The allocation holding all five namespaces.
    buffer: []u8,

    /// Derives the signature namespaces of the deployment with namespace `base`.
    pub fn init(gpa: Allocator, base: []const u8) Allocator.Error!Namespace {
        const prefix_size = codec.encode_size(usize, base.len);
        var total: usize = 0;
        for (suffixes) |suffix| total += prefix_size + base.len + suffix.len;
        const buffer = try gpa.alloc(u8, total);
        var parts: [suffixes.len][]const u8 = undefined;
        var offset: usize = 0;
        for (suffixes, &parts) |suffix, *part| {
            const size = prefix_size + base.len + suffix.len;
            var writer = codec.Writer.init(buffer[offset..][0..size]);
            codec.write(usize, base.len, &writer);
            writer.write_bytes(base);
            writer.write_bytes(suffix);
            assert(writer.written().len == size);
            part.* = buffer[offset..][0..size];
            offset += size;
        }
        assert(offset == total);
        return .{
            .state = parts[0],
            .acknowledgement = parts[1],
            .withdrawal = parts[2],
            .close = parts[3],
            .summary = parts[4],
            .buffer = buffer,
        };
    }

    /// `certificate::Namespace::derive`.
    pub fn derive(gpa: Allocator, base: []const u8) Allocator.Error!Namespace {
        return init(gpa, base);
    }

    pub fn clone(self: *const Namespace, gpa: Allocator) Allocator.Error!Namespace {
        const buffer = try gpa.dupe(u8, self.buffer);
        const start = @intFromPtr(self.buffer.ptr);
        const rebase = struct {
            fn part(new: []u8, old_start: usize, slice: []const u8) []const u8 {
                const offset = @intFromPtr(slice.ptr) - old_start;
                return new[offset..][0..slice.len];
            }
        }.part;
        const result: Namespace = .{
            .state = rebase(buffer, start, self.state),
            .acknowledgement = rebase(buffer, start, self.acknowledgement),
            .withdrawal = rebase(buffer, start, self.withdrawal),
            .close = rebase(buffer, start, self.close),
            .summary = rebase(buffer, start, self.summary),
            .buffer = buffer,
        };
        assert(result.eql(self));
        return result;
    }

    pub fn deinit(self: *Namespace, gpa: Allocator) void {
        gpa.free(self.buffer);
        self.* = undefined;
    }

    pub fn eql(self: *const Namespace, other: *const Namespace) bool {
        return std.mem.eql(u8, self.state, other.state) and
            std.mem.eql(u8, self.acknowledgement, other.acknowledgement) and
            std.mem.eql(u8, self.withdrawal, other.withdrawal) and
            std.mem.eql(u8, self.close, other.close) and
            std.mem.eql(u8, self.summary, other.summary);
    }
};

test "namespace: each kind derives from the deployment's namespace" {
    const gpa = std.testing.allocator;
    var namespace = try Namespace.init(gpa, "deployment");
    defer namespace.deinit(gpa);
    var copy = try namespace.clone(gpa);
    defer copy.deinit(gpa);
    try std.testing.expect(copy.eql(&namespace));
    const parts = [_][]const u8{
        namespace.state,
        namespace.acknowledgement,
        namespace.withdrawal,
        namespace.close,
        namespace.summary,
    };
    for (parts, suffixes) |part, suffix| {
        try std.testing.expectEqual(@as(u8, 10), part[0]);
        try std.testing.expectEqualStrings("deployment", part[1..11]);
        try std.testing.expectEqualStrings(suffix, part[11..]);
    }
    var other = try Namespace.init(gpa, "other");
    defer other.deinit(gpa);
    try std.testing.expect(!other.eql(&namespace));
}
