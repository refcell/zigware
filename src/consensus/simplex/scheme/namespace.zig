//! Per-subject signing namespaces (commonware `simplex::scheme::Namespace`): the application
//! namespace with `_NOTARIZE`, `_NULLIFY`, `_FINALIZE`, or `_SEED` appended, so a signature
//! over one kind of subject never verifies as another.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const notarize_suffix = "_NOTARIZE";
pub const nullify_suffix = "_NULLIFY";
pub const finalize_suffix = "_FINALIZE";
pub const seed_suffix = "_SEED";

pub const Namespace = struct {
    notarize: []u8,
    nullify: []u8,
    finalize: []u8,
    seed: []u8,

    /// `certificate::Namespace::derive`.
    pub fn derive(gpa: Allocator, namespace: []const u8) Allocator.Error!Namespace {
        const notarize = try std.mem.concat(gpa, u8, &.{ namespace, notarize_suffix });
        errdefer gpa.free(notarize);
        const nullify = try std.mem.concat(gpa, u8, &.{ namespace, nullify_suffix });
        errdefer gpa.free(nullify);
        const finalize = try std.mem.concat(gpa, u8, &.{ namespace, finalize_suffix });
        errdefer gpa.free(finalize);
        const seed = try std.mem.concat(gpa, u8, &.{ namespace, seed_suffix });
        const result: Namespace = .{
            .notarize = notarize,
            .nullify = nullify,
            .finalize = finalize,
            .seed = seed,
        };
        assert(result.notarize.len == namespace.len + notarize_suffix.len);
        assert(result.seed.len == namespace.len + seed_suffix.len);
        return result;
    }

    pub fn clone(self: *const Namespace, gpa: Allocator) Allocator.Error!Namespace {
        assert(std.mem.endsWith(u8, self.notarize, notarize_suffix));
        const base = self.notarize[0 .. self.notarize.len - notarize_suffix.len];
        const result = try derive(gpa, base);
        assert(std.mem.eql(u8, result.seed, self.seed));
        return result;
    }

    pub fn deinit(self: *Namespace, gpa: Allocator) void {
        assert(self.notarize.len >= notarize_suffix.len);
        assert(self.seed.len >= seed_suffix.len);
        gpa.free(self.notarize);
        gpa.free(self.nullify);
        gpa.free(self.finalize);
        gpa.free(self.seed);
        self.* = undefined;
    }

    /// The namespace a subject (`types.Subject(D)`) signs under.
    pub fn of(self: *const Namespace, subject: anytype) []const u8 {
        const result: []const u8 = switch (subject) {
            .notarize => self.notarize,
            .nullify => self.nullify,
            .finalize => self.finalize,
        };
        assert(result.len > 0);
        return result;
    }
};

test "namespaces append the subject suffix" {
    const gpa = std.testing.allocator;
    var namespace: Namespace = try .derive(gpa, "app");
    defer namespace.deinit(gpa);
    try std.testing.expectEqualStrings("app_NOTARIZE", namespace.notarize);
    try std.testing.expectEqualStrings("app_NULLIFY", namespace.nullify);
    try std.testing.expectEqualStrings("app_FINALIZE", namespace.finalize);
    try std.testing.expectEqualStrings("app_SEED", namespace.seed);
    var copy = try namespace.clone(gpa);
    defer copy.deinit(gpa);
    try std.testing.expectEqualStrings(namespace.finalize, copy.finalize);
}
