//! A type-erased ancestry (commonware `marshal::ancestry::BoxedAncestry`).
//!
//! The processor hands the application ancestries of several types: marshal's stream with the
//! request's block put back in front (`Prefixed`), a replay's `AncestorStream`, or a bounded
//! list. A flight stores whichever one started it, so `Boxed(B)` owns any ancestry of blocks
//! `B` behind one pointer and a table of its operations.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const consensus = @import("consensus");

const ancestry_mod = consensus.marshal.ancestry;

pub fn Boxed(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;
        const D = broadcast.Digested(B);

        gpa: Allocator,
        pointer: *anyopaque,
        vtable: *const VTable,

        const VTable = struct {
            peek: *const fn (*const anyopaque) ?*const D,
            next: *const fn (*anyopaque) anyerror!?D,
            clone: *const fn (Allocator, *const anyopaque) anyerror!*anyopaque,
            destroy: *const fn (Allocator, *anyopaque) void,
        };

        fn Erased(comptime A: type) type {
            return struct {
                fn cast(pointer: *anyopaque) *A {
                    return @ptrCast(@alignCast(pointer));
                }

                fn cast_const(pointer: *const anyopaque) *const A {
                    return @ptrCast(@alignCast(pointer));
                }

                fn peek_erased(pointer: *const anyopaque) ?*const D {
                    return cast_const(pointer).peek();
                }

                fn next_erased(pointer: *anyopaque) anyerror!?D {
                    return cast(pointer).next();
                }

                fn clone_erased(gpa: Allocator, pointer: *const anyopaque) anyerror!*anyopaque {
                    const copy = try gpa.create(A);
                    errdefer gpa.destroy(copy);
                    copy.* = try cast_const(pointer).clone();
                    return copy;
                }

                fn destroy_erased(gpa: Allocator, pointer: *anyopaque) void {
                    const inner = cast(pointer);
                    inner.deinit();
                    gpa.destroy(inner);
                }

                const vtable: VTable = .{
                    .peek = peek_erased,
                    .next = next_erased,
                    .clone = clone_erased,
                    .destroy = destroy_erased,
                };
            };
        }

        /// Boxes `inner` (taken, also on error: an unboxed ancestry is released).
        pub fn init(gpa: Allocator, inner: anytype) Allocator.Error!Self {
            const A = @TypeOf(inner);
            comptime ancestry_mod.assert_ancestry(A);
            comptime assert(A.Block == B);
            var owned = inner;
            const pointer = gpa.create(A) catch |err| {
                owned.deinit();
                return err;
            };
            pointer.* = owned;
            return .{ .gpa = gpa, .pointer = pointer, .vtable = &Erased(A).vtable };
        }

        /// A box over the `blocks` handles (taken), newest first.
        pub fn from_blocks(gpa: Allocator, blocks: []const D) Allocator.Error!Self {
            const bounded = ancestry_mod.from_iter(B, gpa, blocks) catch |err| {
                for (blocks) |block| block.discard();
                return err;
            };
            return init(gpa, bounded);
        }

        pub fn deinit(self: *Self) void {
            self.vtable.destroy(self.gpa, self.pointer);
            self.* = undefined;
        }

        /// The next block, if already available.
        pub fn peek(self: *const Self) ?*const D {
            return self.vtable.peek(self.pointer);
        }

        /// The next block (owned by the caller), waiting for a pending fetch.
        pub fn next(self: *Self) anyerror!?D {
            return self.vtable.next(self.pointer);
        }

        /// An independent ancestry at the same position.
        pub fn clone(self: *const Self) anyerror!Self {
            const pointer = try self.vtable.clone(self.gpa, self.pointer);
            return .{ .gpa = self.gpa, .pointer = pointer, .vtable = self.vtable };
        }
    };
}
