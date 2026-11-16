//! The storage contract of an authenticated journal (commonware's `journal/authenticated.rs`:
//! `Backing`, `BackingRecovery`, `Stored`, and `init_sync`).
//!
//! An authenticated journal keeps a contiguous journal of items alongside a Merkle structure
//! whose leaf `i` is item `i`. The journal backing it must support initialization-owned
//! recovery, so the Merkle structure can select the retained prefix before the journal is
//! published. The authenticated `Journal` itself, over storage-merkle's persisted Merkle, is
//! in `authenticated_journal.zig`.
//!
//! # The backing contract
//!
//! Commonware's traits are a comptime contract here (`assert_backing`). A backing journal `J`
//! declares:
//!
//! - `BackingConfig` and `BackingRecovery` types;
//! - `recover(gpa, storage, cfg, ?max_size) BackingRecovery`: open recovery storage for an
//!   optional exclusive item end (`ItemPruned` when `max_size` is below the retained start);
//! - `clear(gpa, storage, cfg, size) BackingRecovery`: recovery storage reset to an empty
//!   journal at `size`, discarding stored items unread (`SizeOverflow` for `u64::MAX`);
//! - `span(gpa, storage, cfg) Bounds`: the positions stored items may occupy, without reading
//!   them; a pending reset yields an empty span at its target.
//!
//! Its recovery declares `Item`, `get_bounds()`, `read(position)`, `reset(size)`,
//! `finish(size) J` (durably retain at most `size` items and publish; consumes the recovery,
//! also on error), and `deinit()`. Finishing consumes the recovery: a live journal cannot
//! regain recovery access.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const contiguous = @import("contiguous/mod.zig");

const Storage = runtime.storage.Storage;
const Bounds = contiguous.Bounds;

/// The authenticated journal (`authenticated_journal.zig`).
pub const Journal = @import("authenticated_journal.zig").Journal;

/// Check at comptime that `J` satisfies the backing contract.
pub fn assert_backing(comptime J: type) void {
    comptime {
        @setEvalBranchQuota(10_000);
        assert(@hasDecl(J, "BackingConfig"));
        assert(@hasDecl(J, "BackingRecovery"));
        assert(@hasDecl(J, "recover"));
        assert(@hasDecl(J, "clear"));
        assert(@hasDecl(J, "span"));
        const R = J.BackingRecovery;
        assert(@hasDecl(R, "Item"));
        for ([_][]const u8{ "get_bounds", "read", "reset", "finish", "deinit" }) |name| {
            assert(@hasDecl(R, name));
        }
    }
}

/// The exclusive end just after the latest retained item below `ceiling` that satisfies
/// `predicate(context, item)` (`BackingRecovery::last_matching`). With no match, an unpruned
/// journal selects genesis (0); a pruned one fails with `ItemPruned`, as does a ceiling below
/// the retained start.
pub fn last_matching(
    recovery: anytype,
    ceiling: u64,
    context: anytype,
    comptime predicate: fn (@TypeOf(context), @TypeOf(recovery.*).Item) bool,
) !u64 {
    const bounds = recovery.get_bounds();
    // A ceiling below retained history cannot select a supported prefix.
    if (ceiling < bounds.start) return error.ItemPruned;
    // Search backward and return the end immediately after the latest match.
    var end = @min(bounds.end, ceiling);
    while (end > bounds.start) : (end -= 1) {
        const item = try recovery.read(end - 1);
        defer codec.free(@TypeOf(item), recovery.gpa, item);
        if (predicate(context, item)) return end;
    }
    assert(end == bounds.start);
    // Only an unpruned journal can establish genesis when no retained item matches.
    if (bounds.start != 0) return error.ItemPruned;
    return 0;
}

/// Whether `span` contains `position` or is empty exactly at it.
pub fn covers(span: Bounds, position: u64) bool {
    assert(span.start <= span.end);
    return position == span.start or (position >= span.start and position < span.end);
}

/// A backing journal's storage, as `Stored(J).open` leaves it.
pub fn Stored(comptime J: type) type {
    assert_backing(J);
    return union(enum) {
        const Self = @This();

        /// Recovery opened bounded at the requested end.
        opened: J.BackingRecovery,
        /// Storage whose span cannot hold the requested position, left unopened.
        unopened,

        /// Open recovery bounded at `max_size` when the span contains `position` or is empty
        /// exactly at it; otherwise leave the storage unopened.
        pub fn open(
            gpa: Allocator,
            storage: Storage,
            cfg: J.BackingConfig,
            position: u64,
            max_size: u64,
        ) !Self {
            const span = try J.span(gpa, storage, cfg);
            if (!covers(span, position)) return .unopened;
            return .{ .opened = try J.recover(gpa, storage, cfg, max_size) };
        }
    };
}

/// Recover the part of local storage useful for state sync of `range`, or reset an unusable
/// local range, then publish the journal pruned below `range.start`.
pub fn init_sync(
    comptime J: type,
    gpa: Allocator,
    storage: Storage,
    cfg: J.BackingConfig,
    range: Bounds,
) !J {
    assert_backing(J);
    assert(range.start < range.end); // The range must not be empty.
    // Storage whose span cannot hold the sync start is cleared without reading stored items.
    // The span end reflects blob capacity, which can overstate the recovered end when the tail
    // is short or has a gap, so an opened prefix that does not cover the start is reset.
    var pending = switch (try Stored(J).open(gpa, storage, cfg, range.start, range.end)) {
        .opened => |opened| opened,
        .unopened => try J.clear(gpa, storage, cfg, range.start),
    };
    if (!covers(pending.get_bounds(), range.start)) {
        pending.reset(range.start) catch |err| {
            pending.deinit();
            return err;
        };
    }
    // Publish the retained prefix before pruning complete sections below the sync start.
    var journal = try pending.finish(range.end);
    errdefer journal.deinit();
    _ = try journal.prune(range.start);
    assert(journal.size() >= range.start);
    return journal;
}

test {
    _ = @import("authenticated_test.zig");
    _ = @import("authenticated_journal.zig");
}
