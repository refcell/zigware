//! Certificates the simplex resolver holds and serves, and the repair progress built on them
//! (commonware `actors/resolver/state.rs`).
//!
//! Certificates are kept encoded (as `Certificate` encodings), ready to serve. Every recorded
//! certificate or verdict returns `Effect`s the actor applies to the p2p resolver; they are
//! appended to a caller-owned list instead of returned as a `Vec`. Ordered maps are sorted
//! arrays keyed by view: they hold only views above the last finalization.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus_types = @import("../../../types.zig");
const types = @import("../../types.zig");
const ask = @import("../ask.zig");

const View = consensus_types.View;
const TermLength = consensus_types.TermLength;
const Kind = ask.Kind;

/// Why a resolver fetch was requested.
pub const FetchReason = enum {
    missing_nullification,
    certification_failed,

    pub fn as_str(self: FetchReason) []const u8 {
        return @tagName(self);
    }
};

/// A change to resolver asks that follows from a recorded certificate or verdict.
pub const Effect = union(enum) {
    /// A background fetch for the nullification covering `view`, caused by `cause`.
    fetch: struct { view: View, cause: View, reason: FetchReason },
    /// Asks for `kind` at views in `[start, end]` are settled.
    settled: struct { kind: Kind, start: View, end: View },
    /// A finalization settles every ask at or below this view.
    finalized: View,
    /// The floor rose to this view, ending background repair at or below it.
    raised: View,
};

/// A sorted map from view to `V` (commonware's `BTreeMap`/`BTreeSet` with `V = void`).
fn ViewMap(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { view: View, value: V };

        entries: std.ArrayList(Entry) = .empty,

        fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
        }

        /// The index of the first entry at or above `view`.
        fn lower_bound(self: *const Self, view: View) usize {
            const Context = struct {
                fn compare(target: View, entry: Entry) std.math.Order {
                    return std.math.order(target.get(), entry.view.get());
                }
            };
            const items = self.entries.items;
            return std.sort.lowerBound(Entry, items, view, Context.compare);
        }

        fn find(self: *const Self, view: View) ?usize {
            const index = self.lower_bound(view);
            if (index == self.entries.items.len) return null;
            if (self.entries.items[index].view != view) return null;
            return index;
        }

        fn get(self: *const Self, view: View) ?V {
            const index = self.find(view) orelse return null;
            return self.entries.items[index].value;
        }

        fn contains(self: *const Self, view: View) bool {
            return self.find(view) != null;
        }

        /// Inserts `value` at `view` unless present; returns whether it was inserted.
        fn insert(self: *Self, gpa: Allocator, view: View, value: V) Allocator.Error!bool {
            const index = self.lower_bound(view);
            const items = self.entries.items;
            if (index < items.len and items[index].view == view) return false;
            try self.entries.insert(gpa, index, .{ .view = view, .value = value });
            assert(self.entries.items[index].view == view);
            return true;
        }

        /// Removes `view`, returning its value.
        fn remove(self: *Self, view: View) ?V {
            const index = self.find(view) orelse return null;
            return self.entries.orderedRemove(index).value;
        }

        /// The value of the highest entry in `[start, end]`.
        fn last_in(self: *const Self, start: View, end: View) ?V {
            assert(start.get() <= end.get());
            const index = self.lower_bound(end.next());
            if (index == 0) return null;
            const entry = self.entries.items[index - 1];
            if (entry.view.get() < start.get()) return null;
            return entry.value;
        }
    };
}

pub fn State(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Certificate = types.Certificate(S, D);
        const Notarization = types.Notarization(S, D);
        const Bytes = ViewMap([]u8);
        const Views = ViewMap(void);

        gpa: Allocator,
        /// Number of views in each leader term.
        term_length: TermLength,
        /// Highest seen view.
        current_view: View = .zero(),
        /// View of the highest certified notarization or finalization (construction floor).
        floor: View = .zero(),
        /// Lowest anchor fetch scans still consider (see `fetch_missing`).
        cursor: View = .zero(),
        /// View and encoding of the highest finalization.
        finalization: ?struct { view: View, bytes: []u8 } = null,
        /// Encoded nullifications retained while they cover an unfinalized view.
        nullifications: Bytes = .{},
        /// Views whose notarization awaits certification.
        pending_notarizations: Views = .{},
        /// Encoded certified notarizations retained until finalization.
        certified_notarizations: Bytes = .{},
        /// Views whose notarization is permanently uncertifiable, retained until finalization.
        uncertifiable_notarizations: Views = .{},
        /// Whether journal replay still defers anchor scans and failed-certification fetches.
        replaying: bool = true,

        /// Runs no background repair until `replayed`.
        pub fn init(gpa: Allocator, term_length: TermLength) Self {
            assert(term_length.get() > 0);
            return .{ .gpa = gpa, .term_length = term_length };
        }

        pub fn deinit(self: *Self) void {
            if (self.finalization) |finalization| self.gpa.free(finalization.bytes);
            for (self.nullifications.entries.items) |entry| self.gpa.free(entry.value);
            for (self.certified_notarizations.entries.items) |entry| self.gpa.free(entry.value);
            self.nullifications.deinit(self.gpa);
            self.pending_notarizations.deinit(self.gpa);
            self.certified_notarizations.deinit(self.gpa);
            self.uncertifiable_notarizations.deinit(self.gpa);
            self.* = undefined;
        }

        /// The highest finalized view, or zero.
        fn last_finalized(self: *const Self) View {
            const finalization = self.finalization orelse return .zero();
            return finalization.view;
        }

        fn encode(self: *const Self, certificate: Certificate) Allocator.Error![]u8 {
            return codec.encode(Certificate, self.gpa, certificate);
        }

        /// Records a certificate (borrowed) and appends the effects to apply.
        pub fn updated(
            self: *Self,
            certificate: *const Certificate,
            effects: *std.ArrayList(Effect),
        ) Allocator.Error!void {
            const view = certificate.view();
            const last = self.last_finalized();
            if (view.get() > self.current_view.get()) self.current_view = view;
            switch (certificate.*) {
                .nullification => {
                    const end = view.term_end(self.term_length);
                    if (end.get() > last.get()) {
                        if (!self.nullifications.contains(view)) {
                            const bytes = try self.encode(certificate.*);
                            errdefer self.gpa.free(bytes);
                            assert(try self.nullifications.insert(self.gpa, view, bytes));
                        }
                        try effects.append(self.gpa, .{ .settled = .{
                            .kind = .nullification,
                            .start = view,
                            .end = end,
                        } });
                    }
                },
                .notarization => {
                    // A notarization becomes the floor only once certified (see `certified`).
                    const failed = self.uncertifiable_notarizations.contains(view);
                    if (view.get() > last.get() and !failed) {
                        if (!self.certified_notarizations.contains(view)) {
                            _ = try self.pending_notarizations.insert(self.gpa, view, {});
                        }
                        try effects.append(self.gpa, .{ .settled = .{
                            .kind = .notarization,
                            .start = view,
                            .end = view,
                        } });
                    }
                },
                .finalization => try self.updated_finalization(certificate, effects),
            }
            try self.fetch_missing(view, effects);
        }

        /// Keeps the highest finalization and retires everything it settles.
        fn updated_finalization(
            self: *Self,
            certificate: *const Certificate,
            effects: *std.ArrayList(Effect),
        ) Allocator.Error!void {
            assert(certificate.* == .finalization);
            const view = certificate.view();
            const last = self.last_finalized();
            if (view.get() > last.get()) {
                const bytes = try self.encode(certificate.*);
                if (self.finalization) |old| self.gpa.free(old.bytes);
                self.finalization = .{ .view = view, .bytes = bytes };
            }
            // No valid proposal can name ancestry at or below the finalization.
            const finalized: View = if (view.get() > last.get()) view else last;
            self.retire_bytes(&self.nullifications, finalized, true);
            retire_views(&self.pending_notarizations, finalized);
            self.retire_bytes(&self.certified_notarizations, finalized, false);
            retire_views(&self.uncertifiable_notarizations, finalized);
            try effects.append(self.gpa, .{ .finalized = finalized });
            if (view.get() > self.floor.get()) try effects.append(self.gpa, self.raise(view));
        }

        /// Drops entries at or below `finalized` (by term end for nullifications).
        fn retire_bytes(self: *Self, map: *Bytes, finalized: View, by_term: bool) void {
            var kept: usize = 0;
            const count = map.entries.items.len;
            for (map.entries.items) |entry| {
                const end = if (by_term) entry.view.term_end(self.term_length) else entry.view;
                if (end.get() > finalized.get()) {
                    map.entries.items[kept] = entry;
                    kept += 1;
                } else self.gpa.free(entry.value);
            }
            map.entries.shrinkRetainingCapacity(kept);
            assert(map.entries.items.len <= count);
        }

        fn retire_views(set: *Views, finalized: View) void {
            var kept: usize = 0;
            const count = set.entries.items.len;
            for (set.entries.items) |entry| {
                if (entry.view.get() <= finalized.get()) continue;
                set.entries.items[kept] = entry;
                kept += 1;
            }
            set.entries.shrinkRetainingCapacity(kept);
            assert(set.entries.items.len <= count);
        }

        /// Records a certification verdict for `notarization` (borrowed) and appends the
        /// effects to apply. The verdict may arrive before or after `updated` records it.
        pub fn certified(
            self: *Self,
            notarization: *const Notarization,
            success: bool,
            effects: *std.ArrayList(Effect),
        ) Allocator.Error!void {
            const view = notarization.view();
            const last = self.last_finalized();
            _ = self.pending_notarizations.remove(view);
            try effects.append(self.gpa, .{
                .settled = .{ .kind = .notarization, .start = view, .end = view },
            });
            if (success) {
                if (view.get() > last.get() and !self.certified_notarizations.contains(view)) {
                    const bytes = try self.encode(.{ .notarization = notarization.* });
                    errdefer self.gpa.free(bytes);
                    assert(try self.certified_notarizations.insert(self.gpa, view, bytes));
                }
                if (view.get() > self.floor.get()) try effects.append(self.gpa, self.raise(view));
                try self.fetch_missing(view, effects);
                return;
            }
            // No copy of a failed notarization can certify anywhere.
            if (self.certified_notarizations.remove(view)) |bytes| self.gpa.free(bytes);
            if (view.get() > last.get()) {
                _ = try self.uncertifiable_notarizations.insert(self.gpa, view, {});
            }
            if (!self.replaying and self.needs_nullification(view)) {
                try effects.append(self.gpa, .{ .fetch = .{
                    .view = view,
                    .cause = view,
                    .reason = .certification_failed,
                } });
            }
        }

        /// Marks the end of journal replay and appends the deferred background repair.
        pub fn replayed(self: *Self, effects: *std.ArrayList(Effect)) Allocator.Error!void {
            assert(self.replaying);
            self.replaying = false;
            try self.fetch_missing(self.current_view, effects);
            for (self.uncertifiable_notarizations.entries.items) |entry| {
                if (!self.needs_nullification(entry.view)) continue;
                try effects.append(self.gpa, .{ .fetch = .{
                    .view = entry.view,
                    .cause = entry.view,
                    .reason = .certification_failed,
                } });
            }
        }

        /// Whether local evidence settled an ask for `kind` at `view`: the evidence is in
        /// hand, or no response could ever serve the ask.
        pub fn settled(self: *const Self, view: View, kind: Kind) bool {
            if (view.get() <= self.last_finalized().get()) return true;
            return switch (kind) {
                .nullification => self.covering_nullification(view) != null,
                .notarization => self.pending_notarizations.contains(view) or
                    self.certified_notarizations.contains(view) or
                    self.uncertifiable_notarizations.contains(view),
            };
        }

        /// Whether every ask sharing the resolver key for `view` is settled.
        pub fn key_settled(self: *const Self, view: View) bool {
            return self.settled(view, .nullification) and self.settled(view, .notarization);
        }

        /// Whether the notarization at `view` failed certification.
        pub fn uncertifiable(self: *const Self, view: View) bool {
            return self.uncertifiable_notarizations.contains(view);
        }

        /// The encoded certificate to serve for `view` (borrowed): the highest finalization
        /// at or above it, else an exact certified notarization, else a covering
        /// nullification, else the floor's certified notarization for views below it.
        pub fn produce(self: *const Self, view: View) ?[]const u8 {
            if (self.finalization) |finalization| {
                if (view.get() <= finalization.view.get()) return finalization.bytes;
            }
            if (self.certified_notarizations.get(view)) |bytes| return bytes;
            if (self.covering_nullification(view)) |bytes| return bytes;
            if (view.get() > self.floor.get()) return null;
            return self.certified_notarizations.get(self.floor);
        }

        /// The stored nullification covering `view`, if any.
        fn covering_nullification(self: *const Self, view: View) ?[]const u8 {
            const start, const end = view.covering_range(self.term_length);
            return self.nullifications.last_in(start, end);
        }

        /// Whether `view` is above the floor with no stored covering nullification.
        fn needs_nullification(self: *const Self, view: View) bool {
            return view.get() > self.floor.get() and self.covering_nullification(view) == null;
        }

        /// Appends fetches for each uncovered term anchor from the cursor up to the current
        /// view, advancing the cursor past everything scanned. Nothing during replay.
        fn fetch_missing(
            self: *Self,
            cause: View,
            effects: *std.ArrayList(Effect),
        ) Allocator.Error!void {
            if (self.replaying) return;
            const above_floor = self.floor.next();
            var anchor = if (self.cursor.get() > above_floor.get()) self.cursor else above_floor;
            // Bounded by the views between the floor and the current view.
            while (anchor.get() < self.current_view.get()) {
                if (self.covering_nullification(anchor) == null) {
                    try effects.append(self.gpa, .{ .fetch = .{
                        .view = anchor,
                        .cause = cause,
                        .reason = .missing_nullification,
                    } });
                }
                anchor = anchor.next_term_start(self.term_length);
            }
            self.cursor = anchor;
            assert(self.cursor.get() >= self.current_view.get());
        }

        /// Raises the floor, pulling the cursor back when the floor lands mid-term.
        fn raise(self: *Self, floor: View) Effect {
            assert(floor.get() > self.floor.get());
            self.floor = floor;
            const next = floor.next();
            if (!next.is_term_start(self.term_length) and next.get() < self.cursor.get()) {
                self.cursor = next;
            }
            return .{ .raised = floor };
        }

        /// The term length this state was built with.
        pub fn term(self: *const Self) TermLength {
            return self.term_length;
        }
    };
}
