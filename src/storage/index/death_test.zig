//! commonware's `#[should_panic]` cursor tests of `storage/src/index/mod.rs`, as death tests
//! (`utils.death`): `update`, `delete`, or `insert` before `next`, after the last value, or
//! twice without a `next` between. Each runs on the hash (unordered), ordered, and partitioned
//! indices as commonware's do; a partitioned test runs the unordered index first, which
//! panics, so its ordered half never runs, as in commonware. The panics are in the cursors'
//! `active` and `insert`. The last test is `partitioned::ordered`'s spill cursor test, on a
//! partition spilled at threshold 2.

const std = @import("std");
const testing = std.testing;
const death = @import("utils").death;
const translator = @import("../translator.zig");
const unordered = @import("unordered.zig");
const ordered = @import("ordered.zig");
const partitioned = @import("partitioned/mod.zig");

const gpa = testing.allocator;
const need_next = "must call Cursor::next()";
const no_active = "no active item in Cursor";

const Hash = unordered.Index(translator.TwoCap, u64);
const Ordered = ordered.Index(translator.TwoCap, u64);
const PartitionedUnordered = partitioned.unordered.Index(translator.OneCap, u64, 1);
const PartitionedOrdered = partitioned.ordered.Index(translator.OneCap, u64, 1);
const PartitionedSpilling = partitioned.ordered.IndexSpillAt(translator.OneCap, u64, 1, 2);

const Kind = enum { hash, ordered, partitioned };

/// A test body running `run` on the index or indices of `kind`.
fn Body(comptime run: anytype, comptime kind: Kind) type {
    return struct {
        fn body() !void {
            switch (kind) {
                .hash => try with(Hash, run),
                .ordered => try with(Ordered, run),
                .partitioned => {
                    try with(PartitionedUnordered, run);
                    try with(PartitionedOrdered, run);
                },
            }
        }
    };
}

fn with(comptime I: type, comptime run: anytype) !void {
    const Tr = I.Translator;
    const tr: Tr = if (@hasDecl(Tr, "partition_count")) .init(.{}) else .{};
    var index = I.init(gpa, tr);
    defer index.deinit();
    try run(&index);
}

fn update_before_next(index: anytype) !void {
    try index.insert("key", 123);
    var cursor = index.get_mut("key").?;
    cursor.update(321);
}

fn delete_before_next(index: anytype) !void {
    try index.insert("key", 123);
    var cursor = index.get_mut("key").?;
    cursor.delete();
}

fn update_after_done(index: anytype) !void {
    try index.insert("key", 123);
    var cursor = index.get_mut("key").?;
    try testing.expectEqual(@as(u64, 123), cursor.next().?.*);
    try testing.expect(cursor.next() == null);
    cursor.update(321);
}

fn insert_before_next(index: anytype) !void {
    try index.insert("key", 123);
    var cursor = index.get_mut("key").?;
    try cursor.insert(321);
}

fn delete_after_done(index: anytype) !void {
    try index.insert("key", 123);
    var cursor = index.get_mut("key").?;
    try testing.expectEqual(@as(u64, 123), cursor.next().?.*);
    try testing.expect(cursor.next() == null);
    cursor.delete();
}

fn double_delete(index: anytype) !void {
    try index.insert("key", 123);
    try index.insert("key", 456);
    var cursor = index.get_mut("key").?;
    try testing.expect(cursor.next() != null);
    cursor.delete();
    cursor.delete();
}

fn insert_at_entry_then_delete_head(index: anytype) !void {
    try index.insert("key", 10);
    try index.insert("key", 20);
    var cursor = index.get_mut("key").?;
    try testing.expect(cursor.next() != null);
    try cursor.insert(15);
    cursor.delete();
}

fn delete_then_insert_without_next(index: anytype) !void {
    try index.insert("key", 10);
    try index.insert("key", 20);
    var cursor = index.get_mut("key").?;
    try testing.expect(cursor.next() != null);
    try testing.expect(cursor.next() != null);
    cursor.delete();
    try cursor.insert(15);
}

fn inserts_without_next(index: anytype) !void {
    try index.insert("key", 10);
    try index.insert("key", 20);
    var cursor = index.get_mut("key").?;
    try testing.expect(cursor.next() != null);
    try cursor.insert(15);
    try cursor.insert(25);
}

fn update_before_next_short_key(index: anytype) !void {
    try index.insert("p", 1);
    var cursor = index.get_mut("p").?;
    cursor.update(2);
}

// commonware `test_{hash,ordered,partitioned}_index_cursor_update_before_next_panics`.
test "hash index cursor update before next panics" {
    try death.expect_panic(@src(), need_next, Body(update_before_next, .hash).body);
}
test "ordered index cursor update before next panics" {
    try death.expect_panic(@src(), need_next, Body(update_before_next, .ordered).body);
}
test "partitioned index cursor update before next panics" {
    try death.expect_panic(@src(), need_next, Body(update_before_next, .partitioned).body);
}

// commonware `test_*_index_cursor_delete_before_next_panics`.
test "hash index cursor delete before next panics" {
    try death.expect_panic(@src(), need_next, Body(delete_before_next, .hash).body);
}
test "ordered index cursor delete before next panics" {
    try death.expect_panic(@src(), need_next, Body(delete_before_next, .ordered).body);
}
test "partitioned index cursor delete before next panics" {
    try death.expect_panic(@src(), need_next, Body(delete_before_next, .partitioned).body);
}

// commonware `test_*_index_cursor_update_after_done`.
test "hash index cursor update after done panics" {
    try death.expect_panic(@src(), no_active, Body(update_after_done, .hash).body);
}
test "ordered index cursor update after done panics" {
    try death.expect_panic(@src(), no_active, Body(update_after_done, .ordered).body);
}
test "partitioned index cursor update after done panics" {
    try death.expect_panic(@src(), no_active, Body(update_after_done, .partitioned).body);
}

// commonware `test_*_index_cursor_insert_before_next`.
test "hash index cursor insert before next panics" {
    try death.expect_panic(@src(), need_next, Body(insert_before_next, .hash).body);
}
test "ordered index cursor insert before next panics" {
    try death.expect_panic(@src(), need_next, Body(insert_before_next, .ordered).body);
}
test "partitioned index cursor insert before next panics" {
    try death.expect_panic(@src(), need_next, Body(insert_before_next, .partitioned).body);
}

// commonware `test_*_index_cursor_delete_after_done`.
test "hash index cursor delete after done panics" {
    try death.expect_panic(@src(), no_active, Body(delete_after_done, .hash).body);
}
test "ordered index cursor delete after done panics" {
    try death.expect_panic(@src(), no_active, Body(delete_after_done, .ordered).body);
}
test "partitioned index cursor delete after done panics" {
    try death.expect_panic(@src(), no_active, Body(delete_after_done, .partitioned).body);
}

// commonware `test_{hash,ordered}_index_cursor_double_delete` (no partitioned variant).
test "hash index cursor double delete panics" {
    try death.expect_panic(@src(), need_next, Body(double_delete, .hash).body);
}
test "ordered index cursor double delete panics" {
    try death.expect_panic(@src(), need_next, Body(double_delete, .ordered).body);
}

// commonware `test_*_index_insert_at_entry_then_delete_head`.
test "hash index insert at entry then delete head panics" {
    const body = Body(insert_at_entry_then_delete_head, .hash).body;
    try death.expect_panic(@src(), need_next, body);
}
test "ordered index insert at entry then delete head panics" {
    const body = Body(insert_at_entry_then_delete_head, .ordered).body;
    try death.expect_panic(@src(), need_next, body);
}
test "partitioned index insert at entry then delete head panics" {
    const body = Body(insert_at_entry_then_delete_head, .partitioned).body;
    try death.expect_panic(@src(), need_next, body);
}

// commonware `test_*_index_delete_then_insert_without_next`.
test "hash index delete then insert without next panics" {
    const body = Body(delete_then_insert_without_next, .hash).body;
    try death.expect_panic(@src(), need_next, body);
}
test "ordered index delete then insert without next panics" {
    const body = Body(delete_then_insert_without_next, .ordered).body;
    try death.expect_panic(@src(), need_next, body);
}
test "partitioned index delete then insert without next panics" {
    const body = Body(delete_then_insert_without_next, .partitioned).body;
    try death.expect_panic(@src(), need_next, body);
}

// commonware `test_*_index_inserts_without_next`.
test "hash index inserts without next panics" {
    try death.expect_panic(@src(), need_next, Body(inserts_without_next, .hash).body);
}
test "ordered index inserts without next panics" {
    try death.expect_panic(@src(), need_next, Body(inserts_without_next, .ordered).body);
}
test "partitioned index inserts without next panics" {
    try death.expect_panic(@src(), need_next, Body(inserts_without_next, .partitioned).body);
}

// commonware `test_*_index_update_before_next_panics` (a one-byte key).
test "hash index update before next on a short key panics" {
    const body = Body(update_before_next_short_key, .hash).body;
    try death.expect_panic(@src(), need_next, body);
}
test "ordered index update before next on a short key panics" {
    const body = Body(update_before_next_short_key, .ordered).body;
    try death.expect_panic(@src(), need_next, body);
}
test "partitioned index update before next on a short key panics" {
    const body = Body(update_before_next_short_key, .partitioned).body;
    try death.expect_panic(@src(), need_next, body);
}

fn spill_delete_before_next(index: anytype) !void {
    try index.insert(&.{ 0x10, 0x01 }, 1);
    try index.insert(&.{ 0x10, 0x02 }, 2); // Spills the partition past threshold 2.
    var cursor = index.get_mut(&.{ 0x10, 0x01 }).?;
    cursor.delete();
}

// commonware: partitioned::ordered test_spill_cursor_delete_before_next_panics.
test "spilled partition cursor delete before next panics" {
    try death.expect_panic(@src(), need_next, struct {
        fn body() !void {
            try with(PartitionedSpilling, spill_delete_before_next);
        }
    }.body);
}
