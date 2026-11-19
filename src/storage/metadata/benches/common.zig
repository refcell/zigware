//! Shared setup of the metadata benchmarks (commonware `storage/src/metadata/benches/utils.rs`):
//! the store type, its partition, and the random key-value sets drawn as commonware draws them.
//! Storage comes from the journal benches' `Disk`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const storage = @import("storage");
const journal_common = @import("../../journal/benches/common.zig");

pub const Disk = journal_common.Disk;

/// Partition used across all metadata benchmarks.
pub const partition = "metadata-bench-partition";
/// Bytes in each random value.
pub const value_size = 100;

/// The store every benchmark but `overwrite` uses: `u64` keys and byte-vector values.
pub const Store = storage.metadata.Metadata(u64, []const u8);

pub const KV = struct { key: u64, value: [value_size]u8 };

/// Open (or create) the store (commonware `init`).
pub fn open(gpa: Allocator, disk: *Disk) !Store {
    return Store.init(gpa, disk.interface(), .{
        .partition = partition,
        .codec_config = .{ .range = .full(), .item = {} },
    });
}

/// Put a copy of `value` under `key`, freeing any previous value.
pub fn put(gpa: Allocator, store: *Store, key: u64, value: []const u8) !void {
    const copy = try gpa.dupe(u8, value);
    errdefer gpa.free(copy);
    if (try store.put(key, copy)) |previous| gpa.free(previous);
    assert(store.get(key) != null);
}

/// `count` pairs with keys `0..count` and `test_rng` values (commonware `get_random_kvs`).
pub fn random_kvs(gpa: Allocator, count: usize) ![]KV {
    const kvs = try gpa.alloc(KV, count);
    var rng = utils.rng.test_rng();
    for (kvs, 0..) |*kv, index| {
        kv.key = index;
        rng.fill_bytes(&kv.value);
    }
    assert(kvs.len == count);
    return kvs;
}

/// New values for `modified` keys of `kvs`, chosen by a shuffle (commonware
/// `get_modified_kvs`).
pub fn modified_kvs(gpa: Allocator, kvs: []const KV, modified: usize) ![]KV {
    assert(modified <= kvs.len);
    var rng = utils.rng.test_rng();
    const indices = try gpa.alloc(usize, kvs.len);
    defer gpa.free(indices);
    for (indices, 0..) |*slot, index| slot.* = index;
    journal_common.shuffle(usize, &rng, indices);
    const result = try gpa.alloc(KV, modified);
    for (result, indices[0..modified]) |*kv, index| {
        kv.key = kvs[index].key;
        rng.fill_bytes(&kv.value);
    }
    return result;
}
