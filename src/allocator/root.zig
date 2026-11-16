//! allocator: Allocate and manage memory.
//!
//! Zig port of commonware's `commonware-allocator` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/allocator). The lane file
//! docs/lanes/parallel.md tracks what is ported.
//!
//! Commonware configures mimalloc in the binary and exports its statistics. zigware has no C
//! dependencies, so `Heap` is a native allocator with mimalloc's layout and the same
//! configuration: its size classes (`good_size`), shared pages for objects up to
//! `large_object_limit`, pages of their own above it, arenas of 64 KiB slices, pinned and
//! unpinned reservations, a delayed purge policy, and the same `Stats` and exported
//! `metrics`.
//!
//! ```zig
//! var heap = allocator.Heap.init(io, .{
//!     .purge = .{ .after_ns = 10 * std.time.ns_per_s },
//!     .reserve = .init_pinned(2 << 30),
//!     .arena_max_object_size = allocator.arena_max_object_size,
//!     .allow_large_os_pages = false,
//!     .transparent_huge_pages = true,
//!     .arena_eager_commit = .if_overcommit,
//!     .arena_reserve = 1 << 30,
//!     .stats_merge_threshold = 4 << 20,
//! });
//! defer heap.deinit();
//! const gpa = heap.allocator();
//! ```

const std = @import("std");

const config = @import("config.zig");
pub const Config = config.Config;
pub const Purge = config.Purge;
pub const Reserve = config.Reserve;
pub const EagerCommit = config.EagerCommit;
pub const ReserveOutcome = config.ReserveOutcome;
pub const Status = config.Status;
pub const Effective = config.Effective;
pub const arena_slice_size = config.arena_slice_size;
pub const arena_chunk_size = config.arena_chunk_size;
pub const large_object_limit = config.large_object_limit;
pub const arena_max_object_size = config.arena_max_object_size;
pub const metadata_group_size = config.metadata_group_size;
pub const max_purge_delay_ns = config.max_purge_delay_ns;

const size_class = @import("size_class.zig");
pub const good_size = size_class.good_size;

pub const Stats = @import("stats.zig").Stats;
pub const metrics = @import("metrics.zig");

const heap_module = @import("heap.zig");
pub const Heap = heap_module.Heap;
pub const arenas_max = heap_module.arenas_max;
pub const collect_interval = heap_module.collect_interval;

/// The version of mimalloc whose behavior this heap follows (`major * 10000 + minor * 100 +
/// patch`), as commonware's `version()` reports for its vendored copy.
pub const mimalloc_version: u32 = 30503;

test {
    std.testing.refAllDecls(@This());
    _ = @import("arena.zig");
    _ = @import("os.zig");
    _ = @import("tests.zig");
}
