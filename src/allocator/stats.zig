//! `Stats`: a heap's statistics, the fields of commonware's mimalloc `Stats`.
//!
//! A zigware heap updates them under its lock, except allocated bytes, which each thread's
//! cache counts and a read sums, so unlike mimalloc's per-thread counters, which merge past a
//! threshold, they are exact whenever no thread is allocating.

/// Heap statistics, excluding memory callers obtain elsewhere.
pub const Stats = struct {
    /// Bytes mapped for arenas and pages mapped on their own, excluding pinned reservations.
    reserved_bytes: u64 = 0,
    /// Bytes of pinned reservations, which are never purged.
    pinned_bytes: u64 = 0,
    /// Bytes committed: arena metadata, slices first used, pages mapped on their own, and
    /// whole eagerly committed arenas. As on Unix in mimalloc, a purge does not lower it.
    committed_bytes: u64 = 0,
    committed_peak_bytes: u64 = 0,
    /// Bytes allocated to callers, in block sizes (so including size-class rounding).
    allocated_bytes: u64 = 0,
    /// Peak of `allocated_bytes`.
    allocated_peak_bytes: u64 = 0,
    /// Cumulative bytes purged back to the operating system.
    purged_bytes: u64 = 0,
    /// Cumulative purge operations (system calls).
    purge_calls: u64 = 0,
    /// Cumulative arena-level purge passes.
    arena_purges: u64 = 0,
    /// Cumulative memory mappings requested from the operating system.
    mmap_calls: u64 = 0,
    /// Cumulative commit operations: runs of slices used for the first time.
    commit_calls: u64 = 0,
    /// Pages currently in use.
    pages: u64 = 0,
    /// Distinct threads that have taken a page, up to the heap's thread bound.
    threads: u64 = 0,
    /// Arenas currently managed, excluding pages mapped on their own.
    arenas: u64 = 0,
    /// Cumulative allocations larger than the largest size class.
    huge_allocations: u64 = 0,
    /// Cumulative bytes of those allocations.
    huge_bytes: u64 = 0,
};
