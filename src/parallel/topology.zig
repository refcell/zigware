//! The host's last-level cache (LLC) domains, and how a pool's workers split into groups that
//! prefer one domain (the model of commonware's `parallel/src/topology.rs`).
//!
//! Threads in different LLC domains pay far more to exchange cache lines than threads in one
//! domain. Commonware splits a pool's workers into groups sized from the domain with the most
//! allowed CPUs, homes groups in domains, and pins workers there. This file ports the pure
//! model: detecting domains (from sysfs, through `std.Io`), the group width, the exact
//! one-group-per-domain partition, and the masks homed and floating workers request. zigware's
//! `ThreadPool` is one group, so nothing pins threads yet; a grouped pool will use this.
//!
//! Bounds: CPUs below `cpus_max` (glibc's `CPU_SETSIZE`), at most `domains_max` domains, and
//! sharing lists up to `list_len_max` bytes. A host past them has no topology, which means one
//! unhomed group, as commonware does when it cannot read a mask.

const std = @import("std");
const assert = std.debug.assert;

/// CPUs a `CpuSet` can hold, as `cpu_set_t` does.
pub const cpus_max = 1024;
/// The most domains a topology tracks.
pub const domains_max = 256;
/// The longest `shared_cpu_list` a topology accepts, in bytes.
pub const list_len_max = 256;
/// The fewest CPUs allowed in one domain before groups leave one CPU for other threads.
pub const slack_from = 6;
/// The most groups `reservations` assigns masks to.
pub const groups_max = 64;

/// A CPU affinity mask.
pub const CpuSet = struct {
    bits: std.StaticBitSet(cpus_max) = .empty,

    pub const empty: CpuSet = .{};

    /// The set holding exactly `cpus`.
    pub fn of(cpus: []const usize) CpuSet {
        var mask: CpuSet = .{};
        for (cpus) |cpu| mask.set(cpu);
        return mask;
    }

    /// The set holding `first..end`.
    pub fn range(first: usize, end: usize) CpuSet {
        assert(first <= end and end <= cpus_max);
        var mask: CpuSet = .{};
        for (first..end) |cpu| mask.set(cpu);
        return mask;
    }

    pub fn set(cpu_set: *CpuSet, cpu: usize) void {
        assert(cpu < cpus_max);
        cpu_set.bits.set(cpu);
    }

    /// Whether `cpu` is in the set (false past `cpus_max`).
    pub fn contains(cpu_set: CpuSet, cpu: usize) bool {
        if (cpu >= cpus_max) return false;
        return cpu_set.bits.isSet(cpu);
    }

    pub fn count(cpu_set: CpuSet) usize {
        return cpu_set.bits.count();
    }

    pub fn intersection(cpu_set: CpuSet, other: CpuSet) CpuSet {
        return .{ .bits = cpu_set.bits.intersectWith(other.bits) };
    }

    pub fn difference(cpu_set: CpuSet, other: CpuSet) CpuSet {
        return .{ .bits = cpu_set.bits.differenceWith(other.bits) };
    }

    pub fn eql(cpu_set: CpuSet, other: CpuSet) bool {
        return cpu_set.bits.eql(other.bits);
    }

    /// The CPUs in ascending order.
    pub fn iterator(cpu_set: *const CpuSet) std.StaticBitSet(cpus_max).Iterator(.{}) {
        return cpu_set.bits.iterator(.{});
    }
};

/// One group per allowed domain, used when the allowed CPUs split evenly into those domains and
/// the pool has exactly one worker per allowed CPU.
pub const Partition = struct {
    /// Workers per group, equal to each domain's allowed CPU count.
    width: usize,
    /// Each group's home domain, in group order.
    homes: [domains_max]u16 = undefined,
    /// The allowed CPUs of each home.
    masks: [domains_max]CpuSet = undefined,
    len: usize = 0,
};

/// A group of `width` workers and its home domain, if any.
pub const Group = struct { width: usize, home: ?u16 };

/// A `(cpu, shared_cpu_list)` pair, one per CPU whose LLC was read.
pub const List = struct { cpu: usize, list: []const u8 };

/// The host's last-level cache domains.
pub const Topology = struct {
    /// The domain of each CPU below `cpus_len`, or null for a CPU whose cache was unreadable.
    cpu_to_domain: [cpus_max]?u16 = @splat(null),
    cpus_len: usize = 0,
    /// Each domain's CPUs, indexed by domain in discovery order.
    domains: [domains_max]CpuSet = undefined,
    domains_len: usize = 0,

    /// Builds the tables from `(cpu, shared_cpu_list)` pairs, one domain per distinct list.
    /// Returns null when the pairs are empty, form a single domain, include a CPU at or past
    /// `cpus_max`, or exceed `domains_max` domains or `list_len_max` bytes.
    pub fn from_lists(lists: []const List) ?Topology {
        var builder: Builder = .{};
        for (lists) |pair| if (!builder.add(pair.cpu, pair.list)) return null;
        return builder.finish();
    }

    /// The domain of `cpu`, or null when the topology does not cover it.
    pub fn domain_of(topology: *const Topology, cpu: usize) ?u16 {
        if (cpu >= topology.cpus_len) return null;
        return topology.cpu_to_domain[cpu];
    }

    /// The CPUs of `domain` that `allowed` also contains.
    pub fn within(topology: *const Topology, domain: usize, allowed: CpuSet) CpuSet {
        assert(domain < topology.domains_len);
        return topology.domains[domain].intersection(allowed);
    }

    /// Partitions `parallelism` workers across the domains containing `allowed` CPUs, or null
    /// unless there are at least two such domains, all with the same allowed CPU count of at
    /// least two, every allowed CPU belongs to a domain, and there is one worker per allowed CPU.
    pub fn partition(topology: *const Topology, allowed: CpuSet, parallelism: usize) ?Partition {
        var result: Partition = .{ .width = 0 };
        for (0..topology.domains_len) |index| {
            const mask = topology.within(index, allowed);
            const count = mask.count();
            if (count == 0) continue;
            if (result.width == 0) {
                result.width = count;
            } else if (count != result.width) {
                return null;
            }
            result.homes[result.len] = @intCast(index);
            result.masks[result.len] = mask;
            result.len += 1;
        }
        const exact = result.len > 1 and result.width > 1 and
            result.len * result.width == parallelism and allowed.count() == parallelism;
        if (!exact) return null;
        assert(result.len <= topology.domains_len);
        return result;
    }

    /// Writes into `homes` the mask of each homed group in `groups` (null for floating groups)
    /// and returns the CPUs left for floating workers, or null when fewer remain than there are
    /// floating workers.
    pub fn reservations(
        topology: *const Topology,
        allowed: CpuSet,
        groups: []const Group,
        homes: []?CpuSet,
    ) ?CpuSet {
        assert(homes.len >= groups.len);
        var reserved: CpuSet = .empty;
        var floating: usize = 0;
        for (groups, homes[0..groups.len]) |group, *home| {
            if (group.home) |domain| {
                const mask = topology.within(domain, allowed);
                reserved = .{ .bits = reserved.bits.unionWith(mask.bits) };
                home.* = mask;
            } else {
                floating += group.width;
                home.* = null;
            }
        }
        const remainder = allowed.difference(reserved);
        if (remainder.count() < floating) return null;
        return remainder;
    }

    /// The worker count of a full group: the most CPUs `allowed` in any one domain, minus one
    /// from `slack_from` CPUs up. Null when no domain allows two CPUs.
    pub fn group_width(topology: *const Topology, allowed: CpuSet) ?usize {
        var widest: usize = 0;
        for (0..topology.domains_len) |index| {
            widest = @max(widest, topology.within(index, allowed).count());
        }
        const width = if (widest >= slack_from) widest - 1 else widest;
        if (width <= 1) return null;
        assert(width < cpus_max);
        return width;
    }

    /// Detects the host's domains from sysfs: each CPU's LLC is its highest-level Data or
    /// Unified cache leaf. Null when sysfs is unreadable or the lists are rejected.
    pub fn detect(io: std.Io) ?Topology {
        var cpus = std.Io.Dir.cwd().openDir(io, "/sys/devices/system/cpu", .{
            .iterate = true,
        }) catch |err| return read_failed(Topology, io, err);
        defer cpus.close(io);
        var builder: Builder = .{};
        var entries = cpus.iterate();
        // Bounded by the directory, which holds one entry per possible CPU plus a few files.
        while (entries.next(io) catch |err| return read_failed(Topology, io, err)) |entry| {
            const id_text = std.mem.cutPrefix(u8, entry.name, "cpu") orelse continue;
            const cpu = std.fmt.parseInt(usize, id_text, 10) catch continue;
            var list_buffer: [list_len_max]u8 = undefined;
            const list = llc_list(io, cpus, entry.name, &list_buffer) orelse continue;
            if (!builder.add(cpu, list)) return null;
        }
        return builder.finish();
    }
};

/// Null for a failed sysfs read, re-arming a cancel the read took: the caller carries on
/// without a topology, and an acknowledged cancel would leave its later waits blocked forever.
fn read_failed(comptime T: type, io: std.Io, err: anyerror) ?T {
    if (err == error.Canceled) io.recancel();
    return null;
}

/// The `shared_cpu_list` of the highest-level Data or Unified cache of `cpu_name`, in `buffer`.
fn llc_list(io: std.Io, cpus: std.Io.Dir, cpu_name: []const u8, buffer: []u8) ?[]const u8 {
    var path_buffer: [64]u8 = undefined;
    const cache_path = std.fmt.bufPrint(&path_buffer, "{s}/cache", .{cpu_name}) catch return null;
    var cache = cpus.openDir(io, cache_path, .{ .iterate = true }) catch |err| {
        return read_failed([]const u8, io, err);
    };
    defer cache.close(io);
    var best_level: ?u32 = null;
    var best_len: usize = 0;
    var leaves = cache.iterate();
    while (leaves.next(io) catch |err| return read_failed([]const u8, io, err)) |leaf| {
        if (!std.mem.startsWith(u8, leaf.name, "index")) continue;
        const level = leaf_level(io, cache, leaf.name) orelse continue;
        if (best_level) |best| if (level <= best) continue;
        var file_buffer: [list_len_max + 1]u8 = undefined;
        const list = read_trimmed(io, cache, leaf.name, "shared_cpu_list", &file_buffer) orelse
            continue;
        if (list.len == 0 or list.len > buffer.len) continue;
        @memcpy(buffer[0..list.len], list);
        best_level = level;
        best_len = list.len;
    }
    if (best_level == null) return null;
    return buffer[0..best_len];
}

/// The level of a Data or Unified cache leaf, or null for other leaves.
fn leaf_level(io: std.Io, cache: std.Io.Dir, leaf: []const u8) ?u32 {
    var buffer: [32]u8 = undefined;
    const kind = read_trimmed(io, cache, leaf, "type", &buffer) orelse return null;
    if (!std.mem.eql(u8, kind, "Data") and !std.mem.eql(u8, kind, "Unified")) return null;
    const level = read_trimmed(io, cache, leaf, "level", &buffer) orelse return null;
    return std.fmt.parseInt(u32, level, 10) catch null;
}

fn read_trimmed(
    io: std.Io,
    dir: std.Io.Dir,
    leaf: []const u8,
    name: []const u8,
    buffer: []u8,
) ?[]const u8 {
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ leaf, name }) catch return null;
    const bytes = dir.readFile(io, path, buffer) catch |err| {
        return read_failed([]const u8, io, err);
    };
    // A full buffer may have cut the file short.
    if (bytes.len == buffer.len) return null;
    return std.mem.trim(u8, bytes, " \t\r\n");
}

/// Collects `(cpu, list)` pairs, interning each distinct list as a domain.
const Builder = struct {
    topology: Topology = .{},
    names: [domains_max][list_len_max]u8 = undefined,
    name_lens: [domains_max]usize = undefined,

    /// Adds a pair; false when it exceeds a bound.
    fn add(builder: *Builder, cpu: usize, list: []const u8) bool {
        if (cpu >= cpus_max or list.len > list_len_max) return false;
        const topology = &builder.topology;
        const domain = for (0..topology.domains_len) |index| {
            const name = builder.names[index][0..builder.name_lens[index]];
            if (std.mem.eql(u8, name, list)) break index;
        } else domain: {
            if (topology.domains_len == domains_max) return false;
            const index = topology.domains_len;
            @memcpy(builder.names[index][0..list.len], list);
            builder.name_lens[index] = list.len;
            topology.domains[index] = .empty;
            topology.domains_len += 1;
            break :domain index;
        };
        topology.cpu_to_domain[cpu] = @intCast(domain);
        topology.cpus_len = @max(topology.cpus_len, cpu + 1);
        topology.domains[domain].set(cpu);
        return true;
    }

    /// The topology, or null when it has fewer than two domains (nowhere to move work).
    fn finish(builder: *const Builder) ?Topology {
        if (builder.topology.domains_len <= 1) return null;
        assert(builder.topology.cpus_len > 0);
        return builder.topology;
    }
};

test {
    _ = @import("topology_tests.zig");
}
