//! The metrics registry (commonware `telemetry::metrics::Registry`) and its handles.
//!
//! `Registry.register` stores a metric under a family name and a sorted attribute list and
//! returns a `Registered(M)` handle. Re-registering the same name and attributes returns
//! another handle to the existing metric. A metric stays exposed while any handle to it is
//! live; the last `deinit` (of a handle or a `clone`) unregisters it. Registering one key with
//! two metric types, or one family with two help texts or types, panics as in commonware.
//!
//! `encode` writes every family in name order: `# HELP name help.`, `# TYPE name type`, then
//! each metric's samples in registration order (removals swap the last metric into the gap,
//! as commonware's `swap_remove`), skipping families with no samples, and a final `# EOF`.
//!
//! Metric storage is reference counted apart from the registration, so a `Batched` writer can
//! keep publishing to a metric after its last handle unregisters it (commonware shares the
//! metric's `Arc`). Registering allocates; recording never does.

const std = @import("std");
const encoding = @import("encoding.zig");
const raw = @import("raw.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const SpinLock = raw.SpinLock;

/// Prefix of the runtime's own metrics. Context labels may not start with it.
pub const metrics_prefix = "runtime";

/// One `key="value"` label attached to every metric registered in a scope.
pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
};

/// Whether `label` matches `[a-zA-Z][a-zA-Z0-9_]*` (commonware's `validate_label`).
pub fn is_valid_label(label: []const u8) bool {
    if (label.len == 0 or !std.ascii.isAlphabetic(label[0])) return false;
    for (label[1..]) |char| {
        if (!std.ascii.isAlphanumeric(char) and char != '_') return false;
    }
    return true;
}

/// Panics unless `label` matches `[a-zA-Z][a-zA-Z0-9_]*`.
pub fn validate_label(label: []const u8) void {
    if (!is_valid_label(label)) std.debug.panic("label must match [a-zA-Z][a-zA-Z0-9_]*: {s}", .{
        label,
    });
}

const VTable = struct {
    encode: *const fn (*anyopaque, encoding.SampleEncoder) Writer.Error!void,
    release: *const fn (*anyopaque) void,
};

/// Reference-counted storage for one metric.
pub fn Box(comptime M: type) type {
    comptime assert(@hasDecl(M, "metric_type"));
    return struct {
        const Self = @This();

        refs: std.atomic.Value(u32),
        gpa: Allocator,
        metric: M,

        const vtable: VTable = .{ .encode = encode_erased, .release = release_erased };

        fn create(gpa: Allocator, metric: M) Allocator.Error!*Self {
            const box = try gpa.create(Self);
            box.* = .{ .refs = .init(1), .gpa = gpa, .metric = metric };
            return box;
        }

        pub fn retain(box: *Self) void {
            const previous = box.refs.fetchAdd(1, .monotonic);
            assert(previous > 0);
            assert(previous < std.math.maxInt(u32));
        }

        pub fn release(box: *Self) void {
            const previous = box.refs.fetchSub(1, .acq_rel);
            assert(previous > 0);
            if (previous > 1) return;
            if (comptime @hasDecl(M, "deinit")) box.metric.deinit();
            const gpa = box.gpa;
            gpa.destroy(box);
        }

        fn encode_erased(pointer: *anyopaque, encoder: encoding.SampleEncoder) Writer.Error!void {
            const box: *Self = @ptrCast(@alignCast(pointer));
            try box.metric.encode_samples(encoder);
        }

        fn release_erased(pointer: *anyopaque) void {
            const box: *Self = @ptrCast(@alignCast(pointer));
            box.release();
        }
    };
}

/// A claim on one registry entry; `none` for a detached handle.
pub const Registration = struct {
    registry: ?*Registry,
    id: u32,

    pub const none: Registration = .{ .registry = null, .id = 0 };

    fn claim(registration: Registration) void {
        const registry = registration.registry orelse return;
        registry.lock.lock();
        defer registry.lock.unlock();
        registry.entry(registration.id).claims += 1;
    }

    fn release(registration: Registration) void {
        const registry = registration.registry orelse return;
        registry.release_registration(registration.id);
    }
};

/// A metric handle whose lifetime controls the metric's exposure (commonware `Registered`).
/// Handles are values: `clone` shares the metric and its registration, `deinit` drops one.
pub fn Registered(comptime M: type) type {
    return struct {
        const Self = @This();

        box: *Box(M),
        registration: Registration,

        /// A handle with no registry entry (commonware `Registered::detached`).
        pub fn detached(gpa: Allocator, metric_value: M) Allocator.Error!Self {
            return .{ .box = try Box(M).create(gpa, metric_value), .registration = .none };
        }

        pub fn metric(handle: Self) *M {
            return &handle.box.metric;
        }

        pub fn clone(handle: Self) Self {
            handle.box.retain();
            handle.registration.claim();
            return handle;
        }

        pub fn deinit(handle: *Self) void {
            handle.registration.release();
            handle.box.release();
            handle.* = undefined;
        }
    };
}

const Entry = struct {
    /// The family name, a zero byte, then each attribute as length-prefixed key and value.
    key: []u8,
    name_len: u32,
    /// The attributes as encoded const labels (`k="v",...`).
    const_labels: []u8,
    box: *anyopaque,
    vtable: *const VTable,
    type_name: []const u8,
    /// Live handles (registrations and their clones).
    claims: u32,
    /// Position in the family's `metric_ids`.
    family_index: u32,

    fn name(e: *const Entry) []const u8 {
        return e.key[0..e.name_len];
    }
};

const MetricFamily = struct {
    name: []u8,
    /// The help text with prometheus-client's trailing `.`.
    help: []u8,
    metric_type: encoding.MetricType,
    metric_ids: std.ArrayList(u32),
};

/// Holds every registered metric and encodes them in the OpenMetrics text format.
pub const Registry = struct {
    gpa: Allocator,
    lock: SpinLock = .{},
    /// Dense metric storage indexed by metric id; null slots are free.
    entries: std.ArrayList(?Entry) = .empty,
    /// Ids of null slots, reserved to hold every id so a release never allocates.
    free_ids: std.ArrayList(u32) = .empty,
    /// Families sorted by name.
    families: std.ArrayList(MetricFamily) = .empty,
    /// Entry keys to metric ids.
    keys: std.StringHashMapUnmanaged(u32) = .empty,

    pub fn init(gpa: Allocator) Registry {
        return .{ .gpa = gpa };
    }

    /// Every handle must be released first.
    pub fn deinit(registry: *Registry) void {
        assert(registry.keys.count() == 0);
        assert(registry.families.items.len == 0);
        assert(registry.free_ids.items.len == registry.entries.items.len);
        registry.entries.deinit(registry.gpa);
        registry.free_ids.deinit(registry.gpa);
        registry.families.deinit(registry.gpa);
        registry.keys.deinit(registry.gpa);
        registry.* = undefined;
    }

    /// Registers `metric` (taking ownership) under `name` with `attributes`, which must be
    /// sorted by key with unique keys. A duplicate key returns the existing metric and frees
    /// `metric`.
    pub fn register(
        registry: *Registry,
        name: []const u8,
        help: []const u8,
        attributes: []const Attribute,
        metric: anytype,
    ) Allocator.Error!Registered(@TypeOf(metric)) {
        const M = @TypeOf(metric);
        assert(name.len > 0);
        assert_sorted(attributes);
        var key_buffer: Writer.Allocating = .init(registry.gpa);
        defer key_buffer.deinit();
        write_key(&key_buffer.writer, name, attributes) catch return error.OutOfMemory;
        const key = key_buffer.written();

        registry.lock.lock();
        defer registry.lock.unlock();
        if (registry.keys.get(key)) |id| {
            const existing = registry.entry(id);
            const family = registry.families.items[registry.find_family(name).?];
            assert_help(family, name, help);
            if (!std.mem.eql(u8, existing.type_name, @typeName(M))) std.debug.panic(
                "duplicate metric `{s}` registered with different type",
                .{name},
            );
            existing.claims += 1;
            const box: *Box(M) = @ptrCast(@alignCast(existing.box));
            box.retain();
            var discarded = metric;
            if (comptime @hasDecl(M, "deinit")) discarded.deinit();
            return .{ .box = box, .registration = .{ .registry = registry, .id = id } };
        }
        const box = try Box(M).create(registry.gpa, metric);
        errdefer box.release();
        const id = try registry.insert(key, name, help, attributes, M.metric_type, .{
            .box = box,
            .vtable = &Box(M).vtable,
            .type_name = @typeName(M),
        });
        box.retain(); // The registry's reference.
        return .{ .box = box, .registration = .{ .registry = registry, .id = id } };
    }

    const Erased = struct { box: *anyopaque, vtable: *const VTable, type_name: []const u8 };

    /// Adds a new entry (and its family if needed). Called with the lock held; on error the
    /// registry is unchanged.
    fn insert(
        registry: *Registry,
        key: []const u8,
        name: []const u8,
        help: []const u8,
        attributes: []const Attribute,
        metric_type: encoding.MetricType,
        erased: Erased,
    ) Allocator.Error!u32 {
        const gpa = registry.gpa;
        const family_index = registry.find_family(name);
        if (family_index) |index| {
            const family = registry.families.items[index];
            assert_help(family, name, help);
            if (family.metric_type != metric_type) std.debug.panic(
                "metric family `{s}` registered with inconsistent metric type",
                .{name},
            );
        }
        const key_owned = try gpa.dupe(u8, key);
        errdefer gpa.free(key_owned);
        const const_labels = try encode_attributes(gpa, attributes);
        errdefer gpa.free(const_labels);
        try registry.keys.ensureUnusedCapacity(gpa, 1);
        try registry.entries.ensureUnusedCapacity(gpa, 1);
        try registry.free_ids.ensureTotalCapacity(gpa, registry.entries.items.len + 1);
        var new_family: ?MetricFamily = null;
        errdefer if (new_family) |*family| free_family(gpa, family);
        if (family_index) |index| {
            try registry.families.items[index].metric_ids.ensureUnusedCapacity(gpa, 1);
        } else {
            try registry.families.ensureUnusedCapacity(gpa, 1);
            new_family = try create_family(gpa, name, help, metric_type);
        }

        // Nothing below fails.
        const index = family_index orelse registry.insert_family(new_family.?);
        new_family = null;
        const family = &registry.families.items[index];
        const id = registry.free_ids.pop() orelse id: {
            registry.entries.appendAssumeCapacity(null);
            break :id @as(u32, @intCast(registry.entries.items.len - 1));
        };
        assert(registry.entries.items[id] == null);
        registry.entries.items[id] = .{
            .key = key_owned,
            .name_len = @intCast(name.len),
            .const_labels = const_labels,
            .box = erased.box,
            .vtable = erased.vtable,
            .type_name = erased.type_name,
            .claims = 1,
            .family_index = @intCast(family.metric_ids.items.len),
        };
        family.metric_ids.appendAssumeCapacity(id);
        registry.keys.putAssumeCapacityNoClobber(key_owned, id);
        return id;
    }

    fn insert_family(registry: *Registry, family: MetricFamily) usize {
        const index = std.sort.lowerBound(
            MetricFamily,
            registry.families.items,
            family.name,
            order_family,
        );
        registry.families.insertAssumeCapacity(index, family);
        return index;
    }

    fn find_family(registry: *const Registry, name: []const u8) ?usize {
        return std.sort.binarySearch(MetricFamily, registry.families.items, name, order_family);
    }

    fn entry(registry: *Registry, id: u32) *Entry {
        assert(id < registry.entries.items.len);
        return &(registry.entries.items[id].?);
    }

    fn release_registration(registry: *Registry, id: u32) void {
        registry.lock.lock();
        const released = registry.entry(id);
        assert(released.claims > 0);
        released.claims -= 1;
        if (released.claims > 0) {
            registry.lock.unlock();
            return;
        }
        const removed = released.*;
        registry.entries.items[id] = null;
        const key_removed = registry.keys.remove(removed.key);
        assert(key_removed);
        const family_index = registry.find_family(removed.name()).?;
        const family = &registry.families.items[family_index];
        const swapped = family.metric_ids.swapRemove(removed.family_index);
        assert(swapped == id);
        if (removed.family_index < family.metric_ids.items.len) {
            const moved = family.metric_ids.items[removed.family_index];
            registry.entry(moved).family_index = removed.family_index;
        }
        if (family.metric_ids.items.len == 0) {
            var empty = registry.families.orderedRemove(family_index);
            free_family(registry.gpa, &empty);
        }
        registry.free_ids.appendAssumeCapacity(id);
        registry.lock.unlock();
        registry.gpa.free(removed.key);
        registry.gpa.free(removed.const_labels);
        removed.vtable.release(removed.box);
    }

    /// Encodes every metric in the OpenMetrics text format, ending with `# EOF`.
    pub fn encode(registry: *Registry, gpa: Allocator) Allocator.Error![]u8 {
        var output: Writer.Allocating = .init(gpa);
        errdefer output.deinit();
        var samples: Writer.Allocating = .init(gpa);
        defer samples.deinit();
        registry.lock.lock();
        defer registry.lock.unlock();
        for (registry.families.items) |family| {
            assert(family.metric_ids.items.len > 0);
            samples.clearRetainingCapacity();
            for (family.metric_ids.items) |id| {
                const metric = registry.entry(id);
                metric.vtable.encode(metric.box, .{
                    .writer = &samples.writer,
                    .name = family.name,
                    .const_labels = metric.const_labels,
                }) catch return error.OutOfMemory;
            }
            // A family with no samples (an empty `Family`) writes no descriptor.
            if (samples.written().len == 0) continue;
            const writer = &output.writer;
            encoding.write_descriptor(writer, family.name, family.help, family.metric_type) catch
                return error.OutOfMemory;
            writer.writeAll(samples.written()) catch return error.OutOfMemory;
        }
        output.writer.writeAll("# EOF\n") catch return error.OutOfMemory;
        return output.toOwnedSlice();
    }

    /// Live registry entries (for tests and leak checks).
    pub fn count(registry: *Registry) usize {
        registry.lock.lock();
        defer registry.lock.unlock();
        assert(registry.keys.count() <= registry.entries.items.len);
        return registry.keys.count();
    }
};

fn order_family(name: []const u8, family: MetricFamily) std.math.Order {
    return std.mem.order(u8, name, family.name);
}

fn assert_help(family: MetricFamily, name: []const u8, help: []const u8) void {
    const matches = family.help.len == help.len + 1 and
        std.mem.eql(u8, family.help[0..help.len], help);
    if (!matches) std.debug.panic(
        "metric family `{s}` registered with inconsistent help text",
        .{name},
    );
}

fn create_family(
    gpa: Allocator,
    name: []const u8,
    help: []const u8,
    metric_type: encoding.MetricType,
) Allocator.Error!MetricFamily {
    const name_owned = try gpa.dupe(u8, name);
    errdefer gpa.free(name_owned);
    // prometheus-client's `Descriptor::new` appends a period to the help text.
    const help_owned = try std.mem.concat(gpa, u8, &.{ help, "." });
    errdefer gpa.free(help_owned);
    var metric_ids: std.ArrayList(u32) = .empty;
    try metric_ids.ensureUnusedCapacity(gpa, 1);
    return .{
        .name = name_owned,
        .help = help_owned,
        .metric_type = metric_type,
        .metric_ids = metric_ids,
    };
}

fn free_family(gpa: Allocator, family: *MetricFamily) void {
    gpa.free(family.name);
    gpa.free(family.help);
    family.metric_ids.deinit(gpa);
    family.* = undefined;
}

fn assert_sorted(attributes: []const Attribute) void {
    for (attributes, 0..) |attribute, index| {
        assert(is_valid_label(attribute.key));
        if (index > 0) {
            assert(std.mem.order(u8, attributes[index - 1].key, attribute.key) == .lt);
        }
    }
}

fn write_key(writer: *Writer, name: []const u8, attributes: []const Attribute) !void {
    try writer.writeAll(name);
    try writer.writeByte(0);
    for (attributes) |attribute| {
        try writer.writeInt(u32, @intCast(attribute.key.len), .little);
        try writer.writeAll(attribute.key);
        try writer.writeInt(u32, @intCast(attribute.value.len), .little);
        try writer.writeAll(attribute.value);
    }
}

fn encode_attributes(gpa: Allocator, attributes: []const Attribute) Allocator.Error![]u8 {
    var labels: Writer.Allocating = .init(gpa);
    errdefer labels.deinit();
    for (attributes, 0..) |attribute, index| {
        if (index > 0) labels.writer.writeByte(',') catch return error.OutOfMemory;
        labels.writer.print("{s}=\"{s}\"", .{ attribute.key, attribute.value }) catch
            return error.OutOfMemory;
    }
    return labels.toOwnedSlice();
}

/// Joins a metric or label prefix and a child name with `_` (commonware `prefixed_name`).
pub fn prefixed_name(buffer: []u8, prefix: []const u8, name: []const u8) []const u8 {
    if (prefix.len == 0) {
        @memcpy(buffer[0..name.len], name);
        return buffer[0..name.len];
    }
    const total = prefix.len + 1 + name.len;
    assert(total <= buffer.len);
    @memcpy(buffer[0..prefix.len], prefix);
    buffer[prefix.len] = '_';
    @memcpy(buffer[prefix.len + 1 .. total], name);
    return buffer[0..total];
}
