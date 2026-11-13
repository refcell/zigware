//! The metrics half of commonware's `Supervisor` + `Metrics` traits: a label prefix and a sorted
//! attribute list over a `Registry`. `child("engine")` appends to the prefix, so metrics
//! registered below it are named `engine_<name>`; `with_attribute("epoch", 5)` adds an
//! `epoch="5"` label to every metric registered below it without changing names.
//!
//! A `Scope` is a plain value with inline, bounded storage (no allocation, nothing to free), so
//! a runtime context can carry one and copy it into children. `register` and `encode` go to the
//! shared registry.

const std = @import("std");
const encoding = @import("encoding.zig");
const raw = @import("raw.zig");
const registry_module = @import("registry.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Registry = registry_module.Registry;
const Registered = registry_module.Registered;
const Attribute = registry_module.Attribute;

/// Longest label prefix (all `child` labels joined by `_`).
pub const prefix_size_max = 128;
/// Longest metric name passed to `register`.
pub const name_size_max = 64;
/// Most attributes on one scope.
pub const attribute_count_max = 4;
/// Longest attribute value (a hex-encoded 48-byte public key is 96).
pub const attribute_value_size_max = 96;

const StoredAttribute = struct {
    key: []const u8,
    value_buffer: [attribute_value_size_max]u8,
    value_len: u8,

    fn value(stored: *const StoredAttribute) []const u8 {
        return stored.value_buffer[0..stored.value_len];
    }
};

pub const Scope = struct {
    comptime {
        // Small enough to copy into a spawned task's closure with room to spare.
        assert(@sizeOf(Scope) <= 640);
    }

    registry: *Registry,
    prefix_buffer: [prefix_size_max]u8 = undefined,
    prefix_len: u8 = 0,
    attributes: [attribute_count_max]StoredAttribute = undefined,
    attribute_count: u8 = 0,

    /// The root scope: empty prefix, no attributes.
    pub fn init(registry: *Registry) Scope {
        return .{ .registry = registry };
    }

    pub fn prefix(scope: *const Scope) []const u8 {
        return scope.prefix_buffer[0..scope.prefix_len];
    }

    /// The scope's attributes, sorted by key.
    pub fn attribute(scope: *const Scope, index: usize) Attribute {
        assert(index < scope.attribute_count);
        const stored = &scope.attributes[index];
        return .{ .key = stored.key, .value = stored.value() };
    }

    /// A child scope named `<prefix>_<label>` (commonware `Supervisor::child`). Panics if
    /// `label` is not `[a-zA-Z][a-zA-Z0-9_]*` or the name starts with the reserved
    /// `runtime` prefix.
    pub fn child(scope: Scope, label: []const u8) Scope {
        registry_module.validate_label(label);
        const result = scope.sub_registry(label);
        if (std.mem.startsWith(u8, result.prefix(), registry_module.metrics_prefix)) {
            @panic("using runtime label is not allowed");
        }
        return result;
    }

    /// A child scope without the reserved-prefix check, for the runtime's own metrics
    /// (commonware `Register::sub_registry`).
    pub fn sub_registry(scope: Scope, label: []const u8) Scope {
        registry_module.validate_label(label);
        var result = scope;
        var buffer: [prefix_size_max]u8 = undefined;
        assert(scope.prefix().len + 1 + label.len <= prefix_size_max);
        const name = registry_module.prefixed_name(&buffer, scope.prefix(), label);
        @memcpy(result.prefix_buffer[0..name.len], name);
        result.prefix_len = @intCast(name.len);
        assert(std.mem.endsWith(u8, result.prefix(), label));
        return result;
    }

    /// Adds `key="value"` to every metric registered in this scope and its children
    /// (commonware `Supervisor::with_attribute`). An existing key's value is replaced. `key`
    /// must outlive the scope (commonware takes `&'static str`); `value` is formatted like a
    /// label value (strings verbatim, integers in decimal, `{f}` for formattable types).
    pub fn with_attribute(scope: Scope, key: []const u8, value: anytype) Scope {
        registry_module.validate_label(key);
        var stored: StoredAttribute = .{ .key = key, .value_buffer = undefined, .value_len = 0 };
        var writer: Writer = .fixed(&stored.value_buffer);
        encoding.write_label_value(&writer, value) catch @panic("attribute value too long");
        stored.value_len = @intCast(writer.buffered().len);
        var result = scope;
        const keys = result.attributes[0..result.attribute_count];
        for (keys, 0..) |*existing, index| {
            switch (std.mem.order(u8, existing.key, key)) {
                .lt => continue,
                .eq => existing.* = stored,
                .gt => {
                    assert(result.attribute_count < attribute_count_max);
                    std.mem.copyBackwards(
                        StoredAttribute,
                        result.attributes[index + 1 .. result.attribute_count + 1],
                        result.attributes[index..result.attribute_count],
                    );
                    result.attributes[index] = stored;
                    result.attribute_count += 1;
                },
            }
            return result;
        }
        assert(result.attribute_count < attribute_count_max);
        result.attributes[result.attribute_count] = stored;
        result.attribute_count += 1;
        return result;
    }

    /// Registers `metric` as `<prefix>_<name>` with this scope's attributes (commonware
    /// `Metrics::register`). Keep the handle for as long as the metric should be exposed.
    pub fn register(
        scope: *const Scope,
        name: []const u8,
        help: []const u8,
        metric: anytype,
    ) Allocator.Error!Registered(@TypeOf(metric)) {
        registry_module.validate_label(name);
        assert(name.len <= name_size_max);
        var name_buffer: [prefix_size_max + 1 + name_size_max]u8 = undefined;
        const full_name = registry_module.prefixed_name(&name_buffer, scope.prefix(), name);
        var attributes: [attribute_count_max]Attribute = undefined;
        for (0..scope.attribute_count) |index| attributes[index] = scope.attribute(index);
        return scope.registry.register(
            full_name,
            help,
            attributes[0..scope.attribute_count],
            metric,
        );
    }

    /// Registers a counter (commonware `MetricsExt::counter`).
    pub fn counter(
        scope: *const Scope,
        name: []const u8,
        help: []const u8,
    ) Allocator.Error!Registered(raw.Counter) {
        return scope.register(name, help, raw.Counter{});
    }

    /// Registers a gauge (commonware `MetricsExt::gauge`).
    pub fn gauge(
        scope: *const Scope,
        name: []const u8,
        help: []const u8,
    ) Allocator.Error!Registered(raw.Gauge) {
        return scope.register(name, help, raw.Gauge{});
    }

    /// Registers a histogram over `buckets` (commonware `MetricsExt::histogram`).
    pub fn histogram(
        scope: *const Scope,
        name: []const u8,
        help: []const u8,
        buckets: []const f64,
    ) Allocator.Error!Registered(raw.Histogram) {
        return scope.register(name, help, raw.Histogram.init(buckets));
    }

    /// Registers a family of `M` keyed by label set `L` (commonware `MetricsExt::family`).
    pub fn family(
        scope: *const Scope,
        comptime L: type,
        comptime M: type,
        name: []const u8,
        help: []const u8,
    ) Allocator.Error!Registered(raw.Family(L, M)) {
        return scope.register(name, help, raw.Family(L, M).init(scope.registry.gpa));
    }

    /// Encodes every metric in the registry (commonware `Metrics::encode`).
    pub fn encode(scope: *const Scope, gpa: Allocator) Allocator.Error![]u8 {
        return scope.registry.encode(gpa);
    }
};
