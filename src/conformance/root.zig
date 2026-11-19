//! conformance: Automatically assert the stability of encoding and mechanisms over time.
//!
//! Zig port of commonware's `commonware-conformance` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/conformance).
//!
//! A conformance type produces deterministic bytes from a seed:
//!
//! ```zig
//! pub fn commit(gpa: Allocator, seed: u64) ![]u8   // caller frees
//! ```
//!
//! `compute_hash` commits seeds `0..n_cases` and hashes every commitment, each prefixed by its
//! length as a little-endian u64, with SHA-256; the hex digest is compared against the entry
//! stored under the type's name in a committed TOML file:
//!
//! ```toml
//! ["Vec<u8>"]
//! n_cases = 100
//! hash = "abc123..."
//! ```
//!
//! Library code does no file I/O, so callers `@embedFile` the TOML and pass its text to
//! `verify`. commonware adds a missing entry to the file automatically; zigware fails and
//! prints the entry to add instead.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const formatting = @import("formatting");

/// Default number of cases when a test does not specify one.
pub const default_cases: u64 = 65536;

/// Hex-encoded SHA-256 digest.
pub const Hash = [Sha256.digest_length * 2]u8;

/// Conformance data for one type.
pub const Entry = struct {
    /// Number of cases that were hashed together.
    n_cases: u64,
    /// Hex-encoded SHA-256 of every commitment.
    hash: []const u8,
};

pub const ParseError = error{InvalidConformanceFile};

/// Longest conformance file `find` scans, in lines.
const lines_max = 1 << 20;

/// Finds the entry for `type_name` in the text of a conformance TOML file.
pub fn find(text: []const u8, type_name: []const u8) ParseError!?Entry {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var in_section = false;
    var n_cases: ?u64 = null;
    var hash: ?[]const u8 = null;
    var count: usize = 0;
    while (lines.next()) |raw| : (count += 1) {
        if (count >= lines_max) return error.InvalidConformanceFile;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (line[0] == '[') {
            if (in_section) break;
            const name = try parse_section(line);
            in_section = escaped_eql(name, type_name);
            continue;
        }
        if (!in_section) continue;
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse
            return error.InvalidConformanceFile;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t");
        if (std.mem.eql(u8, key, "n_cases")) {
            n_cases = std.fmt.parseInt(u64, value, 10) catch return error.InvalidConformanceFile;
        } else if (std.mem.eql(u8, key, "hash")) {
            hash = try parse_string(value);
        }
    }
    if (!in_section) return null;
    return .{
        .n_cases = n_cases orelse return error.InvalidConformanceFile,
        .hash = hash orelse return error.InvalidConformanceFile,
    };
}

/// Parses `["name"]` (or `[name]`) and returns the name.
fn parse_section(line: []const u8) ParseError![]const u8 {
    if (line.len < 2 or line[line.len - 1] != ']') return error.InvalidConformanceFile;
    const inner = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
    if (inner.len > 0 and inner[0] == '"') return parse_string(inner);
    return inner;
}

/// Parses a basic TOML string and returns its raw contents, escapes still in place. Only the
/// escapes `\n`, `\t`, `\"`, and `\\` are accepted (commonware's type names wrap with
/// `\n`).
fn parse_string(value: []const u8) ParseError![]const u8 {
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') {
        return error.InvalidConformanceFile;
    }
    const inner = value[1 .. value.len - 1];
    var index: usize = 0;
    while (index < inner.len) : (index += 1) {
        switch (inner[index]) {
            '"' => return error.InvalidConformanceFile,
            '\\' => {
                index += 1;
                if (index == inner.len) return error.InvalidConformanceFile;
                if (std.mem.indexOfScalar(u8, "nt\"\\", inner[index]) == null) {
                    return error.InvalidConformanceFile;
                }
            },
            else => {},
        }
    }
    return inner;
}

/// Whether the raw string contents `raw` (as `parse_string` returns them) unescape to `name`.
fn escaped_eql(raw: []const u8, name: []const u8) bool {
    var raw_index: usize = 0;
    var name_index: usize = 0;
    while (raw_index < raw.len) : (raw_index += 1) {
        var byte = raw[raw_index];
        if (byte == '\\') {
            raw_index += 1;
            if (raw_index == raw.len) return false;
            byte = switch (raw[raw_index]) {
                'n' => '\n',
                't' => '\t',
                else => |escaped| escaped,
            };
        }
        if (name_index == name.len or name[name_index] != byte) return false;
        name_index += 1;
    }
    return name_index == name.len;
}

/// Commits seeds `0..n_cases` with `C.commit` and returns the hex SHA-256 of every
/// commitment, each prefixed by its length as a little-endian u64.
pub fn compute_hash(comptime C: type, gpa: Allocator, n_cases: u64) !Hash {
    var hasher = Sha256.init(.{});
    var seed: u64 = 0;
    while (seed < n_cases) : (seed += 1) {
        const committed = try C.commit(gpa, seed);
        defer gpa.free(committed);
        var prefix: [8]u8 = undefined;
        std.mem.writeInt(u64, &prefix, committed.len, .little);
        hasher.update(&prefix);
        hasher.update(committed);
    }
    assert(seed == n_cases);
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    var result: Hash = undefined;
    const written = formatting.hex_encode(&result, &digest);
    assert(written.len == result.len);
    return result;
}

/// Seeds one task of `compute_hash_parallel` commits at a time.
pub const chunk_cases: u64 = 256;

/// The most tasks `compute_hash_parallel` runs at once.
pub const max_workers = 64;

/// The length-prefixed commitments of one chunk of seeds, in seed order.
const Chunk = struct {
    bytes: std.ArrayList(u8) = .empty,

    fn commit(comptime C: type, gpa: Allocator, chunk: *Chunk, first: u64, end: u64) !void {
        assert(first < end and end - first <= chunk_cases);
        chunk.bytes.clearRetainingCapacity();
        var seed = first;
        while (seed < end) : (seed += 1) {
            const committed = try C.commit(gpa, seed);
            defer gpa.free(committed);
            var prefix: [8]u8 = undefined;
            std.mem.writeInt(u64, &prefix, committed.len, .little);
            try chunk.bytes.appendSlice(gpa, &prefix);
            try chunk.bytes.appendSlice(gpa, committed);
        }
        assert(seed == end);
    }
};

/// `Chunk.commit` for one `C`, as a task `std.Io.concurrent` can run.
fn Task(comptime C: type) type {
    return struct {
        fn run(gpa: Allocator, chunk: *Chunk, first: u64, end: u64) anyerror!void {
            return Chunk.commit(C, gpa, chunk, first, end);
        }
    };
}

/// `compute_hash` with the commitments computed by up to `workers` tasks on `io`, which must
/// allow concurrency, in rounds of `workers` chunks of `chunk_cases` seeds. The caller's
/// thread hashes each round's chunks in seed order, so the hash is `compute_hash`'s. `C.commit`
/// must be safe to call from several threads at once, and `gpa` thread-safe.
pub fn compute_hash_parallel(
    comptime C: type,
    gpa: Allocator,
    io: std.Io,
    workers: u32,
    n_cases: u64,
) !Hash {
    assert(workers >= 1 and workers <= max_workers);
    var chunks: [max_workers]Chunk = @splat(.{});
    defer for (&chunks) |*chunk| chunk.bytes.deinit(gpa);
    var hasher = Sha256.init(.{});
    var next: u64 = 0;
    while (next < n_cases) {
        const round_start = next;
        const count = try commit_round(C, gpa, io, chunks[0..workers], &next, n_cases);
        assert(count > 0 and next > round_start);
        for (chunks[0..count]) |*chunk| hasher.update(chunk.bytes.items);
    }
    assert(next == n_cases);
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    var result: Hash = undefined;
    const written = formatting.hex_encode(&result, &digest);
    assert(written.len == result.len);
    return result;
}

/// Commits the next chunks from `next.*` into `chunks`, one task each, and returns how many
/// it filled. Every task is awaited before an error returns.
fn commit_round(
    comptime C: type,
    gpa: Allocator,
    io: std.Io,
    chunks: []Chunk,
    next: *u64,
    n_cases: u64,
) !usize {
    assert(chunks.len > 0 and next.* < n_cases);
    var futures: [max_workers]?std.Io.Future(anyerror!void) = @splat(null);
    var count: usize = 0;
    var first_error: anyerror!void = {};
    while (count < chunks.len and next.* < n_cases) : (count += 1) {
        const end = @min(n_cases, next.* + chunk_cases);
        const run = Task(C).run;
        futures[count] = io.concurrent(run, .{ gpa, &chunks[count], next.*, end }) catch null;
        // Without a free task, the caller commits this chunk itself.
        if (futures[count] == null) first_error = run(gpa, &chunks[count], next.*, end);
        next.* = end;
        if (first_error) |_| {} else |_| {
            count += 1;
            break;
        }
    }
    for (futures[0..count]) |*maybe| {
        const future = &(maybe.* orelse continue);
        const result = future.await(io);
        if (first_error) |_| first_error = result else |_| {}
    }
    try first_error;
    return count;
}

pub const VerifyError = error{ ConformanceMismatch, ConformanceMissing } || ParseError;

/// Checks that `C` still produces the hash recorded for `type_name` in `file_text`.
pub fn verify(
    comptime C: type,
    gpa: Allocator,
    type_name: []const u8,
    n_cases: u64,
    file_text: []const u8,
) !void {
    const actual = try compute_hash(C, gpa, n_cases);
    return check(actual, type_name, n_cases, file_text);
}

/// `verify` on `compute_hash_parallel`'s hash (the same hash, computed by `workers` tasks).
pub fn verify_parallel(
    comptime C: type,
    gpa: Allocator,
    io: std.Io,
    workers: u32,
    type_name: []const u8,
    n_cases: u64,
    file_text: []const u8,
) !void {
    const actual = try compute_hash_parallel(C, gpa, io, workers, n_cases);
    return check(actual, type_name, n_cases, file_text);
}

/// Compares a computed hash with the entry recorded for `type_name`.
fn check(actual: Hash, type_name: []const u8, n_cases: u64, file_text: []const u8) !void {
    const entry = try find(file_text, type_name) orelse {
        std.debug.print(
            \\conformance: no entry for '{s}'. Add it:
            \\["{s}"]
            \\n_cases = {d}
            \\hash = "{s}"
            \\
        , .{ type_name, type_name, n_cases, actual });
        return error.ConformanceMissing;
    };
    if (entry.n_cases != n_cases) {
        std.debug.print("conformance: '{s}' n_cases mismatch: expected {d}, got {d}\n", .{
            type_name, entry.n_cases, n_cases,
        });
        return error.ConformanceMismatch;
    }
    if (!std.mem.eql(u8, entry.hash, &actual)) {
        std.debug.print("conformance: '{s}' format changed:\n  expected: {s}\n  actual:   {s}\n", .{
            type_name, entry.hash, actual,
        });
        return error.ConformanceMismatch;
    }
}

const testing = std.testing;

/// Commits the seed's little-endian bytes, like commonware's `SimpleConformance`.
const SimpleConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        const out = try gpa.alloc(u8, 8);
        std.mem.writeInt(u64, out[0..8], seed, .little);
        return out;
    }
};

test "compute hash is deterministic" {
    const a = try compute_hash(SimpleConformance, testing.allocator, 1);
    const b = try compute_hash(SimpleConformance, testing.allocator, 1);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "compute hash depends on n_cases" {
    const a = try compute_hash(SimpleConformance, testing.allocator, 10);
    const b = try compute_hash(SimpleConformance, testing.allocator, 20);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "compute hash matches its definition" {
    // One case: sha256(le64(8) ++ le64(0)).
    const input = [_]u8{ 8, 0, 0, 0, 0, 0, 0, 0 } ++ @as([8]u8, @splat(0));
    var expected_digest: [32]u8 = undefined;
    Sha256.hash(&input, &expected_digest, .{});
    var expected: Hash = undefined;
    _ = formatting.hex_encode(&expected, &expected_digest);
    const actual = try compute_hash(SimpleConformance, testing.allocator, 1);
    try testing.expectEqualSlices(u8, &expected, &actual);
}

test "compute hash parallel matches compute hash" {
    // Case counts on both sides of a chunk boundary and of a round boundary, so a dropped,
    // repeated, or reordered chunk changes the hash.
    const n = chunk_cases;
    const counts = [_]u64{ 0, 1, n - 1, n, n + 1, 3 * n + 7 };
    for (counts) |n_cases| {
        const expected = try compute_hash(SimpleConformance, testing.allocator, n_cases);
        for ([_]u32{ 1, 2, 3 }) |workers| {
            const actual = try compute_hash_parallel(
                SimpleConformance,
                testing.allocator,
                testing.io,
                workers,
                n_cases,
            );
            try testing.expectEqualSlices(u8, &expected, &actual);
        }
    }
}

test "conformance file names with escapes" {
    const text =
        \\["a<b\nc>"]
        \\n_cases = 3
        \\hash = "ff"
        \\["later"]
        \\n_cases = 1
        \\hash = "00"
    ;
    const entry = (try find(text, "a<b\nc>")).?;
    try testing.expectEqual(@as(u64, 3), entry.n_cases);
    try testing.expectEqual(null, try find(text, "a<bnc>"));
    try testing.expectEqualStrings("00", (try find(text, "later")).?.hash);
}

test "conformance file parse" {
    const text =
        \\
        \\["u32"]
        \\n_cases = 100
        \\hash = "abc123"
        \\
        \\["Vec<u8>"]
        \\n_cases = 50
        \\hash = "def456"
        \\
    ;
    const u32_entry = (try find(text, "u32")).?;
    try testing.expectEqual(@as(u64, 100), u32_entry.n_cases);
    try testing.expectEqualStrings("abc123", u32_entry.hash);
    const vec_entry = (try find(text, "Vec<u8>")).?;
    try testing.expectEqual(@as(u64, 50), vec_entry.n_cases);
    try testing.expectEqualStrings("def456", vec_entry.hash);
    try testing.expectEqual(@as(?Entry, null), try find(text, "u64"));
    try testing.expectError(error.InvalidConformanceFile, find("[\"x\"]\nn_cases = y\n", "x"));
}

test "verify reports mismatches" {
    const actual = try compute_hash(SimpleConformance, testing.allocator, 2);
    var good_buffer: [128]u8 = undefined;
    const good = try std.fmt.bufPrint(&good_buffer, "[\"s\"]\nn_cases = 2\nhash = \"{s}\"\n", .{
        actual,
    });
    try verify(SimpleConformance, testing.allocator, "s", 2, good);
}
