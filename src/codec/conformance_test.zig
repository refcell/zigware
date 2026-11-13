//! Codec conformance (codec/src/conformance.rs and every `conformance_tests!` in codec).
//!
//! Each entry regenerates commonware's 65536 values per type with the same `arbitrary` +
//! ChaCha8 inputs, encodes them with zigware, and checks the SHA-256 against the hash
//! committed in commonware's `codec/conformance.toml` (copied here unchanged). A match proves
//! the encodings are byte-identical to commonware's.

const std = @import("std");
const Allocator = std.mem.Allocator;
const conformance = @import("conformance");
const codec = @import("codec.zig");
const arbitrary = @import("arbitrary.zig");
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;
const varint = @import("varint.zig");
const Bytes = @import("types/bytes.zig").Bytes;
const map = @import("types/map.zig");
const net = @import("types/net.zig");
const Modes = @import("mode.zig").Modes;
const NonZero = @import("types/nonzero.zig").NonZero;

const conformance_file = @embedFile("conformance.toml");
const prefix = "commonware_codec::";

fn CodecConformance(comptime T: type, comptime gen: arbitrary.Generator(T)) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn Entry(comptime name: []const u8, comptime T: type, comptime gen: arbitrary.Generator(T)) type {
    return struct {
        const type_name = prefix ++ name;
        const Conformance = CodecConformance(T, gen);
    };
}

fn Default(comptime name: []const u8, comptime T: type) type {
    return Entry(name, T, arbitrary.default_generator(T));
}

fn gen_uint(comptime T: type) arbitrary.Generator(varint.UInt(T)) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!varint.UInt(T) {
            return .{ .value = try arbitrary.value(T, gpa, u) };
        }
    }.generate;
}

fn gen_sint(comptime S: type) arbitrary.Generator(varint.SInt(S)) {
    return struct {
        fn generate(_: Allocator, u: *Unstructured) Error!varint.SInt(S) {
            return .{ .value = u.int(S) };
        }
    }.generate;
}

fn gen_nonzero(comptime T: type) arbitrary.Generator(NonZero(T)) {
    return struct {
        fn generate(_: Allocator, u: *Unstructured) Error!NonZero(T) {
            return NonZero(T).init(u.int(T)) orelse error.IncorrectFormat;
        }
    }.generate;
}

/// The conformance-only `Bytes` wrapper: a u8 length, then up to that many iterator items.
fn gen_bytes(gpa: Allocator, u: *Unstructured) Error!Bytes {
    const len = u.int(u8);
    var list: std.ArrayList(u8) = .empty;
    while (list.items.len < len and u.keep_going()) try list.append(gpa, u.int(u8));
    return .init(list.items);
}

/// `arbitrary_iter().collect()` into a map: a later duplicate key replaces the value.
fn gen_map(comptime M: type) arbitrary.Generator(M) {
    const K = @FieldType(M.Entry, "key");
    const V = @FieldType(M.Entry, "value");
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!M {
            var list: std.ArrayList(M.Entry) = .empty;
            next: while (u.keep_going()) {
                const key = try arbitrary.value(K, gpa, u);
                const value = try arbitrary.value(V, gpa, u);
                for (list.items) |*entry| {
                    if (entry.key == key) {
                        entry.value = value;
                        continue :next;
                    }
                }
                try list.append(gpa, .{ .key = key, .value = value });
            }
            M.sort(list.items);
            return M.init(list.items);
        }
    }.generate;
}

/// `arbitrary_iter().collect()` into a set: duplicates collapse.
fn gen_set(comptime S: type) arbitrary.Generator(S) {
    const K = @typeInfo(@FieldType(S, "items")).pointer.child;
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!S {
            var list: std.ArrayList(K) = .empty;
            while (u.keep_going()) {
                const item = try arbitrary.value(K, gpa, u);
                if (std.mem.indexOfScalar(K, list.items, item) == null) {
                    try list.append(gpa, item);
                }
            }
            S.sort(list.items);
            return S.init(list.items);
        }
    }.generate;
}

/// `Ipv4Addr::from(u32::arbitrary)`: the value's big-endian bytes.
fn ipv4(u: *Unstructured) net.Ipv4 {
    var octets: [4]u8 = undefined;
    std.mem.writeInt(u32, &octets, u.int(u32), .big);
    return .{ .octets = octets };
}

fn ipv6(u: *Unstructured) net.Ipv6 {
    var octets: [16]u8 = undefined;
    std.mem.writeInt(u128, &octets, u.int(u128), .big);
    return .{ .octets = octets };
}

fn gen_ipv4(_: Allocator, u: *Unstructured) Error!net.Ipv4 {
    return ipv4(u);
}

fn gen_ipv6(_: Allocator, u: *Unstructured) Error!net.Ipv6 {
    return ipv6(u);
}

fn gen_socket_v4(_: Allocator, u: *Unstructured) Error!net.SocketAddrV4 {
    const ip = ipv4(u);
    return .{ .ip = ip, .port = u.int(u16) };
}

/// Rust draws a flowinfo and a scope id too; the codec does not encode them.
fn gen_socket_v6(_: Allocator, u: *Unstructured) Error!net.SocketAddrV6 {
    const ip = ipv6(u);
    const port = u.int(u16);
    _ = u.int(u32);
    _ = u.int(u32);
    return .{ .ip = ip, .port = port };
}

fn gen_ip(_: Allocator, u: *Unstructured) Error!net.IpAddr {
    if (u.boolean()) return .{ .v4 = ipv4(u) };
    return .{ .v6 = ipv6(u) };
}

fn gen_socket(gpa: Allocator, u: *Unstructured) Error!net.SocketAddr {
    if (u.boolean()) {
        const v4 = try gen_socket_v4(gpa, u);
        return .{ .ip = .{ .v4 = v4.ip }, .port = v4.port };
    }
    const v6 = try gen_socket_v6(gpa, u);
    return .{ .ip = .{ .v6 = v6.ip }, .port = v6.port };
}

fn gen_modes(comptime N: usize) arbitrary.Generator(Modes(N)) {
    return struct {
        fn generate(_: Allocator, u: *Unstructured) Error!Modes(N) {
            const len: usize = @intCast(u.int_in_range(u64, 1, N));
            var modes: [N]u7 = @splat(0);
            for (modes[0 .. len - 1]) |*mode| mode.* = @intCast(u.int_in_range(u8, 0, 127));
            modes[len - 1] = @intCast(u.int_in_range(u8, 1, 127));
            return Modes(N).init(modes) orelse error.IncorrectFormat;
        }
    }.generate;
}

const primitives = "types::primitives::tests::conformance::CodecConformance<";
const tuples = "types::tuple::tests::conformance::CodecConformance<";
const vecs = "types::vec::tests::conformance::CodecConformance<";
const nets = "types::net::test::conformance::CodecConformance<";
const varints = "varint::tests::conformance::CodecConformance<";

const entries = .{
    Default("codec::tests::conformance::CodecConformance<Arc<Vec<u8>>>", *const []const u8),
    Default("codec::tests::conformance::CodecConformance<Arc<u64>>", *const u64),
    Entry("mode::tests::conformance::CodecConformance<Modes<1>>", Modes(1), gen_modes(1)),
    Entry("mode::tests::conformance::CodecConformance<Modes<2>>", Modes(2), gen_modes(2)),
    Entry(
        "types::btree_map::tests::conformance::CodecConformance<BTreeMap<u32,u32>>",
        map.Map(u32, u32),
        gen_map(map.Map(u32, u32)),
    ),
    Entry(
        "types::btree_set::tests::conformance::CodecConformance<BTreeSet<u8>>",
        map.Set(u8),
        gen_set(map.Set(u8)),
    ),
    Entry("types::bytes::tests::conformance::CodecConformance<Bytes>", Bytes, gen_bytes),
    Entry(
        "types::hash_map::tests::conformance::CodecConformance<HashMap<u32,u32>>",
        map.HashMap(u32, u32),
        gen_map(map.HashMap(u32, u32)),
    ),
    Entry(
        "types::hash_set::tests::conformance::CodecConformance<HashSet<u32>>",
        map.HashSet(u32),
        gen_set(map.HashSet(u32)),
    ),
    Entry(nets ++ "IpAddr>", net.IpAddr, gen_ip),
    Entry(nets ++ "Ipv4Addr>", net.Ipv4, gen_ipv4),
    Entry(nets ++ "Ipv6Addr>", net.Ipv6, gen_ipv6),
    Entry(nets ++ "SocketAddr>", net.SocketAddr, gen_socket),
    Entry(nets ++ "SocketAddrV4>", net.SocketAddrV4, gen_socket_v4),
    Entry(nets ++ "SocketAddrV6>", net.SocketAddrV6, gen_socket_v6),
    Entry(primitives ++ "NonZeroU16>", NonZero(u16), gen_nonzero(u16)),
    Entry(primitives ++ "NonZeroU32>", NonZero(u32), gen_nonzero(u32)),
    Entry(primitives ++ "NonZeroU64>", NonZero(u64), gen_nonzero(u64)),
    Default(primitives ++ "Option<u64>>", ?u64),
    Default(primitives ++ "[u8;32]>", [32]u8),
    Default(primitives ++ "bool>", bool),
    Default(primitives ++ "f32>", f32),
    Default(primitives ++ "f64>", f64),
    Default(primitives ++ "i128>", i128),
    Default(primitives ++ "i16>", i16),
    Default(primitives ++ "i32>", i32),
    Default(primitives ++ "i64>", i64),
    Default(primitives ++ "i8>", i8),
    Default(primitives ++ "u128>", u128),
    Default(primitives ++ "u16>", u16),
    Default(primitives ++ "u32>", u32),
    Default(primitives ++ "u64>", u64),
    Default(primitives ++ "u8>", u8),
    Default(tuples ++ "(u32,u32)>", struct { u32, u32 }),
    Default(tuples ++ "(u32,u32,u32)>", struct { u32, u32, u32 }),
    Default(tuples ++ "(u32,u32,u32,u32)>", struct { u32, u32, u32, u32 }),
    Default(tuples ++ "(u32,u32,u32,u32,u32)>", struct { u32, u32, u32, u32, u32 }),
    Default(tuples ++ "(u32,u32,u32,u32,u32,u32)>", struct { u32, u32, u32, u32, u32, u32 }),
    Default(vecs ++ "Vec<u16>>", []const u16),
    Default(vecs ++ "Vec<u32>>", []const u32),
    Default(vecs ++ "Vec<u8>>", []const u8),
    Default("uint::tests::conformance::CodecConformance<U256>", u256),
    Entry(varints ++ "SInt<i128>>", varint.SInt(i128), gen_sint(i128)),
    Entry(varints ++ "SInt<i16>>", varint.SInt(i16), gen_sint(i16)),
    Entry(varints ++ "SInt<i32>>", varint.SInt(i32), gen_sint(i32)),
    Entry(varints ++ "SInt<i64>>", varint.SInt(i64), gen_sint(i64)),
    Entry(varints ++ "UInt<U256>>", varint.UInt(u256), gen_uint(u256)),
    Entry(varints ++ "UInt<u128>>", varint.UInt(u128), gen_uint(u128)),
    Entry(varints ++ "UInt<u16>>", varint.UInt(u16), gen_uint(u16)),
    Entry(varints ++ "UInt<u32>>", varint.UInt(u32), gen_uint(u32)),
    Entry(varints ++ "UInt<u64>>", varint.UInt(u64), gen_uint(u64)),
};

// 3.3M values through the leak-checking testing allocator take 30s in Debug, so this uses the
// general-purpose allocator; leak checks for these types live in their own tests.
test "codec conformance hashes match commonware" {
    comptime std.debug.assert(entries.len == 51);
    inline for (entries) |entry| {
        try conformance.verify(
            entry.Conformance,
            std.heap.smp_allocator,
            entry.type_name,
            conformance.default_cases,
            conformance_file,
        );
    }
}
