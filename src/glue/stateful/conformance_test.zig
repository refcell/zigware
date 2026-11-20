//! `CodecConformance` hashes of the stateful types, checked against commonware's glue
//! `conformance.toml`. Commonware draws them over the simplex mock scheme and SHA-256
//! commitments (its `TestScheme` with `Sha256Digest`, and the probe tests' `Scheme` with
//! `Standard<Block>`). Their wire types stand in below with the `Arbitrary` impls those draws
//! use, as consensus's own conformance tests do, so the encoded values match commonware's.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const plan = @import("actor/syncer/plan.zig");
const wire = @import("probe/wire.zig");

const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const ArbitraryError = arbitrary.Error;
const value_of = arbitrary.value;
const Sha256 = cryptography.Sha256;

/// `sha256::Digest`, whose `Arbitrary` hashes up to 256 arbitrary bytes.
const Digest = struct {
    inner: Sha256.Digest,

    pub const fixed_size: usize = 32;

    pub fn write(self: Digest, writer: *codec.Writer) void {
        self.inner.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Digest {
        return .{ .inner = try Sha256.Digest.read(gpa, reader, {}) };
    }

    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!Digest {
        const len = u.int_in_range(u64, 0, 256);
        const data = try gpa.alloc(u8, len);
        try u.bytes(data);
        assert(data.len <= 256);
        return .{ .inner = Sha256.hash(&.{data}) };
    }
};

/// The mock scheme's certificate, `sequence::U64`, whose derived `Arbitrary` draws its
/// eight bytes.
const MockCertificate = struct {
    bytes: [8]u8,

    pub const fixed_size: usize = 8;

    pub fn write(self: MockCertificate, writer: *codec.Writer) void {
        writer.write_bytes(&self.bytes);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!MockCertificate {
        return .{ .bytes = (try reader.take_array(8)).* };
    }

    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!MockCertificate {
        return .{ .bytes = try value_of([8]u8, gpa, u) };
    }
};

/// The parts of `mocks::Scheme` a finalization's encoding reads.
const Scheme = struct {
    pub const Certificate = MockCertificate;

    pub fn max_certificate_size(_: u32) usize {
        return MockCertificate.fixed_size;
    }
};
/// `Standard<Block>`'s commitment is the block digest, all the probe's `Message` reads of it.
const Variant = struct {
    pub const Commitment = Digest;
};

const file = @embedFile("../conformance.toml");
const prefix = "commonware_glue::stateful::";

fn CodecConformance(comptime T: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = arbitrary.default_generator(T);
            const value = try arbitrary.generate(T, gen, arena.allocator(), seed);
            const encoded = try codec.encode(T, gpa, value);
            assert(encoded.len == value.encode_size());
            return encoded;
        }
    };
}

/// `Tag` encodes as its one byte.
const TagConformance = struct {
    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        const gen = arbitrary.default_generator(wire.Tag);
        const tag = try arbitrary.generate(wire.Tag, gen, gpa, seed);
        const encoded = try gpa.dupe(u8, &.{@backingInt(tag)});
        assert(encoded[0] <= 1);
        return encoded;
    }
};

fn verify(comptime C: type, comptime name: []const u8) !void {
    const cases = conformance.default_cases;
    try conformance.verify(C, std.testing.allocator, prefix ++ name, cases, file);
}

test "stateful conformance: CodecConformance<SyncState<TestScheme,Sha256Digest>>" {
    try verify(
        CodecConformance(plan.SyncState(Scheme, Digest)),
        "actor::syncer::tests::conformance::CodecConformance<SyncState<TestScheme,Sha256Digest>>",
    );
}

test "stateful conformance: CodecConformance<wire::Message<Scheme,Variant>>" {
    try verify(
        CodecConformance(wire.Message(Scheme, Variant)),
        "probe::test::conformance::CodecConformance<wire::Message<Scheme,Variant>>",
    );
}

test "stateful conformance: CodecConformance<wire::Tag>" {
    try verify(TagConformance, "probe::test::conformance::CodecConformance<wire::Tag>");
}
