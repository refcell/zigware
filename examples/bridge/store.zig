//! What the indexer keeps (the `handler` task of commonware's `bin/indexer.rs`): for each
//! network it serves, the blocks put to it by digest and its finalizations, and the answer to
//! every `Inbound` request. A finalization is stored only when it verifies against that
//! network's identity. Requests for a network the indexer does not serve fail (`false`, or
//! nothing found).
//!
//! commonware keeps every finalization in a map by view and answers with the highest; only
//! the highest is ever read, so this keeps just that one (a later one at the same view
//! replaces it, as a map insert does). Blocks are kept forever, as in commonware.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const types = @import("types.zig");

const codec = zigware.codec;
const traces = zigware.runtime.telemetry.traces;
const Sha256 = zigware.cryptography.Sha256;

/// The most networks one indexer serves.
pub const networks_max = 16;

/// One network's blocks and latest finalization.
pub const Network = struct {
    public: types.Public,
    /// Verifies the network's certificates against its identity.
    verifier: lib.Scheme,
    blocks: std.AutoHashMapUnmanaged([lib.Digest.fixed_size]u8, types.BlockFormat) = .empty,
    latest: ?types.Finalization = null,
};

pub const Store = struct {
    networks: []Network,
    tracer: traces.Tracer,

    /// Serves the networks with identities `publics`, which must be distinct.
    pub fn init(gpa: Allocator, publics: []const types.Public, tracer: traces.Tracer) !Store {
        assert(publics.len > 0 and publics.len <= networks_max);
        const networks = try gpa.alloc(Network, publics.len);
        var initialized: usize = 0;
        errdefer {
            for (networks[0..initialized]) |*network| network.verifier.deinit(gpa);
            gpa.free(networks);
        }
        const namespace = lib.application_namespace ++ lib.consensus_suffix;
        for (publics, networks, 0..) |public, *network, index| {
            for (publics[0..index]) |earlier| assert(!earlier.eql(public));
            network.* = .{
                .public = public,
                .verifier = try .certificate_verifier(gpa, namespace, public),
            };
            initialized += 1;
        }
        assert(initialized == publics.len);
        return .{ .networks = networks, .tracer = tracer };
    }

    pub fn deinit(store: *Store, gpa: Allocator) void {
        for (store.networks) |*network| {
            network.blocks.deinit(gpa);
            network.verifier.deinit(gpa);
        }
        gpa.free(store.networks);
        store.* = undefined;
    }

    fn find(store: *Store, public: types.Public) ?*Network {
        for (store.networks) |*network| {
            if (network.public.eql(public)) return network;
        }
        return null;
    }

    /// Answers `inbound` as the indexer's connection handler does.
    pub fn handle(
        store: *Store,
        gpa: Allocator,
        rng: anytype,
        inbound: types.Inbound,
    ) Allocator.Error!types.Outbound {
        assert(store.networks.len > 0);
        return switch (inbound) {
            .put_block => |put| .{ .success = try store.put_block(gpa, put) },
            .get_block => |get| if (store.get_block(get)) |block|
                .{ .block = block }
            else
                .{ .success = false },
            .put_finalization => |put| .{
                .success = try store.put_finalization(gpa, rng, put),
            },
            .get_finalization => |get| if (store.get_finalization(get)) |finalization|
                .{ .finalization = finalization }
            else
                .{ .success = false },
        };
    }

    fn put_block(store: *Store, gpa: Allocator, put: types.PutBlock) Allocator.Error!bool {
        const network = store.find(put.network) orelse return false;
        const digest = block_digest(put.block);
        try network.blocks.put(gpa, digest.bytes, put.block);
        assert(network.blocks.contains(digest.bytes));
        store.tracer.event(.info, "stored block", .{
            .network = Hex(types.Public){ .value = put.network },
            .block = digest,
        });
        return true;
    }

    fn get_block(store: *Store, get: types.GetBlock) ?types.BlockFormat {
        const network = store.find(get.network) orelse return null;
        return network.blocks.get(get.digest.bytes);
    }

    fn put_finalization(
        store: *Store,
        gpa: Allocator,
        rng: anytype,
        put: types.PutFinalization,
    ) Allocator.Error!bool {
        const network = store.find(put.network) orelse return false;
        const sequential = zigware.parallel.sequential;
        if (!try put.finalization.verify(gpa, rng, &network.verifier, sequential)) return false;
        const view = put.finalization.view();
        if (network.latest) |latest| {
            if (latest.view().get() <= view.get()) network.latest = put.finalization;
        } else {
            network.latest = put.finalization;
        }
        assert(network.latest.?.view().get() >= view.get());
        store.tracer.event(.info, "stored finalization", .{
            .network = Hex(types.Public){ .value = put.network },
            .view = view.get(),
        });
        return true;
    }

    fn get_finalization(store: *Store, get: types.GetFinalization) ?types.Finalization {
        const network = store.find(get.network) orelse return null;
        return network.latest;
    }
};

/// The digest a block is named by: SHA-256 of its encoding.
pub fn block_digest(block: types.BlockFormat) lib.Digest {
    var buffer: [block_size_max]u8 = undefined;
    const encoded = codec.encode_to(types.BlockFormat, block, &buffer);
    assert(encoded.len > 0 and encoded.len <= block_size_max);
    return Sha256.hash(&.{encoded});
}

/// The largest block encoding: a tag and a finalization.
pub const block_size_max = types.outbound_size_max - 1;

/// Formats a codec value as lowercase hex of its encoding (commonware's `Hex` Debug).
pub fn Hex(comptime T: type) type {
    const size = codec.fixed_size(T).?;
    comptime assert(size > 0);
    return struct {
        value: T,

        pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const bytes = codec.encode_fixed(T, self.value);
            assert(bytes.len == size);
            try writer.print("{x}", .{&bytes});
        }
    };
}

test {
    _ = @import("store_test.zig");
}
