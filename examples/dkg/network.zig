//! The authenticated discovery network both node subcommands run (commonware's
//! `discovery::Config::local` over SAKE and CUPS in `bootstrap.rs` and `validator.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const config = @import("config.zig");
const types = @import("types.zig");

const codec = zigware.codec;
const ed25519 = zigware.cryptography.ed25519;
const production = zigware.runtime.production;
const discovery = zigware.p2p.authenticated.discovery;
const Cups = zigware.stream.SakeCups(ed25519.PrivateKey, zigware.cryptography.ChaCha20Poly1305);

pub const Net = discovery.Network(Cups, production.network.Network);
pub const Bootstrapper = discovery.Bootstrapper(types.PublicKey);

/// The p2p namespace: the application namespace with commonware's `_P2P` suffix.
pub const namespace = types.namespace ++ "_P2P";

fn to_codec(address: config.SocketAddr) codec.SocketAddr {
    return .{ .ip = discovery.network.to_ip(address.to_io()), .port = address.port };
}

/// Every peer but `local`, dialed at its configured address (`NetworkConfig::bootstrappers`).
pub fn bootstrappers(
    arena: Allocator,
    network: *const config.NetworkConfig,
    local: types.PublicKey,
) Allocator.Error![]const Bootstrapper {
    const peers = try network.bootstrappers(arena, local);
    const out = try arena.alloc(Bootstrapper, peers.len);
    for (out, peers) |*bootstrapper, peer| {
        assert(!peer.public_key.eql(local));
        const ingress: zigware.p2p.Ingress = .{ .socket = to_codec(peer.dial) };
        bootstrapper.* = .{ .peer = peer.public_key, .ingress = ingress };
    }
    return out;
}

/// The node's discovery config, sized for `max_payload_size_bytes`.
pub fn network_config(
    arena: Allocator,
    node: *const config.NodeConfig,
    network: *const config.NetworkConfig,
    max_payload_size_bytes: usize,
) Allocator.Error!Net.Config {
    const local = node.public_key();
    assert(max_payload_size_bytes > 0);
    const limit = zigware.p2p.sizing.peer_set_limit(types.PublicKey, network.participants, local);
    return Net.Config.local(.{
        .upgrader = .init(.{
            .signer = node.signer,
            .synchrony_bound_ms = 5_000,
            .max_handshake_age_ms = 10_000,
            .version = .v1,
        }, .v1),
        .namespace = namespace,
        .listen = discovery.network.to_address(to_codec(node.listen)),
        .dialable = .{ .socket = to_codec(node.dial) },
        .bootstrappers = try bootstrappers(arena, network, local),
        .max_peers_per_set = limit,
        .max_message_size = zigware.p2p.sizing.max_message_size(&.{max_payload_size_bytes}),
        .mailbox_size = types.mailbox_size,
    });
}

/// A registered channel's two ends.
/// Runs `net` until canceled; any other failure panics, as commonware's listener does.
pub fn run(net: *Net) std.Io.Cancelable!void {
    net.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("network failed: {t}", .{err}),
    };
}

pub const Channel = struct { sender: Net.Sender, receiver: Net.Receiver };

/// Registers `id` at commonware's per-peer `MESSAGE_RATE`.
pub fn register(net: *Net, id: u64) !Channel {
    const quota = zigware.p2p.Quota.per_second(types.message_rate_per_second);
    const registered = try net.register(id, quota);
    return .{ .sender = registered.sender, .receiver = registered.receiver };
}
