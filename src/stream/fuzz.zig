//! Fuzz targets for SAKE and CUPS (commonware `stream/fuzz/fuzz_targets`): `transport`,
//! `connection`, `lazy_transport`, and `e2e`, run on the deterministic runtime over mock
//! channels.
//!
//! Each target body takes raw input bytes and draws structured values from them with
//! `cryptography.fuzz.Input` (zeros once the bytes run out, like `arbitrary`'s `Unstructured`).
//! `run` feeds a body seeded random bytes in `zig build test` (iterations scaled by
//! `build_options.fuzz_soak`, seed mixed with `build_options.fuzz_seed`), then the bytes of a
//! `std.testing.Smith` under coverage-guided fuzzing. Smith's typed draws are not used: on a
//! fixed input they read eight bytes per integer and fall back to the minimum when out of
//! range, so random bytes would yield degenerate values. (stream does not depend on
//! `invariants`, so it carries this small driver itself.)
//!
//! Differences from commonware:
//! `connection` caps message lengths at 128 KiB (commonware allows up to its ~1 MiB limit, mostly
//! zero bytes) so the debug build stays fast; that still exceeds the mock channel's 64 KiB
//! buffer, so the backpressure path is covered. `lazy_transport` keeps its four connections in
//! one runtime and feeds them seeded inputs, without a coverage-guided variant.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const Smith = std.testing.Smith;
const Input = cryptography.fuzz.Input;
const build_options = @import("build_options");
const cryptography = @import("cryptography");
const runtime = @import("runtime");

const stream = @import("root.zig");
const cups = @import("cups.zig");
const sake = @import("sake.zig");
const mocks = runtime.mocks;
const framing = @import("utils/codec.zig");
const Timeout = @import("utils/timeout.zig").Timeout;

const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Cipher = cryptography.ChaCha20Poly1305;
const Upgrade = stream.SakeCups(PrivateKey, Cipher);
const Connection = Upgrade.Connection(mocks.Stream, mocks.Sink);
const Accepted = Upgrade.Accepted(mocks.Stream, mocks.Sink);
const tag_size = cups.tag_size(Cipher);

const gpa = testing.allocator;

/// Largest input `run` hands a body.
pub const input_size_max = 8192;

/// Runs `body` on `iterations * fuzz_soak` seeded random inputs, then on the bytes of
/// `std.testing.fuzz` inputs.
pub fn run(comptime body: fn ([]const u8) anyerror!void, seed: u64, iterations: u32) !void {
    assert(iterations > 0);
    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [input_size_max]u8 = undefined;
    const total: u64 = @as(u64, iterations) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        // Bias toward short inputs, where most decoding edge cases live.
        const len_max: usize = if (random.boolean()) 256 else input.len;
        const len = random.uintAtMost(usize, len_max);
        random.bytes(input[0..len]);
        body(input[0..len]) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed: {t}\n", .{
                seed ^ build_options.fuzz_seed, iteration, err,
            });
            return err;
        };
    }
    assert(iteration == total);
    const Coverage = struct {
        fn one(_: void, smith: *Smith) anyerror!void {
            var bytes: [input_size_max]u8 = undefined;
            const len = smith.slice(&bytes);
            try body(bytes[0..len]);
        }
    };
    try std.testing.fuzz({}, Coverage.one, .{});
}

fn run_deterministic(comptime function: anytype, args: anytype) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 120 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try (try runner.start(function, .{runner.io()} ++ args));
}

const AdmitAll = struct {
    pub fn admit(_: AdmitAll, _: PublicKey) Io.Cancelable!bool {
        return true;
    }
};

/// Both peers' configuration.
const Setup = struct {
    sake_version: sake.Version,
    cups_version: cups.Version,
    dialer_seed: u64 = 42,
    listener_seed: u64 = 24,
    namespace: []const u8 = "fuzz_transport",
    max_message_size: u32 = 64 * 1024,
    synchrony_bound_ms: u64 = 1000,
    max_handshake_age_ms: u64 = 1000,
    timeout_ms: i64 = 1000,

    fn upgrader(setup: Setup, seed: u64) Timeout(Upgrade) {
        const handshake: sake.Sake(PrivateKey) = .{
            .signer = .from_seed(seed),
            .synchrony_bound_ms = setup.synchrony_bound_ms,
            .max_handshake_age_ms = setup.max_handshake_age_ms,
            .version = setup.sake_version,
        };
        const upgrade = Upgrade.init(handshake, setup.cups_version);
        return .init(upgrade, .fromMilliseconds(setup.timeout_ms));
    }
};

fn draw_versions(input: *Input) Setup {
    const sake_version: sake.Version = if (input.boolean()) .v1 else .v0;
    const cups_version: cups.Version = if (input.boolean()) .v1 else .v0;
    return .{ .sake_version = sake_version, .cups_version = cups_version };
}

fn listen_task(io: Io, setup: Setup, in: mocks.Stream, out: mocks.Sink) anyerror!Accepted {
    const upgrader = setup.upgrader(setup.listener_seed);
    const admit: AdmitAll = .{};
    return upgrader.listen(gpa, io, setup.namespace, setup.max_message_size, admit, in, out);
}

fn dial_task(io: Io, setup: Setup, in: mocks.Stream, out: mocks.Sink) anyerror!Connection {
    const upgrader = setup.upgrader(setup.dialer_seed);
    const peer = PrivateKey.from_seed(setup.listener_seed).public_key();
    return upgrader.dial(gpa, io, setup.namespace, setup.max_message_size, peer, in, out);
}

const Peers = struct {
    dialer: Connection,
    listener: Accepted,

    fn deinit(peers: *Peers) void {
        peers.dialer.deinit(gpa);
        peers.listener.deinit(gpa);
    }
};

/// Connects a dialer and a listener over direct channels; both must succeed.
fn connect(io: Io, setup: Setup) !Peers {
    const d2l = try mocks.channel(gpa, io);
    const l2d = try mocks.channel(gpa, io);
    var listening = try io.concurrent(listen_task, .{ io, setup, d2l.stream, l2d.sink });
    var dialer = dial_task(io, setup, l2d.stream, d2l.sink) catch |err| {
        release_accepted(listening.cancel(io));
        return err;
    };
    errdefer dialer.deinit(gpa);
    var listener = try listening.await(io);
    errdefer listener.deinit(gpa);
    const dialer_key = PrivateKey.from_seed(setup.dialer_seed).public_key();
    try testing.expect(listener.peer.eql(dialer_key));
    return .{ .dialer = dialer, .listener = listener };
}

fn release_accepted(result: anyerror!Accepted) void {
    var accepted = result catch return;
    accepted.deinit(gpa);
}

fn release_connection(result: anyerror!Connection) void {
    var connection = result catch return;
    connection.deinit(gpa);
}

// transport: data in 1 KiB chunks, each echoed in both directions.

fn transport_round_trips(io: Io, setup: Setup, data: []const u8) !void {
    var peers = try connect(io, setup);
    defer peers.deinit();
    const dialer = &peers.dialer;
    const listener = &peers.listener.connection;
    var offset: usize = 0;
    while (offset < data.len) {
        const chunk = data[offset..@min(offset + 1024, data.len)];
        offset += chunk.len;
        try dialer.sender.send(chunk);
        try testing.expectEqualSlices(u8, chunk, try listener.receiver.recv());
        try listener.sender.send(chunk);
        try testing.expectEqualSlices(u8, chunk, try dialer.receiver.recv());
    }
}

fn fuzz_transport(bytes: []const u8) anyerror!void {
    var input = Input.init(bytes);
    const setup = draw_versions(&input);
    try run_deterministic(transport_round_trips, .{ setup, input.take(input_size_max) });
}

test "fuzz transport" {
    try run(fuzz_transport, 0x7472_616e_7370, 6);
}

// connection: arbitrary identities, namespace, limits, and messages in both directions.

const connection_messages_max = 10;
const connection_message_bytes_max = 128 * 1024;

const Messages = struct {
    lengths: [connection_messages_max]u32 = undefined,
    count: usize = 0,
    bytes: []u8,

    fn get(messages: *const Messages, index: usize) []const u8 {
        assert(index < messages.count);
        var offset: usize = 0;
        for (messages.lengths[0..index]) |len| offset += len;
        return messages.bytes[offset..][0..messages.lengths[index]];
    }
};

/// Draws up to ten messages within `max_message_size` (capped, see the file comment).
fn draw_messages(input: *Input, max_message_size: u32, storage: []u8) Messages {
    var messages: Messages = .{ .bytes = storage };
    const count = input.int_in_range(0, connection_messages_max);
    const len_max: u32 = @min(max_message_size, connection_message_bytes_max);
    var used: usize = 0;
    while (messages.count < count) : (messages.count += 1) {
        // Biased toward short messages; the long ones exercise channel backpressure.
        const limit: u32 = if (input.boolean()) @min(len_max, 256) else len_max;
        const len: usize = @min(input.int_in_range(0, limit), storage.len - used);
        input.fill(storage[used..][0..len]);
        messages.lengths[messages.count] = @intCast(len);
        used += len;
    }
    return messages;
}

fn send_task(sender: *cups.Sender(Cipher, mocks.Sink), message: []const u8) anyerror!void {
    try sender.send(message);
}

/// Sends and receives concurrently, so messages larger than the channel buffer progress.
fn exchange(
    io: Io,
    sender: *cups.Sender(Cipher, mocks.Sink),
    receiver: *cups.Receiver(Cipher, mocks.Stream),
    messages: *const Messages,
    max_message_size: u32,
) !void {
    for (0..messages.count) |index| {
        const message = messages.get(index);
        if (message.len == 0 or message.len > max_message_size) continue;
        var sent = try io.concurrent(send_task, .{ sender, message });
        const received = receiver.recv() catch |err| {
            sent.cancel(io) catch {};
            return err;
        };
        try sent.await(io);
        try testing.expectEqualSlices(u8, message, received);
    }
}

fn connection_round_trips(
    io: Io,
    setup: Setup,
    to_listener: *const Messages,
    to_dialer: *const Messages,
) !void {
    var peers = try connect(io, setup);
    defer peers.deinit();
    const dialer = &peers.dialer;
    const listener = &peers.listener.connection;
    const max = setup.max_message_size;
    try exchange(io, &dialer.sender, &listener.receiver, to_listener, max);
    try exchange(io, &listener.sender, &dialer.receiver, to_dialer, max);
}

fn fuzz_connection(bytes: []const u8) anyerror!void {
    var input = Input.init(bytes);
    var setup = draw_versions(&input);
    setup.dialer_seed = input.int_in_range(0, std.math.maxInt(u64));
    setup.listener_seed = setup.dialer_seed +% 1;
    var namespace: [256]u8 = undefined;
    const namespace_len: usize = @intCast(input.int_in_range(0, namespace.len));
    input.fill(namespace[0..namespace_len]);
    setup.namespace = namespace[0..namespace_len];
    // 210 bytes hold the largest handshake message.
    setup.max_message_size = @intCast(input.int_in_range(210, 1024 * 1023));
    setup.synchrony_bound_ms = input.int_in_range(1, 12) * std.time.ms_per_s;
    setup.max_handshake_age_ms = input.int_in_range(1, 12) * std.time.ms_per_s;
    setup.timeout_ms = @intCast(input.int_in_range(1, 12) * std.time.ms_per_s);

    const storage = try gpa.alloc(u8, 1024 * 1024);
    defer gpa.free(storage);
    const half = storage.len / 2;
    const to_listener = draw_messages(&input, setup.max_message_size, storage[0..half]);
    const to_dialer = draw_messages(&input, setup.max_message_size, storage[half..]);
    try run_deterministic(connection_round_trips, .{ setup, &to_listener, &to_dialer });
}

test "fuzz connection" {
    try run(fuzz_connection, 0x636f_6e6e, 4);
}

// lazy_transport: four long-lived connections, one per version pair, fed many inputs.

const lazy_max_message_size: u32 = 1023 * 1024;

fn lazy_transports(io: Io, seed: u64, inputs: u64) !void {
    var transports: [4]Peers = undefined;
    var connected: usize = 0;
    defer for (transports[0..connected]) |*peers| peers.deinit();
    for (&transports, 0..) |*peers, index| {
        peers.* = try connect(io, .{
            .sake_version = if (index & 1 == 0) .v0 else .v1,
            .cups_version = if (index & 2 == 0) .v0 else .v1,
            .namespace = "lazy_fuzz_transport",
            .max_message_size = lazy_max_message_size,
            .synchrony_bound_ms = 3000,
            .max_handshake_age_ms = 5000,
            .timeout_ms = 2000,
        });
        connected += 1;
    }

    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var data: [4096]u8 = undefined;
    for (0..inputs) |_| {
        const peers = &transports[random.uintLessThan(usize, transports.len)];
        const len = random.uintAtMost(usize, data.len);
        random.bytes(data[0..len]);
        var offset: usize = 0;
        while (offset < len) {
            const chunk = data[offset..@min(offset + 1024, len)];
            offset += chunk.len;
            try peers.dialer.sender.send(chunk);
            const received = try peers.listener.connection.receiver.recv();
            try testing.expectEqualSlices(u8, chunk, received);
        }
    }
}

test "fuzz lazy transport" {
    const inputs = 40 * @as(u64, build_options.fuzz_soak);
    try run_deterministic(lazy_transports, .{ 0x6c61_7a79, inputs });
}

// e2e: an adversary between the peers relays, corrupts, drops, forges, and tampers.

const e2e_max_message_size: u32 = 2048;
const e2e_max_ciphertext_size: u32 = e2e_max_message_size + tag_size;
const e2e_messages_max = 16;

const Kind = enum { authenticated, unauthenticated, tampered };

const Message = struct {
    to_listener: bool,
    kind: Kind,
    data: [e2e_max_ciphertext_size]u8,
    len: usize,
    index: u64,
    mask: u8,

    fn bytes(message: *const Message) []const u8 {
        return message.data[0..message.len];
    }
};

const E2eInput = struct {
    setup: Setup,
    corruption: [256]u8,
    corruption_len: usize,
    messages: [e2e_messages_max]Message,
    count: usize,

    fn has_setup_corruption(input: *const E2eInput) bool {
        for (input.corruption[0..input.corruption_len]) |byte| if (byte != 0) return true;
        return false;
    }

    fn draw(e2e: *E2eInput, input: *Input) void {
        e2e.setup = draw_versions(input);
        e2e.setup.max_message_size = e2e_max_message_size;
        e2e.corruption_len = 0;
        if (input.boolean()) {
            e2e.corruption_len = @intCast(input.int_in_range(0, e2e.corruption.len));
            input.fill(e2e.corruption[0..e2e.corruption_len]);
        }
        // Like `arbitrary_iter`, draw messages until the input runs out.
        e2e.count = 0;
        while (e2e.count < e2e_messages_max and input.bytes.len > 0) : (e2e.count += 1) {
            const message = &e2e.messages[e2e.count];
            message.to_listener = input.boolean();
            message.kind = switch (input.int_in_range(0, 2)) {
                0 => .authenticated,
                1 => .unauthenticated,
                else => .tampered,
            };
            // Forged records may be as long as a ciphertext; the others carry plaintext.
            const len_max = if (message.kind == .unauthenticated)
                e2e_max_ciphertext_size
            else
                e2e_max_message_size;
            message.len = @intCast(input.int_in_range(0, @min(len_max, input.bytes.len)));
            input.fill(message.data[0..message.len]);
            message.index = input.int_in_range(0, std.math.maxInt(u64));
            // A zero mask would leave the record unchanged.
            message.mask = @max(1, @as(u8, @intCast(input.int_in_range(0, 255))));
        }
    }
};

/// The adversary's channel ends: it reads what each peer writes and writes what each reads.
const Adversary = struct {
    from_dialer: mocks.Stream,
    to_listener: mocks.Sink,
    from_listener: mocks.Stream,
    to_dialer: mocks.Sink,

    fn deinit(adversary: *Adversary) void {
        adversary.from_dialer.deinit();
        adversary.to_listener.deinit();
        adversary.from_listener.deinit();
        adversary.to_dialer.deinit();
    }
};

/// Relays one handshake frame, XORing it with the next unused corruption bytes.
fn relay(in: *mocks.Stream, out: *mocks.Sink, corruption: []const u8, used: *usize) !void {
    var buffer: [e2e_max_message_size]u8 = undefined;
    const frame = try framing.recv_frame(in, &buffer, e2e_max_message_size);
    for (frame) |*byte| {
        if (used.* == corruption.len) break;
        byte.* ^= corruption[used.*];
        used.* += 1;
    }
    try framing.send_frame(out, &.{frame}, e2e_max_message_size);
}

const Relayed = struct { sent_corrupted_data: bool, adversary: Adversary };

fn adversary_task(adversary: Adversary, corruption: []const u8) anyerror!Relayed {
    var owned = adversary;
    errdefer owned.deinit();
    // The identity prelude passes unchanged; Syn, SynAck, and Ack take the corruption.
    var unused: usize = 0;
    try relay(&owned.from_dialer, &owned.to_listener, &.{}, &unused);
    var used: usize = 0;
    try relay(&owned.from_dialer, &owned.to_listener, corruption, &used);
    try relay(&owned.from_listener, &owned.to_dialer, corruption, &used);
    try relay(&owned.from_dialer, &owned.to_listener, corruption, &used);
    var sent_corrupted_data = false;
    for (corruption[0..used]) |byte| sent_corrupted_data = sent_corrupted_data or byte != 0;
    return .{ .sent_corrupted_data = sent_corrupted_data, .adversary = owned };
}

/// Runs the handshake through the adversary. Returns null when a peer rejected it, which
/// only setup corruption may cause.
fn e2e_setup(io: Io, input: *const E2eInput) !?Established {
    const d2a = try mocks.channel(gpa, io);
    const a2l = try mocks.channel(gpa, io);
    const l2a = try mocks.channel(gpa, io);
    const a2d = try mocks.channel(gpa, io);
    const adversary: Adversary = .{
        .from_dialer = d2a.stream,
        .to_listener = a2l.sink,
        .from_listener = l2a.stream,
        .to_dialer = a2d.sink,
    };
    const corruption = input.corruption[0..input.corruption_len];
    var relaying = try io.concurrent(adversary_task, .{ adversary, corruption });
    const setup = input.setup;
    var listening = try io.concurrent(listen_task, .{ io, setup, a2l.stream, l2a.sink });
    var dialing = try io.concurrent(dial_task, .{ io, setup, a2d.stream, d2a.sink });
    const dialed = dialing.await(io);
    const listened = listening.await(io);
    const dialer = dialed catch {
        release_accepted(listened);
        return finish_rejected(io, input, &relaying);
    };
    const listener = listened catch {
        release_connection(dialer);
        return finish_rejected(io, input, &relaying);
    };
    var peers: Peers = .{ .dialer = dialer, .listener = listener };
    errdefer peers.deinit();
    const relayed = try relaying.await(io);
    // Both peers accepted, so nothing the adversary changed reached them.
    try testing.expect(!relayed.sent_corrupted_data);
    return .{ peers, relayed.adversary };
}

const Established = struct { Peers, Adversary };

fn finish_rejected(io: Io, input: *const E2eInput, relaying: anytype) !?Established {
    if (relaying.cancel(io)) |relayed| {
        var adversary = relayed.adversary;
        adversary.deinit();
    } else |_| {}
    try testing.expect(input.has_setup_corruption());
    return null;
}

/// One direction of the connection, seen from the wire.
const Lane = struct {
    sender: *cups.Sender(Cipher, mocks.Sink),
    intercept: *mocks.Stream,
    forward: *mocks.Sink,
    receiver: *cups.Receiver(Cipher, mocks.Stream),
    corrupted: *bool,
};

fn e2e_message(lane: Lane, version: cups.Version, message: *const Message) !void {
    // The largest header (v1: 4 + tag) plus the largest forged or sealed body.
    var record: [4 + tag_size + e2e_max_ciphertext_size + tag_size]u8 = undefined;
    const data = message.bytes();
    switch (message.kind) {
        .authenticated => {
            // A legitimate record, intercepted and forwarded unchanged, delivers.
            try lane.sender.send(data);
            const len = cups.record_len(Cipher, version, data.len);
            try lane.intercept.recv(record[0..len]);
            try lane.forward.send(&.{record[0..len]});
            try testing.expectEqualSlices(u8, data, try lane.receiver.recv());
            return;
        },
        .unauthenticated => {
            // Drop a legitimate record and forge one in its place. A forged v1 header is padded
            // to full size so the receiver has a header to reject.
            try lane.sender.send(&.{0});
            try lane.intercept.recv(record[0..cups.record_len(Cipher, version, 1)]);
            switch (version) {
                .v0 => try framing.send_frame(lane.forward, &.{data}, e2e_max_ciphertext_size),
                .v1 => {
                    const len = @max(data.len, cups.header_len(Cipher, .v1, 0));
                    @memcpy(record[0..data.len], data);
                    @memset(record[data.len..len], 0);
                    try lane.forward.send(&.{record[0..len]});
                },
            }
        },
        .tampered => {
            // Flip one byte. A v0 prefix stays intact so the receiver reads the same span; any
            // v1 byte may change because its header is authenticated before the body is read.
            try lane.sender.send(data);
            const len = cups.record_len(Cipher, version, data.len);
            try lane.intercept.recv(record[0..len]);
            const start = switch (version) {
                .v0 => cups.header_len(Cipher, .v0, data.len),
                .v1 => 0,
            };
            const offset: usize = @intCast(message.index % @as(u64, len - start));
            record[start + offset] ^= message.mask;
            try lane.forward.send(&.{record[0..len]});
        },
    }
    // The receiver rejects the record, and refuses every later one.
    if (lane.receiver.recv()) |_| return error.TestUnexpectedResult else |_| {}
    lane.corrupted.* = true;
}

fn e2e_run(io: Io, input: *const E2eInput) !void {
    const established = try e2e_setup(io, input) orelse return;
    var peers, var adversary = established;
    defer peers.deinit();
    defer adversary.deinit();
    var d2l_corrupted = false;
    var l2d_corrupted = false;
    const d2l: Lane = .{
        .sender = &peers.dialer.sender,
        .intercept = &adversary.from_dialer,
        .forward = &adversary.to_listener,
        .receiver = &peers.listener.connection.receiver,
        .corrupted = &d2l_corrupted,
    };
    const l2d: Lane = .{
        .sender = &peers.listener.connection.sender,
        .intercept = &adversary.from_listener,
        .forward = &adversary.to_dialer,
        .receiver = &peers.dialer.receiver,
        .corrupted = &l2d_corrupted,
    };
    for (input.messages[0..input.count]) |*message| {
        const lane = if (message.to_listener) d2l else l2d;
        if (lane.corrupted.*) continue;
        try e2e_message(lane, input.setup.cups_version, message);
    }
}

fn fuzz_e2e(bytes: []const u8) anyerror!void {
    const e2e = try gpa.create(E2eInput);
    defer gpa.destroy(e2e);
    var input = Input.init(bytes);
    e2e.draw(&input);
    try run_deterministic(e2e_run, .{@as(*const E2eInput, e2e)});
}

test "fuzz e2e with an adversary in the middle" {
    try run(fuzz_e2e, 0x6532_65, 12);
}
