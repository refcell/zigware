//! Benchmarks of the codec (commonware `codec/src/benches`): `Lazy.get` on values sliced
//! from one shared buffer or held in private buffers, against decoding borrowed bytes, with
//! commonware's names, transaction count, and concurrency.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const codec = @import("codec");

const TXS: usize = 100_000;
const concurrencies = [_]usize{ 1, 8 };

/// A fixed-size transaction fixture: only fixed-width integers and byte arrays, so every
/// buffer of `fixed_size` bytes is a valid encoding.
const Tx = struct {
    nonce: u64,
    sender: [32]u8,
    recipient: [32]u8,
    amount: u64,
    fee: u64,
    signature: [64]u8,

    pub const fixed_size: usize = 3 * 8 + 2 * 32 + 64;

    pub fn write(self: Tx, writer: *codec.Writer) void {
        codec.write(u64, self.nonce, writer);
        codec.write([32]u8, self.sender, writer);
        codec.write([32]u8, self.recipient, writer);
        codec.write(u64, self.amount, writer);
        codec.write(u64, self.fee, writer);
        codec.write([64]u8, self.signature, writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Tx {
        return .{
            .nonce = try codec.read(u64, gpa, reader),
            .sender = try codec.read([32]u8, gpa, reader),
            .recipient = try codec.read([32]u8, gpa, reader),
            .amount = try codec.read(u64, gpa, reader),
            .fee = try codec.read(u64, gpa, reader),
            .signature = try codec.read([64]u8, gpa, reader),
        };
    }
};

/// `Tx` plus a short memo, which decoding borrows from the input.
const MemoTx = struct {
    tx: Tx,
    memo: codec.Bytes,

    pub fn write(self: MemoTx, writer: *codec.Writer) void {
        codec.write(Tx, self.tx, writer);
        codec.write(codec.Bytes, self.memo, writer);
    }

    pub fn encode_size(self: MemoTx) usize {
        return Tx.fixed_size + codec.encode_size(codec.Bytes, self.memo);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!MemoTx {
        const tx = try codec.read(Tx, gpa, reader);
        const memo = try codec.read_cfg(codec.Bytes, gpa, reader, .to_inclusive(64));
        return .{ .tx = tx, .memo = memo };
    }
};

/// The encodings of `values`, sliced out of one block as when a block is decoded. Free the
/// block (`slices[0].ptr`) and the slices with `free_shared`.
fn shared_slices(comptime T: type, gpa: Allocator, values: []const T) ![]const []const u8 {
    assert(values.len > 0);
    var total: usize = 0;
    for (values) |value| total += codec.encode_size(T, value);
    const block = try gpa.alloc(u8, total);
    errdefer gpa.free(block);
    const slices = try gpa.alloc([]const u8, values.len);
    var writer: codec.Writer = .init(block);
    for (values, slices) |value, *slice| {
        const start = writer.end;
        codec.write(T, value, &writer);
        slice.* = block[start..writer.end];
    }
    assert(writer.end == total);
    return slices;
}

fn free_shared(gpa: Allocator, slices: []const []const u8) void {
    assert(slices.len > 0);
    const last = slices[slices.len - 1];
    gpa.free(slices[0].ptr[0 .. last.ptr - slices[0].ptr + last.len]);
    gpa.free(slices);
}

/// `count` random transactions from `prng`.
fn random_txs(gpa: Allocator, prng: *std.Random.DefaultPrng, count: usize) ![]Tx {
    assert(count > 0);
    const txs = try gpa.alloc(Tx, count);
    var bytes: [Tx.fixed_size]u8 = undefined;
    for (txs) |*tx| {
        prng.random().bytes(&bytes);
        tx.* = codec.decode(Tx, gpa, &bytes) catch unreachable; // Proof: any bytes decode.
    }
    return txs;
}

/// One iteration gets every lazy value deferred (untimed) over `sources`, or, when
/// `borrowed`, decodes every source directly, split into `conc` contiguous parts, one per
/// concurrent task.
fn GetWorkload(comptime T: type) type {
    return struct {
        const Self = @This();
        const Lazy = codec.Lazy(T);

        gpa: Allocator,
        io: std.Io,
        sources: []const []const u8,
        lazies: []Lazy,
        conc: usize,
        borrowed: bool,

        pub fn before_iter(workload: *Self) void {
            assert(workload.lazies.len == workload.sources.len);
            if (workload.borrowed) return;
            for (workload.sources, workload.lazies) |source, *lazy| lazy.* = .deferred(source, {});
        }

        fn get_part(gpa: Allocator, lazies: []Lazy) void {
            // Pointer sinks: by value, an array of 64 bytes or less (`[33]u8`) gets one barrier
            // per byte; Rust's `black_box` is one opaque use.
            for (lazies) |*lazy| {
                const value = lazy.get(gpa).?;
                std.mem.doNotOptimizeAway(&value);
            }
        }

        fn decode_part(gpa: Allocator, sources: []const []const u8) void {
            for (sources) |source| {
                const value = codec.decode(T, gpa, source) catch unreachable; // Proof: encoded.
                std.mem.doNotOptimizeAway(&value);
            }
        }

        fn run_part(workload: *Self, start: usize, end: usize) void {
            assert(start < end and end <= workload.sources.len);
            if (workload.borrowed) {
                decode_part(workload.gpa, workload.sources[start..end]);
            } else {
                get_part(workload.gpa, workload.lazies[start..end]);
            }
        }

        pub fn iter(workload: *Self) !usize {
            const len = workload.sources.len;
            assert(workload.conc > 0);
            if (workload.conc == 1) {
                workload.run_part(0, len);
                return len;
            }
            const chunk = std.math.divCeil(usize, len, workload.conc) catch unreachable;
            var group: std.Io.Group = .init;
            errdefer group.cancel(workload.io);
            var start: usize = 0;
            while (start < len) : (start += chunk) {
                const end = @min(start + chunk, len);
                try group.concurrent(workload.io, run_part, .{ workload, start, end });
            }
            try group.await(workload.io);
            return len;
        }
    };
}

fn bench_get_with(
    comptime T: type,
    runner: *bench.Runner,
    benchmark: bench.Benchmark,
    sources: []const []const u8,
    conc: usize,
    borrowed: bool,
) !void {
    assert(sources.len > 0);
    const gpa = runner.allocator;
    const lazies = try gpa.alloc(codec.Lazy(T), sources.len);
    defer gpa.free(lazies);
    var workload: GetWorkload(T) = .{
        .gpa = gpa,
        .io = runner.io,
        .sources = sources,
        .lazies = lazies,
        .conc = conc,
        .borrowed = borrowed,
    };
    try runner.run(benchmark, &workload);
}

fn bench_get(runner: *bench.Runner, txs: usize) !void {
    const gpa = runner.allocator;
    var prng: std.Random.DefaultPrng = .init(0);
    const values = try random_txs(gpa, &prng, txs);
    defer gpa.free(values);
    const shared = try shared_slices(Tx, gpa, values);
    defer free_shared(gpa, shared);
    const private = try gpa.alloc([]const u8, txs);
    defer gpa.free(private);
    var private_len: usize = 0;
    defer for (private[0..private_len]) |bytes| gpa.free(bytes);
    for (shared, private) |bytes, *copy| {
        copy.* = try gpa.dupe(u8, bytes);
        private_len += 1;
    }

    const get = bench.Benchmark.init("codec::lazy::get");
    for (concurrencies) |conc| {
        const sources = [_]struct { []const u8, []const []const u8 }{
            .{ "shared", shared },
            .{ "private", private },
        };
        for (sources) |source| {
            const name = get.with_param("source", source[0]).with_param("txs", txs)
                .with_param("conc", conc);
            try bench_get_with(Tx, runner, name, source[1], conc, false);
        }
        const borrowed = get.with_param("source", "borrowed").with_param("txs", txs)
            .with_param("conc", conc);
        try bench_get_with(Tx, runner, borrowed, shared, conc, true);
    }
}

/// `get` on lazy `T` values sliced from one shared buffer.
fn bench_shared(
    comptime T: type,
    runner: *bench.Runner,
    value: []const u8,
    values: []const T,
) !void {
    const gpa = runner.allocator;
    const shared = try shared_slices(T, gpa, values);
    defer free_shared(gpa, shared);
    for (concurrencies) |conc| {
        const name = bench.Benchmark.init("codec::lazy::get").with_param("value", value)
            .with_param("source", "shared").with_param("txs", values.len)
            .with_param("conc", conc);
        try bench_get_with(T, runner, name, shared, conc, false);
    }
}

fn bench_get_values(runner: *bench.Runner, txs: usize) !void {
    const gpa = runner.allocator;

    // A value that keeps a byte field, which `get` borrows from the shared buffer.
    var prng: std.Random.DefaultPrng = .init(0);
    const plain = try random_txs(gpa, &prng, txs);
    defer gpa.free(plain);
    const memos = try gpa.alloc([16]u8, txs);
    defer gpa.free(memos);
    const memo_txs = try gpa.alloc(MemoTx, txs);
    defer gpa.free(memo_txs);
    for (plain, memos, memo_txs, 0..) |tx, *memo, *memo_tx, index| {
        memo.* = @splat(@truncate(index));
        memo_tx.* = .{ .tx = tx, .memo = .init(memo) };
    }
    try bench_shared(MemoTx, runner, "memo_tx", memo_txs);

    // A small fixed-size value, like a public key.
    prng = .init(0);
    const keys = try gpa.alloc([33]u8, txs);
    defer gpa.free(keys);
    for (keys) |*key| prng.random().bytes(key);
    try bench_shared([33]u8, runner, "key33", keys);
}

pub fn run(runner: *bench.Runner) !void {
    const txs = runner.inputs.pick(usize, 100, TXS, TXS);
    try bench_get(runner, txs);
    try bench_get_values(runner, txs);
}
