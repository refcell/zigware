//! Fault-injecting storage for the archive and freezer recovery fuzzers: commonware's
//! deterministic `FaultConfig` (torn writes, failed syncs, removes, and resizes, and torn
//! unsynced writes at a crash) over the memory backend. A fuzz input chooses the rates and
//! seeds the fault RNG, so it replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime");
const utils = @import("utils");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const memory = runtime.storage.memory;
const faulty = runtime.storage.faulty;
const Probability = utils.Probability;
const Rng = utils.rng.TestRng;

/// Must stay at one address: the fault layer points at its backend and RNG.
pub const Faults = struct {
    inner: memory.Storage,
    rng: Rng,
    layer: faulty.Storage(Rng),

    pub fn init(self: *Faults, gpa: std.mem.Allocator, seed: u64) void {
        self.inner = .init(gpa);
        self.rng = .init(seed);
        self.layer = .init(gpa, &self.inner, &self.rng, .{});
        assert(self.layer.inner == &self.inner);
        assert(self.layer.rng == &self.rng);
    }

    pub fn deinit(self: *Faults) void {
        self.layer.deinit();
        self.inner.deinit();
        self.* = undefined;
    }

    pub fn interface(self: *Faults) runtime.storage.Storage {
        return self.layer.storage();
    }

    /// Arms faults chosen by the input: writes fail at up to 1/8 and keep a prefix or a subset
    /// of their bytes at the given retention, syncs and removes fail at up to 1/8, and resizes
    /// fail (sometimes partway) at up to 1/8. Reads, opens, and scans never fail.
    pub fn arm(self: *Faults, reader: *fuzz_bytes.Reader) void {
        const write_failure = rate(reader, 8);
        const retention = Probability.init(reader.below(101), 100).?;
        const mode: faulty.PartialWriteMode = if (reader.boolean()) .prefix else .subset;
        self.layer.config = .{
            .write_rate = .{
                .failure_rate = write_failure,
                .retention_rate = retention,
                .mode = mode,
            },
            .sync_rate = rate(reader, 8),
            .remove_rate = rate(reader, 8),
            .resize_rate = .{ .failure_rate = rate(reader, 8), .partial_rate = .ratio(1, 2) },
        };
        assert(self.layer.config.read_rate == null and self.layer.config.open_rate == null);
    }

    /// Faults off: recovery and checks run on reliable storage.
    pub fn disarm(self: *Faults) void {
        self.layer.config = .{};
        assert(self.layer.config.write_rate == null);
    }

    /// A crash: the unsynced journal is replayed with its retention (tearing writes), then
    /// everything not durable is dropped and every blob can be reopened.
    pub fn crash(self: *Faults) !void {
        try self.layer.crash();
        self.inner.crash();
        assert(self.layer.pending.items.len == 0);
    }

    /// commonware's `faulted_recovery`: a chain of one to four `recover(context)` attempts,
    /// each under one fresh mutation fault drawn from the fault RNG and each crashing into the
    /// next. Attempt results are discarded (a failed mutation retires the instance), except
    /// that running out of memory is a real failure. Faults are off when it returns.
    pub fn faulted_recovery(self: *Faults, context: anytype, comptime recover: anytype) !void {
        const attempts = 1 + self.below(4);
        assert(attempts >= 1 and attempts <= 4);
        for (0..attempts) |_| {
            self.layer.config = self.recovery_fault_config();
            recover(context) catch |err| if (err == error.OutOfMemory) return err;
            // Retention binds when a write is issued, so clearing faults before the crash
            // still tears what the attempt wrote.
            self.disarm();
            try self.crash();
        }
        assert(self.layer.config.write_rate == null);
    }

    /// commonware's `recovery_fault_config`: one mutation (write, sync, resize, or remove)
    /// fails at a rate in 1..=100%, and the crash retention and partial-write mode stay live.
    fn recovery_fault_config(self: *Faults) faulty.Config {
        const mutation = self.below(4);
        const failure_rate = self.percent(1);
        var config: faulty.Config = .{ .write_rate = .{
            .failure_rate = if (mutation == 0) failure_rate else .zero,
            .retention_rate = self.percent(0),
            .mode = if (self.below(2) == 0) .prefix else .subset,
        } };
        switch (mutation) {
            0 => {},
            1 => config.sync_rate = failure_rate,
            2 => config.resize_rate = .{
                .failure_rate = failure_rate,
                .partial_rate = self.percent(0),
            },
            3 => config.remove_rate = failure_rate,
            else => unreachable, // Proof: `below(4)` is in 0..4.
        }
        assert(config.write_rate != null);
        return config;
    }

    fn below(self: *Faults, bound: u64) u64 {
        assert(bound > 0);
        const result = self.rng.next_u64() % bound;
        assert(result < bound);
        return result;
    }

    /// A probability of `from..=100` percent.
    fn percent(self: *Faults, from: u64) Probability {
        assert(from <= 100);
        return Probability.init(from + self.below(101 - from), 100).?;
    }
};

/// A rate in `[0, 1/denominator]`, in 1/256 steps of that range.
fn rate(reader: *fuzz_bytes.Reader, comptime denominator: u64) Probability {
    const numerator = reader.below(257);
    const result = Probability.init(numerator, 256 * denominator).?;
    assert(result.as_f64() <= 1.0 / @as(f64, denominator));
    return result;
}
