//! Stackful fibers: a stack, a saved CPU context, and the entry trampoline.
//!
//! The executors switch between fibers with `std.Io.fiber.contextSwitch`, the same primitive
//! `std.Io.Evented` uses. Every fiber switches back to its executor's scheduler context when it
//! blocks, so the scheduler alone decides what runs next (which the deterministic runtime needs
//! to replay a seed exactly).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const Context = std.Io.fiber.Context;

pub const supported = std.Io.fiber.supported;

const page_size = std.heap.page_size_min;

/// A mapped stack with an inaccessible guard page at its low end (Linux), so an overflow
/// faults instead of corrupting the neighbouring allocation.
pub const Stack = struct {
    memory: []align(page_size) u8,

    pub fn map(size_bytes: usize) error{OutOfMemory}!Stack {
        assert(size_bytes >= 16 * 1024);
        assert(size_bytes % page_size == 0);
        const total = size_bytes + page_size;
        const memory = std.posix.mmap(
            null,
            total,
            .{ .READ = true, .WRITE = true },
            map_flags(),
            -1,
            0,
        ) catch return error.OutOfMemory;
        if (builtin.os.tag == .linux) {
            const rc = std.os.linux.mprotect(memory.ptr, page_size, .{});
            assert(std.os.linux.errno(rc) == .SUCCESS);
        }
        assert(memory.len == total);
        return .{ .memory = memory };
    }

    pub fn unmap(stack: Stack) void {
        assert(stack.memory.len > page_size);
        std.posix.munmap(stack.memory);
    }

    /// One past the highest usable byte.
    pub fn top(stack: Stack) usize {
        return @intFromPtr(stack.memory.ptr) + stack.memory.len;
    }

    fn map_flags() std.posix.MAP {
        var flags: std.posix.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
        if (builtin.os.tag == .linux) flags.NORESERVE = true;
        return flags;
    }
};

/// The first frame on a fresh stack: what the trampoline hands to `entry_fn`.
pub const Frame = extern struct {
    entry_fn: *const fn (argument: *anyopaque) callconv(.c) noreturn,
    argument: *anyopaque,
};

comptime {
    assert(@sizeOf(Frame) <= 16);
}

/// Prepare `stack` so that switching to the returned context calls
/// `entry_fn(argument)` on it. `entry_fn` must never return: it switches away for good.
pub fn prepare(
    stack: Stack,
    entry_fn: *const fn (argument: *anyopaque) callconv(.c) noreturn,
    argument: *anyopaque,
) Context {
    const frame_address = std.mem.alignBackward(usize, stack.top() - @sizeOf(Frame), 16);
    assert(frame_address > @intFromPtr(stack.memory.ptr) + page_size);
    const frame: *Frame = @ptrFromInt(frame_address);
    frame.* = .{ .entry_fn = entry_fn, .argument = argument };
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ .rsp = frame_address - 8, .rbp = 0, .rip = @intFromPtr(&trampoline) },
        .aarch64, .riscv64 => .{ .sp = frame_address, .fp = 0, .pc = @intFromPtr(&trampoline) },
        else => @compileError("fibers are not implemented for this architecture"),
    };
}

/// Entered by the first switch to a prepared context. The stack pointer addresses the
/// `Frame` (plus the fake return slot on x86_64); load it and call the entry function.
fn trampoline() callconv(.naked) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ leaq 8(%%rsp), %%rdi
            \\ jmp %[start:P]
            :
            : [start] "X" (&start),
        ),
        .aarch64 => asm volatile (
            \\ mov x0, sp
            \\ b %[start]
            :
            : [start] "X" (&start),
        ),
        .riscv64 => asm volatile (
            \\ mv a0, sp
            \\ tail %[start]@plt
            :
            : [start] "X" (&start),
        ),
        else => @compileError("fibers are not implemented for this architecture"),
    }
}

fn start(frame: *Frame) callconv(.withStackAlign(.c, 16)) noreturn {
    frame.entry_fn(frame.argument);
}

/// Save the current CPU state into `from` and resume `to`.
pub inline fn switch_to(from: *Context, to: *Context) void {
    const message: std.Io.fiber.Switch = .{ .old = from, .new = to };
    if (builtin.cpu.arch == .aarch64) {
        switch_aarch64(&message);
    } else {
        _ = std.Io.fiber.contextSwitch(&message);
    }
}

/// Everything the switch clobbers except sp, fp, x18, and x30 (saved by hand above).
const aarch64_clobbers: std.lang.assembly.Clobbers = .{
    .x0 = true,
    .x1 = true,
    .x2 = true,
    .x3 = true,
    .x4 = true,
    .x5 = true,
    .x6 = true,
    .x7 = true,
    .x8 = true,
    .x9 = true,
    .x10 = true,
    .x11 = true,
    .x12 = true,
    .x13 = true,
    .x14 = true,
    .x15 = true,
    .x16 = true,
    .x17 = true,
    .x19 = true,
    .x20 = true,
    .x21 = true,
    .x22 = true,
    .x23 = true,
    .x24 = true,
    .x25 = true,
    .x26 = true,
    .x27 = true,
    .x28 = true,
    .x30 = true,
    .z0 = true,
    .z1 = true,
    .z2 = true,
    .z3 = true,
    .z4 = true,
    .z5 = true,
    .z6 = true,
    .z7 = true,
    .z8 = true,
    .z9 = true,
    .z10 = true,
    .z11 = true,
    .z12 = true,
    .z13 = true,
    .z14 = true,
    .z15 = true,
    .z16 = true,
    .z17 = true,
    .z18 = true,
    .z19 = true,
    .z20 = true,
    .z21 = true,
    .z22 = true,
    .z23 = true,
    .z24 = true,
    .z25 = true,
    .z26 = true,
    .z27 = true,
    .z28 = true,
    .z29 = true,
    .z30 = true,
    .z31 = true,
    .p0 = true,
    .p1 = true,
    .p2 = true,
    .p3 = true,
    .p4 = true,
    .p5 = true,
    .p6 = true,
    .p7 = true,
    .p8 = true,
    .p9 = true,
    .p10 = true,
    .p11 = true,
    .p12 = true,
    .p13 = true,
    .p14 = true,
    .p15 = true,
    .fpcr = true,
    .fpsr = true,
    .ffr = true,
    .memory = true,
};

/// `std.Io.fiber.contextSwitch` for aarch64, plus explicit saves of x18 and x30.
/// In optimized builds LLVM kept live values in both across std's asm, and the resuming
/// side overwrote them: x30 (the link register) despite its clobber (a bus error on macOS),
/// and x18, which std does not list because Darwin reserves it but Linux allocates it.
/// Every switch pushes x18/x30 on its own stack before leaving and pops them after
/// resuming (fp travels in the context). A fresh fiber starts at `trampoline`, not at the
/// resume label, so the pushes and pops pair up.
inline fn switch_aarch64(message: *const std.Io.fiber.Switch) void {
    _ = asm volatile (
        \\ stp x18, x30, [sp, #-16]!
        \\ ldp x0, x2, [x1]
        \\ ldr x3, [x2, #16]
        \\ mov x4, sp
        \\ stp x4, fp, [x0]
        \\ adr x5, 0f
        \\ ldp x4, fp, [x2]
        \\ str x5, [x0, #16]
        \\ mov sp, x4
        \\ br x3
        \\0:
        \\ ldp x18, x30, [sp], #16
        : [received_message] "={x1}" (-> *const std.Io.fiber.Switch),
        : [message_to_send] "{x1}" (message),
        : aarch64_clobbers);
}

test "fiber runs on its own stack and switches back" {
    if (!supported) return error.SkipZigTest;
    const State = struct {
        main: Context = undefined,
        fiber: Context = undefined,
        steps: u32 = 0,

        fn entry(argument: *anyopaque) callconv(.c) noreturn {
            const state: *@This() = @ptrCast(@alignCast(argument));
            var local: u32 = 1;
            state.steps += local;
            switch_to(&state.fiber, &state.main);
            local += 1;
            state.steps += local;
            switch_to(&state.fiber, &state.main);
            unreachable;
        }
    };
    const stack = try Stack.map(64 * 1024);
    defer stack.unmap();
    var state: State = .{};
    state.fiber = prepare(stack, State.entry, &state);
    switch_to(&state.main, &state.fiber);
    try std.testing.expectEqual(@as(u32, 1), state.steps);
    switch_to(&state.main, &state.fiber);
    try std.testing.expectEqual(@as(u32, 3), state.steps);
}
