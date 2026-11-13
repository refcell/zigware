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
    _ = std.Io.fiber.contextSwitch(&message);
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
