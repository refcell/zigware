//! Stackful fibers: a stack, a saved stack pointer, and an out-of-line context switch.
//!
//! The executors switch between fibers with `switch_to`, which calls `switch_naked`, a naked
//! function, through a C-ABI function pointer. That makes the switch an ordinary call: the
//! ABI guarantees where its arguments are and that the caller treats every caller-saved
//! register as clobbered, and `switch_naked` itself pushes every callee-saved register (and
//! the floating-point control state) on the outgoing fiber's stack before switching stacks,
//! then pops the incoming fiber's. Correctness therefore holds for any register allocation.
//!
//! We do not use `std.Io.fiber.contextSwitch`: it is inline asm with register operands and a
//! clobber list, and in optimized builds LLVM lowered it wrongly here. On aarch64 it kept
//! live values in x30 and x18 across the switch, and on x86_64 it omitted loading the `rsi`
//! input operand, so the switch read its message through a stale pointer.
//!
//! Every fiber switches back to its executor's scheduler context when it blocks, so the
//! scheduler alone decides what runs next (which the deterministic runtime needs to replay a
//! seed exactly).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

pub const supported = switch (builtin.cpu.arch) {
    .x86_64, .aarch64 => true,
    else => false,
};

/// A suspended fiber: its stack pointer. Its callee-saved registers are on that stack.
pub const Context = struct {
    sp: usize = 0,
};

const page_size = std.heap.page_size_min;

/// A mapped stack with an inaccessible guard page at each end (Linux): an overflow faults
/// instead of corrupting the neighbouring allocation, and so does an unwinder that walks past
/// the outermost frame.
pub const Stack = struct {
    memory: []align(page_size) u8,

    pub fn map(size_bytes: usize) error{OutOfMemory}!Stack {
        assert(size_bytes >= 16 * 1024);
        assert(size_bytes % page_size == 0);
        const total = size_bytes + 2 * page_size;
        const memory = std.posix.mmap(
            null,
            total,
            .{ .READ = true, .WRITE = true },
            map_flags(),
            -1,
            0,
        ) catch return error.OutOfMemory;
        if (builtin.os.tag == .linux) {
            const low = std.os.linux.mprotect(memory.ptr, page_size, .{});
            assert(std.os.linux.errno(low) == .SUCCESS);
            const high = std.os.linux.mprotect(memory[total - page_size ..].ptr, page_size, .{});
            assert(std.os.linux.errno(high) == .SUCCESS);
        }
        assert(memory.len == total);
        return .{ .memory = memory };
    }

    pub fn unmap(stack: Stack) void {
        assert(stack.memory.len > 2 * page_size);
        std.posix.munmap(stack.memory);
    }

    /// One past the highest usable byte (the start of the high guard page).
    pub fn top(stack: Stack) usize {
        return @intFromPtr(stack.memory.ptr) + stack.memory.len - page_size;
    }

    fn map_flags() std.posix.MAP {
        var flags: std.posix.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
        if (builtin.os.tag == .linux) flags.NORESERVE = true;
        return flags;
    }
};

pub const EntryFn = *const fn (argument: *anyopaque) callconv(.c) noreturn;

/// Bytes `switch_naked` keeps on a suspended fiber's stack, return address included.
const saved_frame_bytes = switch (builtin.cpu.arch) {
    // FP control words, r15, r14, r13, r12, rbx, rbp, return address.
    .x86_64 => 8 * 8,
    // x19..x28, x29, x30, d8..d15, fpcr, padding.
    .aarch64 => 176,
    else => 0,
};

comptime {
    assert(saved_frame_bytes % 16 == 0);
}

/// Prepare `stack` so that switching to the returned context calls `entry_fn(argument)` on
/// it. `entry_fn` must never return: it switches away for good.
pub fn prepare(stack: Stack, entry_fn: EntryFn, argument: *anyopaque) Context {
    comptime assert(supported);
    // Above the saved frame sits a zeroed 16-byte terminator: an unwinder that walks past
    // `trampoline` (such as an allocator capturing a stack trace) reads a null return address
    // there instead of the first byte past the mapping.
    const terminator_bytes = 16;
    const base = std.mem.alignBackward(usize, stack.top(), 16) - saved_frame_bytes -
        terminator_bytes;
    assert(base > @intFromPtr(stack.memory.ptr) + page_size);
    assert(base % 16 == 0);
    const slots: [*]usize = @ptrFromInt(base);
    @memset(slots[0 .. (saved_frame_bytes + terminator_bytes) / @sizeOf(usize)], 0);
    switch (builtin.cpu.arch) {
        .x86_64 => {
            // Default MXCSR (all exceptions masked, round to nearest) and x87 control word.
            slots[0] = 0x1F80 | (@as(usize, 0x037F) << 32);
            slots[4] = @intFromPtr(argument); // r12
            slots[3] = @intFromPtr(entry_fn); // r13
            slots[7] = @intFromPtr(&trampoline); // return address
        },
        .aarch64 => {
            slots[0] = @intFromPtr(argument); // x19
            slots[1] = @intFromPtr(entry_fn); // x20
            slots[11] = @intFromPtr(&trampoline); // x30
        },
        else => unreachable,
    }
    return .{ .sp = base };
}

/// Whether switches save and restore the floating-point control state (x86_64 MXCSR and x87
/// control word, aarch64 FPCR). It is callee-saved, so a fiber that changed it and switched
/// away would hand it to the next fiber. No zigware code changes it: safe builds keep the save
/// and assert at every switch that the outgoing fiber's state is the default, which is the
/// condition under which skipping the save changes nothing; optimized builds skip it (about
/// 2.5 ns per switch on x86_64).
pub const saves_fp_control = builtin.mode == .debug or builtin.mode == .safe;

/// Save the current fiber into `from` and resume `to`. Returns when something switches back.
pub fn switch_to(from: *Context, to: *const Context) void {
    comptime assert(supported);
    assert(to.sp != 0);
    assert(to.sp % 16 == 0);
    if (saves_fp_control) assert(fp_control_is_default());
    const switch_fn: *const fn (from_sp: *usize, to_sp: usize) callconv(.c) void =
        if (saves_fp_control) @ptrCast(&switch_naked) else @ptrCast(&switch_naked_fast);
    switch_fn(&from.sp, to.sp);
}

/// Whether the floating-point control state, ignoring sticky exception flags, is the default
/// every fiber starts with (`prepare`'s saved frame).
pub fn fp_control_is_default() bool {
    var state: u64 = 0;
    const read_fn: *const fn (state: *u64) callconv(.c) void = @ptrCast(&fp_control_read);
    read_fn(&state);
    return switch (builtin.cpu.arch) {
        // MXCSR in the low word, the x87 control word above it. MXCSR bits 0..5 are exception
        // flags that ordinary arithmetic sets.
        .x86_64 => state & 0xFFFF_FFFF & ~@as(u64, 0x3F) == 0x1F80 and
            (state >> 32) & 0xFFFF == 0x037F,
        .aarch64 => state == 0,
        else => unreachable,
    };
}

/// `read_fn(state: *u64)`: store the floating-point control state, as `switch_naked` saves it.
fn fp_control_read() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ stmxcsr (%%rdi)
            \\ fnstcw 4(%%rdi)
            \\ retq
        ),
        .aarch64 => asm volatile (
            \\ mrs x9, fpcr
            \\ str x9, [x0]
            \\ ret
        ),
        else => @compileError("fibers are not implemented for this architecture"),
    }
}

/// `switch_naked` without the floating-point control state, for optimized builds. The frame
/// keeps the same layout, so `prepare` serves both.
fn switch_naked_fast() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ pushq %%rbp
            \\ pushq %%rbx
            \\ pushq %%r12
            \\ pushq %%r13
            \\ pushq %%r14
            \\ pushq %%r15
            \\ subq $8, %%rsp
            \\ movq %%rsp, (%%rdi)
            \\ movq %%rsi, %%rsp
            \\ addq $8, %%rsp
            \\ popq %%r15
            \\ popq %%r14
            \\ popq %%r13
            \\ popq %%r12
            \\ popq %%rbx
            \\ popq %%rbp
            \\ retq
        ),
        .aarch64 => asm volatile (
            \\ sub sp, sp, #176
            \\ stp x19, x20, [sp, #0]
            \\ stp x21, x22, [sp, #16]
            \\ stp x23, x24, [sp, #32]
            \\ stp x25, x26, [sp, #48]
            \\ stp x27, x28, [sp, #64]
            \\ stp x29, x30, [sp, #80]
            \\ stp d8, d9, [sp, #96]
            \\ stp d10, d11, [sp, #112]
            \\ stp d12, d13, [sp, #128]
            \\ stp d14, d15, [sp, #144]
            \\ mov x9, sp
            \\ str x9, [x0]
            \\ mov sp, x1
            \\ ldp x19, x20, [sp, #0]
            \\ ldp x21, x22, [sp, #16]
            \\ ldp x23, x24, [sp, #32]
            \\ ldp x25, x26, [sp, #48]
            \\ ldp x27, x28, [sp, #64]
            \\ ldp x29, x30, [sp, #80]
            \\ ldp d8, d9, [sp, #96]
            \\ ldp d10, d11, [sp, #112]
            \\ ldp d12, d13, [sp, #128]
            \\ ldp d14, d15, [sp, #144]
            \\ add sp, sp, #176
            \\ ret
        ),
        else => @compileError("fibers are not implemented for this architecture"),
    }
}

/// `switch_fn(from_sp: *usize, to_sp: usize)`: push callee-saved state, store sp into
/// `from_sp`, load `to_sp`, pop the incoming fiber's state, and return into it.
fn switch_naked() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ pushq %%rbp
            \\ pushq %%rbx
            \\ pushq %%r12
            \\ pushq %%r13
            \\ pushq %%r14
            \\ pushq %%r15
            \\ subq $8, %%rsp
            \\ stmxcsr (%%rsp)
            \\ fnstcw 4(%%rsp)
            \\ movq %%rsp, (%%rdi)
            \\ movq %%rsi, %%rsp
            \\ ldmxcsr (%%rsp)
            \\ fldcw 4(%%rsp)
            \\ addq $8, %%rsp
            \\ popq %%r15
            \\ popq %%r14
            \\ popq %%r13
            \\ popq %%r12
            \\ popq %%rbx
            \\ popq %%rbp
            \\ retq
        ),
        .aarch64 => asm volatile (
            \\ sub sp, sp, #176
            \\ stp x19, x20, [sp, #0]
            \\ stp x21, x22, [sp, #16]
            \\ stp x23, x24, [sp, #32]
            \\ stp x25, x26, [sp, #48]
            \\ stp x27, x28, [sp, #64]
            \\ stp x29, x30, [sp, #80]
            \\ stp d8, d9, [sp, #96]
            \\ stp d10, d11, [sp, #112]
            \\ stp d12, d13, [sp, #128]
            \\ stp d14, d15, [sp, #144]
            \\ mrs x9, fpcr
            \\ str x9, [sp, #160]
            \\ mov x9, sp
            \\ str x9, [x0]
            \\ mov sp, x1
            \\ ldp x19, x20, [sp, #0]
            \\ ldp x21, x22, [sp, #16]
            \\ ldp x23, x24, [sp, #32]
            \\ ldp x25, x26, [sp, #48]
            \\ ldp x27, x28, [sp, #64]
            \\ ldp x29, x30, [sp, #80]
            \\ ldp d8, d9, [sp, #96]
            \\ ldp d10, d11, [sp, #112]
            \\ ldp d12, d13, [sp, #128]
            \\ ldp d14, d15, [sp, #144]
            \\ ldr x9, [sp, #160]
            \\ msr fpcr, x9
            \\ add sp, sp, #176
            \\ ret
        ),
        else => @compileError("fibers are not implemented for this architecture"),
    }
}

/// Where a prepared fiber's first switch returns to: enter `entry_fn(argument)`, both left in
/// callee-saved registers by `prepare`. The stack is 16-byte aligned here.
///
/// `entry_fn` is entered with a null return address (pushed on x86_64, in x30 on aarch64)
/// instead of called, so it is the outermost frame: every unwinder, DWARF or frame pointer,
/// stops there. A call would leave a return address into this function, which has no CFI; on
/// aarch64 its return address is x30 again, so an unwinder repeats this frame forever. The
/// stack alignment `entry_fn` sees is the same as after a call.
fn trampoline() callconv(.naked) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movq %%r12, %%rdi
            \\ pushq $0
            \\ jmpq *%%r13
        ),
        .aarch64 => asm volatile (
            \\ mov x0, x19
            \\ mov x30, xzr
            \\ br x20
        ),
        else => @compileError("fibers are not implemented for this architecture"),
    }
}

const testing = std.testing;

test "fiber runs on its own stack and switches back" {
    if (!supported) return error.SkipZigTest;
    const State = struct {
        main: Context = .{},
        fiber: Context = .{},
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
    try testing.expectEqual(@as(u32, 1), state.steps);
    switch_to(&state.main, &state.fiber);
    try testing.expectEqual(@as(u32, 3), state.steps);
}

// Regression (899b57d): code on a fiber that captures a stack trace, as testing.allocator does
// on every free, must stop at the outermost frame instead of reading past the stack (into the
// high guard page here, a segfault).
test "stack traces on a fiber stop at the outermost frame" {
    if (!supported) return error.SkipZigTest;
    const State = struct {
        main: Context = .{},
        fiber: Context = .{},
        frames_safe: usize = 0,
        frames_unsafe: usize = 0,
        freed: bool = false,

        fn entry(argument: *anyopaque) callconv(.c) noreturn {
            const state: *@This() = @ptrCast(@alignCast(argument));
            var addresses: [64]usize = undefined;
            const safe = std.debug.captureCurrentStackTrace(.{}, &addresses);
            state.frames_safe = safe.return_addresses.len;
            const unsafe = std.debug.captureCurrentStackTrace(.{
                .allow_unsafe_unwind = true,
            }, &addresses);
            state.frames_unsafe = unsafe.return_addresses.len;
            if (testing.allocator.alloc(u8, 32)) |bytes| {
                testing.allocator.free(bytes);
                state.freed = true;
            } else |_| {}
            switch_to(&state.fiber, &state.main);
            unreachable;
        }
    };
    const stack = try Stack.map(64 * 1024);
    defer stack.unmap();
    var state: State = .{};
    state.fiber = prepare(stack, State.entry, &state);
    switch_to(&state.main, &state.fiber);
    try testing.expect(state.freed);
    // The walk ends at `entry`, the outermost frame, instead of filling the buffer.
    try testing.expect(state.frames_safe >= 1 and state.frames_safe <= 4);
    try testing.expect(state.frames_unsafe >= 1 and state.frames_unsafe <= 4);
}

// Many fibers ping-pong with the scheduler while keeping values live in locals and floats
// across every switch; any register the switch fails to preserve shows up as a wrong sum.
test "fibers preserve live values across many switches" {
    if (!supported) return error.SkipZigTest;
    const fiber_count = 8;
    const rounds = 1000;
    const Shared = struct {
        main: Context = .{},
        current: usize = 0,
    };
    const Fiber = struct {
        shared: *Shared,
        context: Context = .{},
        index: u64,
        sum: u64 = 0,
        float_sum: f64 = 0,
        alignment_ok: bool = true,

        fn entry(argument: *anyopaque) callconv(.c) noreturn {
            const self: *@This() = @ptrCast(@alignCast(argument));
            var a: u64 = self.index;
            var b: u64 = self.index * 3 + 1;
            var c: f64 = @floatFromInt(self.index);
            var aligned: @Vector(4, f32) align(16) = @splat(@floatFromInt(self.index));
            for (0..rounds) |round| {
                a +%= round;
                b ^= a *% 0x9e37_79b9_7f4a_7c15;
                c += 0.5;
                aligned += @splat(1.0);
                if (@intFromPtr(&aligned) % 16 != 0) self.alignment_ok = false;
                switch_to(&self.context, &self.shared.main);
            }
            self.sum = a +% b;
            self.float_sum = c + aligned[0];
            switch_to(&self.context, &self.shared.main);
            unreachable;
        }
    };
    var shared: Shared = .{};
    var fibers: [fiber_count]Fiber = undefined;
    var stacks: [fiber_count]Stack = undefined;
    for (&fibers, &stacks, 0..) |*fiber, *stack, i| {
        stack.* = try Stack.map(64 * 1024);
        fiber.* = .{ .shared = &shared, .index = i };
        fiber.context = prepare(stack.*, Fiber.entry, fiber);
    }
    defer for (stacks) |stack| stack.unmap();
    for (0..rounds + 1) |_| {
        for (&fibers) |*fiber| switch_to(&shared.main, &fiber.context);
    }
    for (fibers, 0..) |fiber, i| {
        var a: u64 = i;
        var b: u64 = i * 3 + 1;
        for (0..rounds) |round| {
            a +%= round;
            b ^= a *% 0x9e37_79b9_7f4a_7c15;
        }
        try testing.expectEqual(a +% b, fiber.sum);
        const index: f64 = @floatFromInt(i);
        try testing.expectEqual(index + 0.5 * rounds + index + rounds, fiber.float_sum);
        try testing.expect(fiber.alignment_ok);
    }
}

/// Sets the floating-point control state from `state`, laid out as `fp_control_read` stores it.
fn fp_control_set(state: u64) void {
    const write_fn: *const fn (state: *const u64) callconv(.c) void = @ptrCast(&fp_control_write);
    write_fn(&state);
}

fn fp_control_write() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ ldmxcsr (%%rdi)
            \\ fldcw 4(%%rdi)
            \\ retq
        ),
        .aarch64 => asm volatile (
            \\ ldr x9, [x0]
            \\ msr fpcr, x9
            \\ ret
        ),
        else => @compileError("fibers are not implemented for this architecture"),
    }
}

/// The default state (`prepare`'s), and the same with rounding toward zero.
const fp_default: u64 = if (builtin.cpu.arch == .x86_64) 0x1F80 | (0x037F << 32) else 0;
const fp_round_to_zero: u64 = if (builtin.cpu.arch == .x86_64) fp_default | 0x6000 else 3 << 22;

/// Switches to a fiber and back once, with `fp_state` set across the switch.
fn switch_with_fp_control(fp_state: u64) !void {
    const State = struct {
        main: Context = .{},
        fiber: Context = .{},

        fn entry(argument: *anyopaque) callconv(.c) noreturn {
            const state: *@This() = @ptrCast(@alignCast(argument));
            switch_to(&state.fiber, &state.main);
            unreachable;
        }
    };
    const stack = try Stack.map(64 * 1024);
    defer stack.unmap();
    var state: State = .{};
    state.fiber = prepare(stack, State.entry, &state);
    fp_control_set(fp_state);
    defer fp_control_set(fp_default);
    switch_to(&state.main, &state.fiber);
}

// The fast switch skips the floating-point control state, which is only equivalent while every
// fiber switches with the default: safe builds assert it, so a fiber that changed the rounding
// mode fails loudly instead of handing it to the next fiber in an optimized build.
test "a switch with non-default floating-point control state panics in safe builds" {
    if (!supported or !saves_fp_control) return error.SkipZigTest;
    // Sticky exception flags (x86_64 MXCSR bits 0..5, here precision) are not control state.
    if (builtin.cpu.arch == .x86_64) try switch_with_fp_control(fp_default | 0x20);
    try @import("utils").death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            try switch_with_fp_control(fp_round_to_zero);
        }
    }.body);
}
