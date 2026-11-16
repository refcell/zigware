//! The supervision tree (commonware `runtime/src/utils/supervision.rs`): which tasks a finished
//! or aborted task takes down with it.
//!
//! Every context has a node. `child` adds a node below the context's node. `spawn` consumes the
//! context: the task is registered at the context's node and runs with a new node below it.
//! When the task returns or is aborted, the whole subtree of the node it is registered at is
//! aborted, which cancels every task registered there (except a task finishing itself) and
//! retires the nodes. A node holds at most one task, so spawning twice from one context panics;
//! spawn several tasks from `ctx.child(label)`.
//!
//! Nodes live in a fixed pool sized at init (TigerStyle: bounded). A retired node's slot is
//! reused with a new generation, so a stale context (one whose node was retired) sees its node as
//! aborted: its children are aborted and its spawns return closed handles, as commonware's
//! aborted-parent contexts do. An exhausted pool panics.
//!
//! Each spawned task is an `Io.Future` that exactly one party consumes ("claims"): `join`,
//! `abort`, an aborting ancestor, or the zombie reaper (for detached handles). Others wait on
//! `done` for the stored result.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const none: u32 = std.math.maxInt(u32);

/// A reference to a node. Stale once the node is retired.
pub const NodeRef = struct {
    index: u32,
    generation: u32,

    /// A node that is already aborted.
    pub const aborted: NodeRef = .{ .index = none, .generation = 0 };
};

const Slot = struct {
    generation: u32 = 0,
    live: bool = false,
    parent: u32 = none,
    first_child: u32 = none,
    /// Next sibling while live; next free slot (or pending node while aborting) otherwise.
    next: u32 = none,
    previous: u32 = none,
    task: ?*Header = null,
};

/// The type-erased part of a spawned task's state.
pub const Header = struct {
    vtable: *const VTable,
    /// The node the task is registered at (its consumed context's node).
    node: NodeRef = .aborted,
    /// Some party consumes the future.
    claimed: bool = false,
    /// The task's function returned.
    ended: bool = false,
    /// The handle was released without joining.
    detached: bool = false,
    /// The task was canceled before it ended.
    closed: bool = false,
    /// The handle and the future.
    references: u8 = 2,
    /// Set once the claimer stored the result.
    done: Io.Event = .unset,
    /// Zombie list link.
    next: ?*Header = null,

    pub const VTable = struct {
        /// Await (or cancel and await) the future and store its result.
        finish: *const fn (header: *Header, io: Io, cancel: bool) void,
        destroy: *const fn (header: *Header) void,
    };
};

pub const Tree = struct {
    io: Io,
    mutex: Io.Mutex = .init,
    slots: []Slot,
    free: u32,
    live_count: u32 = 0,
    /// Detached tasks that ended; their futures still need awaiting.
    zombies: ?*Header = null,

    pub fn init(gpa: Allocator, io: Io, capacity: u32) Allocator.Error!Tree {
        assert(capacity > 0 and capacity < none);
        const slots = try gpa.alloc(Slot, capacity);
        for (slots, 0..) |*slot, index| {
            slot.* = .{ .next = if (index + 1 < capacity) @intCast(index + 1) else none };
        }
        return .{ .io = io, .slots = slots, .free = 0 };
    }

    /// Every task must be joined, aborted, or reaped first.
    pub fn deinit(tree: *Tree, gpa: Allocator) void {
        assert(tree.zombies == null);
        gpa.free(tree.slots);
        tree.* = undefined;
    }

    fn lock(tree: *Tree) void {
        tree.mutex.lockUncancelable(tree.io);
    }

    fn unlock(tree: *Tree) void {
        tree.mutex.unlock(tree.io);
    }

    fn live(tree: *const Tree, node: NodeRef) bool {
        if (node.index == none) return false;
        const slot = &tree.slots[node.index];
        return slot.live and slot.generation == node.generation;
    }

    /// A new root node.
    pub fn root(tree: *Tree) NodeRef {
        tree.lock();
        defer tree.unlock();
        return tree.allocate(none);
    }

    /// A new node below `parent`, or an aborted one if `parent` is aborted.
    pub fn child(tree: *Tree, parent: NodeRef) NodeRef {
        tree.lock();
        defer tree.unlock();
        if (!tree.live(parent)) return .aborted;
        return tree.allocate(parent.index);
    }

    fn allocate(tree: *Tree, parent: u32) NodeRef {
        const index = tree.free;
        if (index == none) @panic("supervision tree full: raise max_contexts");
        const slot = &tree.slots[index];
        assert(!slot.live);
        tree.free = slot.next;
        slot.* = .{ .generation = slot.generation, .live = true, .parent = parent };
        if (parent != none) {
            const parent_slot = &tree.slots[parent];
            assert(parent_slot.live);
            slot.next = parent_slot.first_child;
            if (slot.next != none) tree.slots[slot.next].previous = index;
            parent_slot.first_child = index;
        }
        tree.live_count += 1;
        return .{ .index = index, .generation = slot.generation };
    }

    /// Registers `header`'s task at `header.node`. False if that node was aborted meanwhile
    /// (by an ancestor, or by the task itself returning); the caller then consumes the task.
    pub fn attach(tree: *Tree, header: *Header) bool {
        tree.lock();
        defer tree.unlock();
        if (!tree.live(header.node)) return false;
        const slot = &tree.slots[header.node.index];
        if (slot.task != null) @panic("spawn consumes its context: spawn from ctx.child(label)");
        slot.task = header;
        return true;
    }

    /// Claims the future for the caller, which awaits it, or cancels it when `cancel` (the
    /// task is then closed unless it already ended). False if another party claimed it.
    pub fn claim(tree: *Tree, header: *Header, cancel: bool) bool {
        tree.lock();
        defer tree.unlock();
        return tree.claim_locked(header, cancel);
    }

    fn claim_locked(tree: *const Tree, header: *Header, cancel: bool) bool {
        _ = tree;
        if (header.claimed) return false;
        header.claimed = true;
        header.closed = cancel and !header.ended;
        return true;
    }

    /// Consumes a claimed future and releases the future's reference.
    pub fn finish(tree: *Tree, header: *Header, cancel: bool) void {
        assert(header.claimed);
        header.vtable.finish(header, tree.io, cancel);
        header.done.set(tree.io);
        tree.release(header);
    }

    /// Drops one reference; the last frees the task state.
    pub fn release(tree: *Tree, header: *Header) void {
        tree.lock();
        assert(header.references > 0);
        header.references -= 1;
        const last = header.references == 0;
        tree.unlock();
        if (last) header.vtable.destroy(header);
    }

    /// Aborts the subtree at `node`: retires its nodes and cancels every task registered in
    /// it except `self` (a task finishing itself). Returns once those tasks have returned.
    pub fn abort(tree: *Tree, node: NodeRef, self: ?*Header) void {
        var claimed: ?*Header = null;
        tree.lock();
        if (tree.live(node)) {
            tree.unlink(node.index);
            var pending = node.index;
            var visited: u32 = 0;
            while (pending != none) : (visited += 1) {
                assert(visited < tree.slots.len);
                const index = pending;
                const slot = &tree.slots[index];
                pending = slot.next;
                var child_index = slot.first_child;
                while (child_index != none) {
                    const next = tree.slots[child_index].next;
                    tree.slots[child_index].next = pending;
                    pending = child_index;
                    child_index = next;
                }
                if (slot.task) |task| {
                    if (task != self and tree.claim_locked(task, true)) {
                        task.next = claimed;
                        claimed = task;
                    }
                }
                tree.retire(index);
            }
        }
        tree.unlock();
        while (claimed) |task| {
            claimed = task.next;
            task.next = null;
            tree.finish(task, true);
        }
    }

    /// Removes a live node from its parent's children (lock held).
    fn unlink(tree: *Tree, index: u32) void {
        const slot = &tree.slots[index];
        assert(slot.live);
        if (slot.previous != none) {
            tree.slots[slot.previous].next = slot.next;
        } else if (slot.parent != none) {
            assert(tree.slots[slot.parent].first_child == index);
            tree.slots[slot.parent].first_child = slot.next;
        }
        if (slot.next != none) tree.slots[slot.next].previous = slot.previous;
        slot.next = none;
        slot.previous = none;
        slot.parent = none;
    }

    /// Returns a node's slot to the free list with a new generation (lock held).
    fn retire(tree: *Tree, index: u32) void {
        const slot = &tree.slots[index];
        assert(slot.live);
        slot.* = .{ .generation = slot.generation +% 1, .next = tree.free };
        tree.free = index;
        tree.live_count -= 1;
    }

    /// The task's function returned: a detached, unclaimed task becomes a zombie.
    pub fn ended(tree: *Tree, header: *Header) void {
        tree.lock();
        defer tree.unlock();
        assert(!header.ended);
        header.ended = true;
        if (header.detached and tree.claim_locked(header, false)) {
            header.next = tree.zombies;
            tree.zombies = header;
        }
    }

    /// The handle is released without joining.
    pub fn detach(tree: *Tree, header: *Header) void {
        tree.lock();
        assert(!header.detached);
        header.detached = true;
        const reap_now = header.ended and tree.claim_locked(header, false);
        tree.unlock();
        if (reap_now) tree.finish(header, false);
        tree.release(header);
    }

    /// Awaits every zombie's future.
    pub fn reap(tree: *Tree) void {
        tree.lock();
        var zombies = tree.zombies;
        tree.zombies = null;
        tree.unlock();
        while (zombies) |zombie| {
            zombies = zombie.next;
            zombie.next = null;
            tree.finish(zombie, false);
        }
    }
};
