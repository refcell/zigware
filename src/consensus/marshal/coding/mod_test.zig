//! commonware `marshal/coding/mod.rs`'s tests, on the coding harness (harness.zig).

const std = @import("std");
const testing = std.testing;
const harness = @import("harness.zig");
const shared = @import("../mocks/harness.zig");
const core_mailbox = @import("../core/mailbox.zig");

const Mailbox = core_mailbox.Mailbox(shared.S, harness.CodingVariant);

test "mailbox provides application blocks" {
    // commonware asserts `Mailbox<S, Coding<..>>: BlockProvider<Block = CodingB>`.
    try testing.expect(Mailbox.Block == harness.CodingB);
    try testing.expect(@hasDecl(Mailbox, "subscribe_parent"));
    try testing.expect(@hasDecl(Mailbox.ParentReceiver, "recv"));
}
