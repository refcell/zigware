//! Authenticated networking with peer addresses known in advance (commonware
//! `p2p/src/authenticated/lookup`).

pub const types = @import("types.zig");
pub const Message = types.Message;
pub const record = @import("record.zig");
pub const Record = record.Record;
pub const directory = @import("directory.zig");
pub const Directory = directory.Directory;

test {
    @import("std").testing.refAllDecls(@This());
}
