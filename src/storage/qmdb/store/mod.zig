//! A mutable key-value database of variable-size values, without authentication
//! (qmdb/store).

const std = @import("std");

pub const db = @import("db.zig");
pub const Db = db.Db;
pub const Config = db.Config;

test {
    std.testing.refAllDecls(@This());
    _ = @import("db_test.zig");
}
