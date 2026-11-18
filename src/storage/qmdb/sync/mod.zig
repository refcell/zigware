//! Shared sync types for authenticated databases (commonware's `qmdb/sync`).
//!
//! Sources are untrusted: their responses are verified against the requested target. The
//! target itself is a trusted input chosen by the caller. Target updates form a forward-only
//! sequence: sync adopts only strictly advancing targets and discards the rest. The engine,
//! database interface, and sources land in later pieces.

const std = @import("std");

pub const errors = @import("error.zig");
pub const ServeError = errors.ServeError;
pub const EngineError = errors.EngineError;
pub const Error = errors.Error;
pub const database = @import("database.zig");
pub const gaps = @import("gaps.zig");
pub const journal = @import("journal.zig");
pub const requests = @import("requests.zig");
pub const metrics = @import("metrics.zig");
pub const Metrics = metrics.Metrics;
pub const source = @import("source.zig");
pub const Request = source.Request;
pub const Response = source.Response;
pub const max_response_size = source.max_response_size;
pub const Feedback = source.Feedback;
pub const Served = source.Served;
pub const JournalSource = source.JournalSource;
pub const target = @import("target.zig");
pub const Target = target.Target;
pub const CompactTarget = target.CompactTarget;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
    _ = @import("source_test.zig");
}
