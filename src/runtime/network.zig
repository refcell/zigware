//! Network interface (commonware `Network`, `Listener`, `Sink`, and `Stream` traits in
//! `runtime/src/lib.rs`, and `runtime/src/network`).
//!
//! Backends are duck-typed (each declares `Listener`, `Accepted`, and `Connection`):
//!
//! ```zig
//! var listener = try network.bind(address);   // error.BindFailed if taken
//! const accepted = try listener.accept();     // .address, .sink, .stream
//! listener.local_addr()                        // Address
//! var connection = try network.dial(address); // .sink, .stream; error.ConnectionFailed
//! try sink.send(&.{ header, body });           // one write of every buffer, in order
//! try stream.recv(out);                        // exactly out.len bytes
//! stream.peek(max_len)                         // buffered bytes, never blocks
//! ```
//!
//! Sinks and streams follow the contract in `runtime.mocks` (byte-compatible with
//! `src/stream/mocks.zig`): after any error a half is unusable and the next call returns
//! `error.Closed`; `error.Canceled` also poisons the half it interrupted. Close each half and
//! each listener with `deinit`.

const std = @import("std");

/// A socket address.
pub const Address = std.Io.net.IpAddress;

pub const Error = error{
    BindFailed,
    ConnectionFailed,
    ReadFailed,
    SendFailed,
    RecvFailed,
    Closed,
    OutOfMemory,
} || std.Io.Cancelable;

pub const deterministic = @import("network/deterministic.zig");
pub const tests = @import("network/tests.zig");

test {
    _ = deterministic;
}
