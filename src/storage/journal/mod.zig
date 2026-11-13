//! An append-only log for storing arbitrary data.
//!
//! Port of commonware's `storage/src/journal`. Journals provide append-only logging for
//! persisting arbitrary data with fast replay, historical pruning, and rudimentary support for
//! fetching individual items. A journal can be used on its own to serve as a backing store
//! for some in-memory data structure, or as a building block for a more complex construction
//! that prescribes some meaning to items in the log.

const std = @import("std");
const codec = @import("codec");

pub const frame = @import("frame.zig");
pub const durability = @import("durability.zig");
pub const zstd = @import("zstd.zig");
pub const segmented = @import("segmented/mod.zig");
pub const contiguous = @import("contiguous/mod.zig");
pub const authenticated = @import("authenticated.zig");

/// Errors that can occur when interacting with a journal (commonware's `journal::Error`).
///
/// Zig errors carry no payload; commonware's payloads (section, offset, sizes) are reported
/// through return values or logs where callers need them. Codec failures keep their codec
/// error (commonware's `Error::Codec`).
pub const Error = error{
    InvalidBlobName,
    InvalidBlobSize,
    ItemTooLarge,
    AlreadyPrunedToSection,
    SectionOutOfRange,
    OffsetOverflow,
    ReplayInterrupted,
    ReplayFailed,
    SizeOverflow,
    ItemOutOfRange,
    ItemPruned,
    CompressionFailed,
    DecompressionFailed,
    ValueTooLarge,
    Corruption,
    /// The offsets journal and the data journal disagree about an item's layout.
    OffsetDataMismatch,
    InvalidConfiguration,
    ChecksumMismatch,
    EmptyAppend,
} || codec.Error;

test {
    std.testing.refAllDecls(@This());
}
