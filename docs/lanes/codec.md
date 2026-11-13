# Lane: codec

Owns `src/formatting`, `src/conformance`, `src/invariants`, `src/codec`. Everything else
builds on codec, so land the core API first and keep it stable; record each public type
here so other lanes can code against it.

Reference: `~/.cache/zigware/commonware-ref/{formatting,conformance,invariants,codec}`.

## Backlog
- [ ] formatting: hex encode/decode (`hex`, `from_hex`, `from_hex_formatted`), display
  helpers, hex literal parsing at comptime. Tests from formatting/src.
- [ ] codec core: `Write`/`Read`/`EncodeSize`/`Encode`/`Decode` as comptime interfaces
  (a type with `write`, `read(cfg)`, `encode_size`), error set matching codec/src/error.rs,
  `RangeCfg` and config types, buffer helpers (buf.rs).
- [ ] codec varint (u16/u32/u64/u128, zigzag signed) byte-identical to varint.rs, with its
  tests and a fuzz round-trip.
- [ ] codec types: primitives (ints big-endian, bool, f32/f64, arrays), bytes, vec, tuple,
  optional, maps/sets (sorted, canonical encoding, reject duplicates/unsorted), net addrs,
  lazy. Port every test in codec/src/types.
- [ ] conformance: the hash-of-encodings harness (conformance/src/lib.rs) and codec's
  conformance.rs, reading commonware's committed conformance TOML so encodings are proven
  identical.
- [ ] invariants: invariant definitions and minifuzz (deterministic seeded fuzz driver all
  lanes use; expose seed/iteration knobs from `build_options.fuzz_seed`/`fuzz_soak`).
- [ ] `std.testing.fuzz` targets for every decoder (commonware codec/fuzz).

## Log
