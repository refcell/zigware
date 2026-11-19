# stream

Exchange messages over arbitrary transport.

A Zig port of commonware's
[`commonware-stream`](https://github.com/commonwarexyz/monorepo/tree/main/stream).

## Status

**BETA** upstream: wire and storage formats are stable, and breaking changes come with a migration
path. See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port is complete. [docs/lanes/actor-stream.md](../../docs/lanes/actor-stream.md)
tracks it, including its test audit.

## Modules

- `Accepted(PublicKey)`, `SakeCups(S, C)` ([root.zig](root.zig)): the handshake contract's
  listener result, and CUPS over SAKE, the authenticated transport p2p uses.
- `cups` ([cups.zig](cups.zig)): an upgrader that runs a handshake, then exchanges encrypted,
  ordered records.
- `sake` ([sake.zig](sake.zig)): the SAKE handshake over an ordered byte stream.
- `utils` ([utils.zig](utils.zig)): length-prefixed framing (`utils.codec`) and a deadline
  around any upgrader (`utils.Timeout`).

## Testing

```sh
zig build test-stream  # unit tests, including the seeded fuzz targets
```

For long, coverage-guided fuzzing, run `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the
[actor-stream lane decisions](../../docs/lanes/actor-stream.md#decisions).

- Transports receive into caller buffers, so framing allocates nothing per frame. Framing
  errors carry no payload, and `error.Canceled` passes through.
- CUPS halves own their buffers. Records always decrypt in the receiver's own buffer, and a
  batch is still one sink call. Errors carry no payload.
- `Timeout` runs the attempt and the deadline as `std.Io.Select` tasks. A timed-out call
  returns a few scheduler cycles after its deadline, because a canceled fiber must run to
  unwind. Commonware drops the future at once.
- The stream conformance hashes (CupsV0, CupsV1, SakeV0CupsV1, SakeV1CupsV0) are not ported.
  They depend on commonware's executor polling order. Wire identity is checked piecewise
  instead: SAKE and ChaCha20-Poly1305 hashes, and CUPS record bytes against an oracle.
