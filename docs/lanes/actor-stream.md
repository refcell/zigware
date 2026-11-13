# Lane: actor-stream

Owns `src/actor`, `src/stream`.

Reference: `~/.cache/zigware/commonware-ref/{actor,stream}`. Both run on the runtime lane's
deterministic runtime (`runtime.deterministic.Runner`, `runner.io()` is a full `std.Io`;
see docs/lanes/runtime.md). Write library code against `std.Io`.

## Backlog
- [ ] actor: mailbox (bounded, over `std.Io.Queue` or a ring with backpressure), the actor
  traits and lifecycle in actor/src/lib.rs, with its tests on the deterministic runtime.
- [ ] stream utils: length-prefixed framing codec (utils/codec.rs), timeouts.
- [ ] stream sake: the authenticated handshake protocol and encrypted send/receive, wire
  format and conformance hashes identical to commonware's. Uses cryptography's ed25519,
  chacha20_poly1305, transcript, and handshake as the crypto lane lands them; coordinate
  with it (thread in docs/lanes/README.md) if you need one of those sooner.
- [ ] stream cups protocol.
- [ ] Tests over the runtime's deterministic network once it lands (in-memory sink/stream
  pairs before then), plus fuzz targets (commonware stream/fuzz).

## Log
