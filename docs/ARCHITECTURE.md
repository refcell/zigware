# Architecture

zigware mirrors the commonware monorepo crate for crate. Each crate is one Zig package with
the same name, the same public concepts, and the same dependency edges.

| commonware | zigware |
| --- | --- |
| `<crate>/src/lib.rs` | `src/<crate>/root.zig` |
| `<crate>/src/<module>` | `src/<crate>/<module>/` (or `<module>.zig`) |
| `<crate>/fuzz/`, proptests | `std.testing.fuzz` tests and `invariants.minifuzz` targets next to the code, run seeded in `zig build test` |
| `<crate>/src/**/conformance.rs` | the same conformance hashes, checked by `zig build test` (the heavy ones only with `-Dslow-tests`) |
| `examples/<name>` | `examples/<name>/main.zig` (or `<binary>.zig` per binary), a `run-<name>` build step |
| `macros`, `*/macros` | comptime code in the package that uses it (no separate package) |
| `docs`, `mcp`, `sol`, `docker`, `pipeline` | not ported |

## Packages and dependency order

`build.zig` declares one module per package and lets a package import only the packages
its Rust crate depends on. The order below is a valid build order: each line depends only
on lines above it.

| Package | Imports | commonware size (Rust lines) |
| --- | --- | ---: |
| formatting |  | 0.6k |
| allocator |  | 2.2k |
| bench |  | 1.8k |
| conformance | formatting | 0.8k |
| invariants | formatting | 0.6k |
| simd | invariants | 9k |
| codec | conformance, formatting | 9k |
| utils | codec, formatting, conformance, invariants | 35k |
| parallel | utils | 26k |
| math | codec, invariants, parallel, utils, simd, conformance | 4.6k |
| cryptography | codec, formatting, math, parallel, utils, invariants, simd, conformance | 67k |
| curve25519 (`src/cryptography/curve25519`) | codec, cryptography, formatting, math, parallel, utils, conformance, invariants | 20k |
| runtime | codec, cryptography, formatting, parallel, utils, conformance | 99k |
| actor | runtime, utils | 2.8k |
| storage | codec, cryptography, formatting, parallel, runtime, utils, math, conformance, invariants | 220k |
| stream | codec, cryptography, formatting, math, runtime, utils | 4.3k |
| coding | codec, cryptography, parallel, storage, utils, runtime, invariants, conformance | 4.3k |
| clearing | codec, cryptography, formatting, parallel, storage, utils, runtime, conformance, invariants | 16k |
| p2p | actor, codec, cryptography, math, parallel, runtime, stream, utils, conformance, invariants | 42k |
| broadcast | actor, codec, cryptography, p2p, parallel, runtime, utils, invariants | 3.3k |
| collector | actor, codec, cryptography, p2p, runtime, utils, invariants | 2.4k |
| resolver | actor, codec, cryptography, p2p, runtime, stream, utils, conformance | 14k |
| consensus | actor, broadcast, codec, coding, cryptography, formatting, math, parallel, p2p, resolver, runtime, storage, utils, conformance, invariants | 140k |
| glue | actor, broadcast, codec, coding, consensus, cryptography, math, p2p, parallel, resolver, runtime, storage, stream, utils, conformance, invariants | 68k |
| deployer | cryptography, utils | 8.8k |

The table is `build.zig`'s `packages` list, in its order. Rust line counts are every `.rs` file
under the crate at commonware a9ffc25f3 (2026-11-19), tests included, which are a large share
of every crate; cryptography's excludes `curve25519`.

## Principles

- **Same wire formats.** Codec encodings, storage layouts, network messages, hashes, and
  signatures are byte-identical to commonware's. Commonware's conformance hashes and test
  vectors are ported with the code and must pass.
- **The runtime is the only door to the OS.** Commonware passes a `Context` that implements
  `Spawner`, `Clock`, `Network`, `Storage`, `Metrics`, and an RNG. zigware does the same
  with `runtime.Context`: library code never reads the clock, opens a socket or file, or
  draws randomness except through it. There are two runtimes behind one interface:
  - **deterministic**: single-threaded, seeded scheduler on stackful fibers, simulated time,
    in-memory storage with fault injection, and an auditor hash of every event, so any run
    replays exactly from its seed and two runs can be compared. It shuffles each ready batch
    with commonware's `StdRng` and shuffle, but queues a woken task once, where commonware's
    executor queues it once per wake. Tests that pin commonware's bytes from a seeded run draw
    the shuffles that difference removes. stream's conformance draws one after joining its
    listener task (`src/stream/sake_conformance_test.zig`), where commonware holds the root
    task twice; removing that draw breaks all four hashes;
  - **production**: real clock, TCP, and files on disk. Its `Runner` owns a `std.Io.Threaded`
    on every platform, since `std.Io.Uring` does not compile in Zig 0.17.1; on Linux,
    `Config.io_uring` moves blob and socket I/O onto zigware's own io_uring rings
    (`src/runtime/production/ring.zig`, commonware's `iouring-storage` and `iouring-network`).
  The runtime lane owns the exact interface and documents it in `src/runtime/root.zig`.
- **Actors and bounded mailboxes.** Long-lived components are actors that own their state
  and talk through bounded mailboxes (`actor`), as in commonware.
- **Simulated networks for protocols.** p2p ships `simulated` (in the deterministic
  runtime: links with latency, jitter, drops, partitions) and `authenticated` (real TCP with
  the `stream` encrypted handshake). Broadcast, resolver, and consensus are tested on the
  simulated network with many nodes and Byzantine actors, like commonware's tests.
- **Generics are comptime.** Rust traits become comptime interfaces (a type parameter
  checked with `comptime` assertions) or small vtables where dynamic dispatch is needed.
  Proc macros become comptime functions.
