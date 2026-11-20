# zigware

[![Zig](https://img.shields.io/badge/Zig-0.17.1-F7A41D?style=for-the-badge&logo=zig&logoColor=white)](#installation)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)](#installation)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=for-the-badge)](#design)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)

zigware is the [Commonware Library](https://github.com/commonwarexyz/monorepo) rewritten from
scratch in Zig: codec, cryptography, a deterministic runtime, storage, authenticated p2p,
broadcast, and BFT consensus, with zero dependencies.

It is a ground-up port of the public commonware monorepo and keeps its layout: every crate
there is a package here with the same name and the same dependency graph, and wire formats
are byte-identical so the two can interoperate.

<p align="center">
  <img src="docs/assets/dkg-demo.gif" width="800"
    alt="Validators reshare a threshold BLS12-381 key at every epoch boundary while a fifth joins with state sync">
</p>

[dkg](examples/dkg) follows commonware's flow: `dkg setup` writes configs for five peers
with a committee of four, the epoch-zero players run `bootstrap` to complete a one-shot DKG
and write the genesis, then four `validator`s run Simplex over marshal and a QMDB-backed
stateful application. At every epoch boundary the committee reshares its threshold key on
chain: each pane shows dealings and acks arriving, dealer logs observed on chain,
`completed reshare ceremony ... success=true`, and the orchestrator entering the next epoch
with the new key. After the first reshare, the bottom pane starts a fifth validator with
`--state-sync`: its first block is a peer's floor rather than genesis, and it enters the
current epoch and reshares in step with the rest ([video](docs/assets/dkg-demo.mp4?raw=true)).
`etc/scripts/record-demo.sh dkg` records it again.

<p align="center">
  <img src="docs/assets/interop-dkg-demo.gif" width="800"
    alt="Three commonware and three zigware validators run one dkg network through reshares">
</p>

The same network runs with both implementations at once. One `commonware-dkg setup` writes
the configs, commonware's players 0 and 1 and zigware's players 2 and 3 complete the
epoch-zero DKG together, and all six genesis files come out identical. Then commonware's
validators 0, 1 and 4 and zigware's validators 2 and 3 run Simplex, marshal, and the
stateful application together, and zigware's validator 5 joins with `--state-sync`. Every
pane shows the same digest at each height through every epoch's reshare
([video](docs/assets/interop-dkg-demo.mp4?raw=true)). `etc/scripts/interop.sh` runs this check, and
`etc/scripts/record-demo.sh interop-dkg` records it again.

<p align="center">
  <img src="docs/assets/interop-log-demo.gif" width="800"
    alt="Two commonware Rust validators and two zigware validators finalize the same blocks">
</p>

zigware and commonware run one network together. Here commonware's Rust [log](examples/log)
validators 0 and 1 and zigware's validators 2 and 3 form one Simplex committee: each
implementation proposes about half the views, and all four finalize every view with the same
digest. A zigware validator that is stopped and restarted on its storage rejoins and finalizes
later views with the same digests ([video](docs/assets/interop-log-demo.mp4?raw=true)).
`etc/scripts/interop.sh` runs this check, after a chat session between the two
implementations, and `etc/scripts/record-demo.sh interop-log` records it again.

<p align="center">
  <img src="docs/assets/bridge-demo.gif" width="800"
    alt="Two consensus networks finalize each other's certificates through a shared indexer">
</p>

[bridge](examples/bridge) runs two independent networks of four validators, each with a
threshold BLS12-381 key dealt by `bridge-dealer`, plus an indexer they share. Each network
runs Simplex and proposes either random data or the other network's latest finalization,
which its validators verify against the other network's public identity before voting. The
top pane is the indexer storing blocks and finalizations from both networks; the bottom panes
are one validator from each network, where `block=Bridge(..)` marks a proposal carrying the
other network's finalization ([video](docs/assets/bridge-demo.mp4?raw=true)).
`etc/scripts/record-demo.sh bridge` records it again.
<p align="center">
  <img src="docs/assets/interop-bridge-demo.gif" width="800"
    alt="Mixed commonware and zigware validators on two networks bridge each other's certificates">
</p>

The same bridge runs with both implementations mixed. Each network has two commonware and two
zigware validators from one shared dealing (commonware's `dealer` and zigware's `bridge-dealer`
print identical shares), with commonware's indexer between them. Validators of both kinds
finalize the same payloads and propose Bridge blocks carrying the other network's certificate,
which voters of the other implementation verify
([video](docs/assets/interop-bridge-demo.mp4?raw=true)). The nightly interop check runs this
with each indexer, and `etc/scripts/record-demo.sh interop-bridge` records it again.

The other examples have their own READMEs and recordings: [chat](examples/chat), an
encrypted group chat over authenticated p2p, including a session with commonware's Rust chat;
[log](examples/log), four Simplex validators over TCP; [flood](examples/flood), p2p load; and
[estimator](examples/estimator), simulated consensus latency across AWS regions.

> [!NOTE]
> zigware has not been audited and has no tagged releases. Most of commonware's primitives
> are ALPHA or BETA upstream, and each package's README gives its stability.

## Packages

Each package's README gives its upstream stability, its modules, how to test, bench, and fuzz
it, and every recorded difference from commonware.

| Package | What it does | Status |
| --- | --- | --- |
| [codec](src/codec) | Serialize structured data | ported |
| [cryptography](src/cryptography) | Keys, signatures, hashes, BLS12-381 threshold crypto | ported |
| [curve25519](src/cryptography/curve25519) | Curve25519 arithmetic, Ed25519 signing and batch verification, X25519 | ported |
| [math](src/math) | Fields, polynomials, NTT | ported |
| [runtime](src/runtime) | Async tasks on a deterministic scheduler or std.Io (optional io_uring) | ported |
| [storage](src/storage) | Journals, archives, MMRs, authenticated databases | ported |
| [utils](src/utils) | Shared functionality across primitives | ported |
| [parallel](src/parallel) | Parallel folds with pluggable strategies | ported |
| [actor](src/actor) | Coordinate concurrent components | ported |
| [stream](src/stream) | Encrypted messages over any transport | ported |
| [p2p](src/p2p) | Communicate with authenticated peers | ported |
| [broadcast](src/broadcast) | Disseminate data over a wide-area network | ported |
| [resolver](src/resolver) | Resolve data by a fixed-length key | ported |
| [collector](src/collector) | Collect responses to committable requests | ported |
| [coding](src/coding) | Erasure-code data for recovery from fragments | ported |
| [clearing](src/clearing) | Settle actions at scale | ported |
| [consensus](src/consensus) | Order messages in a Byzantine environment (simplex, aggregation, marshal) | ported |
| [glue](src/glue) | Default constructions spanning several primitives | ported |
| [deployer](src/deployer) | Deploy infrastructure across cloud providers | ported |

Support packages: [formatting](src/formatting), [conformance](src/conformance),
[invariants](src/invariants), [simd](src/simd), [allocator](src/allocator),
[bench](src/bench). [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) maps every commonware crate
to its package and lists the dependency order.

## Performance

Twelve of commonware's criterion benchmarks, run against the zigware benchmark of the same
name and parameters on the same machine ([docs/BENCHMARKS.md](docs/BENCHMARKS.md) has the
setup, the commands, and the caveats). Below 1× means zigware is faster. commonware is built
with `target-cpu=native`, rounds run in ABBA order, and a row is "faster" only when the median
of the per-round ratios is below 0.95 with at most n/8 rounds at or above 1.

| bench | zigware / commonware |
| --- | --- |
| `codec::lazy::get` (100k shared) | 0.17× faster |
| `journal::append_sync` (fixed) / `fixed_append` (10k) / `fixed_replay` (100k) | 0.09× / 0.26× / 0.76×, all faster |
| `buffer_paged::append` (4 KiB) | 0.46× faster |
| `bls12381::aggregate_verify_same_message` (1000 keys) / single verify | 1.04× tie / 0.89× faster |
| `sha256::hash_message` (4 KiB / 1 MiB) | 0.99× / 1.00×, both tie |
| `ed25519::signature_verification` / `batch_verify_same_message` (100 keys) | 0.86× / 0.94×, both faster |
| `qmdb::apply_batch` (16384 updates) | 1.09× tie |

End to end, four local [flood](examples/flood) peers over authenticated p2p at
262144 msg/s each, both built for the native CPU: zigware receives 768–774k msg/s per peer
at 8–10 ms mean latency, commonware 391–422k at 117–120 ms (1.87×, ahead in all 5 alternating
rounds). Below saturation both hit the rate cap, and zigware's
latency is lower at every rate ([details](docs/BENCHMARKS.md#end-to-end-flood-4-peers-2026-11-19-p2p-lane)).

<p align="center">
  <img src="docs/assets/flood-262144-demo.gif" width="800"
    alt="Four local zigware flood peers at 262144 msg/s, each receiving about 600k msg/s">
</p>

Four local zigware flood peers at 262144 msg/s with 1024-byte messages, each receiving about
600k msg/s on a busy desktop ([video](docs/assets/flood-262144-demo.mp4?raw=true)).
`etc/scripts/record-demo.sh flood-262144` records it again.

These were measured on a busy desktop with storage on tmpfs, so ratios near 1 are noise and
the storage numbers measure code, not the disk. ed25519 single verify uses an AVX-512 IFMA
backend where the CPU has one; batch verify uses IFMA, then AVX2 (0.76×), then a scalar
path. The BLS rows wait on a quiet re-run.

## Design

- **Zero dependencies.** Only the Zig standard library: no C libraries, no vendored code,
  `build.zig.zon` has an empty `.dependencies`. BLS12-381, Reed-Solomon, the ed25519 verify
  and MSM paths, the runtime, and the storage engines are implemented here; the hashes,
  X25519, secp256r1, and ed25519's field arithmetic come from `std.crypto`.
- **Same wire formats.** Encodings, storage layouts, and network messages match
  commonware's byte for byte, checked against commonware's own test vectors and
  conformance hashes.
- **Deterministic simulation testing.** All time, randomness, tasks, network, and storage go
  through the runtime. The deterministic runtime runs real protocol code on a simulated
  network with fault injection, and any run replays exactly from its seed.
- **TigerStyle.** Assertions on every precondition, postcondition, and invariant; every
  loop, queue, and mailbox bounded; no recursion; functions ≤ 70 lines. See
  [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md).
- **Fuzzed.** Every decoder, parser, and state machine has a coverage-guided fuzz target
  and a seeded fuzz run that executes with the normal test suite.
- **Production runtime.** Production I/O runs on `std.Io.Threaded`; on Linux, blob and
  socket I/O can move onto an io_uring ring (`Config.io_uring`).

## Upstream bugs

Porting commonware and running it side by side with zigware has turned up one real bug so
far. In the flood example, the sender loop never yields when a send is refused, so it spins on
its tokio worker, the network tasks it woke never run, and peers receive nothing; one
`reschedule` fixes it, and it is filed as
[commonware#5809](https://github.com/commonwarexyz/monorepo/issues/5809). Two smaller,
unfiled items sit alongside it: flood binds every peer to `0.0.0.0`, so several peers cannot
share one machine, and bulletproofs' IPA verifier can panic instead of rejecting a claim
longer than its setup. [docs/UPSTREAM_BUGS.md](docs/UPSTREAM_BUGS.md) has the evidence and
repro steps.

## Optimizations commonware could adopt

A few of zigware's speedups over commonware built for the native CPU come from changes that
would carry over. ed25519 verification splits its scalar with Lehmer's algorithm instead of a
bit-at-a-time Euclid, BLS12-381 runs its field arithmetic eight elements at a time on AVX-512
IFMA lanes and clears the cofactor once per batch of messages, short SHA-256 batches hash in
interleaved SHA-NI pairs, and short BLAKE3 messages take a single root compression. In
storage, a compressed journal batch can be reserved once instead of growing, and much of
the gap looks like blob I/O issued inline rather than on a blocking thread pool.
[docs/UPSTREAM_OPTIMIZATIONS.md](docs/UPSTREAM_OPTIMIZATIONS.md) has the bench rows,
verdicts, and commits, and separates these from wins whose cause is not yet known.

## Installation

```sh
git clone https://github.com/refcell/zigware && cd zigware
just release
```

`just release` needs [`just`](https://github.com/casey/just) and `curl`. It uses Zig 0.17.1
from `PATH`, or downloads it into `.cache/zig`, and writes optimized binaries to
`zig-out/bin`. zigware has no other build dependency. There are no tagged releases; build
from `main`.

Use a package from your own `build.zig` through the `zigware` module, or one package by
name (`b.dependency("zigware", .{}).module("codec")`).

## Contributing

`just` lists every development recipe. `zig build test` runs every package's tests and
`zig build test-<package>` runs one. Contributor rules are in [AGENTS.md](AGENTS.md); the
port's work split is in [docs/lanes](docs/lanes/README.md) and
[docs/ROADMAP.md](docs/ROADMAP.md).

## License

[MIT](LICENSE). zigware is a port of the Commonware Library, which is dual-licensed under
MIT and Apache 2.0.
