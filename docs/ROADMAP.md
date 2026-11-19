# Roadmap

zigware ports the whole Commonware Library. Lanes run in parallel, each in its own clone,
and started when what they build on had landed (or could be stubbed behind an interface).

| Wave | Lane | Owns | Status (lane file, 2026-11-19) |
| --- | --- | --- | --- |
| 1 | codec | formatting, conformance, invariants, codec | done |
| 1 | utils | utils | done |
| 1 | crypto | cryptography (hashes, ed25519, secp256r1, certificate, handshake, zk, ...) | done |
| 1 | bls-math | math, simd, cryptography/bls12381 (primitives, dkg, tle, certificate) | done |
| 1 | runtime | runtime: interface, deterministic runtime, iobuf, storage, network | done |
| 1 | storage-merkle | storage: merkle (mmr, mmb), bitmap, index, rmap, translator | done (byte-exact zstd level 3 included) |
| 2 | parallel | parallel, allocator, bench, p2p/authenticated/lookup | done |
| 2 | actor-stream | actor, stream | done |
| 2 | storage-journal | storage: journal, metadata, queue; runtime/buffer | done |
| 2 | storage-archive | storage: archive, freezer, ordinal, cache | done |
| 2 | p2p | p2p: simulated, authenticated | done; test audit 463 ported, 0 open, 13 not portable |
| 2 | coding | coding, storage/bmt, cryptography/reed_solomon | done |
| 3 | broadcast-resolver | resolver | done |
| 3 | broadcast-collector | broadcast, collector, consensus/marshal/coding | done |
| 3 | runtime-telemetry | runtime/telemetry, runtime/production (incl. io_uring) | done |
| 3 | examples-estimator | examples: estimator, flood, chat, log, bridge, ui | done |
| 3 | clearing | clearing | done |
| 3 | storage-qmdb | storage: qmdb shared modules, keyless, immutable, any, store | done |
| 3 | storage-qmdb-sync | storage: qmdb current, sync, compact | done (reshare harness phase 2 landed; lane box to tick) |
| 3 | consensus-simplex | consensus: types, simplex | done |
| 3 | consensus-marshal | consensus: aggregation, marshal | done (marshal tally: 193/197 standard with 4 not portable, 101/101 coding) |
| 3 | deployer | deployer | done |
| 3 | curve25519 | cryptography/curve25519 | done |
| 4 | glue | glue: simulate, transfers, stateful, dkg | in progress (stateful: stable leaders; simulate and dkg done) |
| 4 | examples-dkg | examples/dkg | done |

Status is the lane file's backlog: "done" means every backlog item is ticked. Each lane file
(`docs/lanes/<lane>.md`) has the details, and its test audit where one exists.

Demo recordings for the README come from the examples as they become runnable.
