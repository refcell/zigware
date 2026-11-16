# Lanes

Work is split into lanes. Each lane is owned by one autonomous agent session working in its
own clone and owns the directories listed in its file. A lane file is the lane's living
backlog and log: the owning agent keeps its checklist current, records decisions, and
appends a short dated log line after each push. Other lanes read it to find interfaces.

| Lane | File | Owns | Wave |
| --- | --- | --- | --- |
| codec | codec.md | `src/{formatting,conformance,invariants,codec}` (done) | 1 |
| utils | utils.md | `src/utils` | 1 |
| parallel | parallel.md | `src/{parallel,allocator,bench}` | 2 |
| crypto | crypto.md | `src/cryptography` except `bls12381/`, `reed_solomon/`, `curve25519/` | 1 |
| bls-math | bls-math.md | `src/{math,simd}`, `src/cryptography/bls12381` | 1 |
| runtime | runtime.md | `src/runtime` except `buffer/`, `telemetry/`, `production/` | 1 |
| clearing | clearing.md | `src/clearing` | 3 |
| storage-qmdb | storage-qmdb.md | `src/storage/qmdb` | 3 |
| storage-qmdb-sync | storage-qmdb-sync.md | `src/storage/qmdb/{current,sync,compact}` | 3 |
| storage-merkle | storage-merkle.md | `src/storage/{merkle,bitmap,index,rmap}`, `src/storage/translator.zig`, `src/storage/root.zig` | 1 |
| actor-stream | actor-stream.md | `src/{actor,stream}` (done) | 2 |
| storage-journal | storage-journal.md | `src/storage/{journal,metadata,queue}`, `src/runtime/buffer` | 2 |
| coding | coding.md | `src/coding`, `src/storage/bmt`, `src/cryptography/reed_solomon` (done; benches wait on bench) | 2 |
| p2p | p2p.md | `src/p2p` | 2 |
| storage-archive | storage-archive.md | `src/storage/{archive,freezer,ordinal,cache}` | 3 |
| runtime-telemetry | runtime-telemetry.md | `src/runtime/telemetry`, `src/runtime/production` | 3 |
| broadcast-resolver | broadcast-resolver.md | `src/resolver` | 3 |
| broadcast-collector | broadcast-collector.md | `src/{broadcast,collector}` | 3 |
| examples-estimator | examples-estimator.md | `examples/estimator` | 3 |
| consensus-marshal | consensus-marshal.md | `src/consensus/{aggregation,marshal}` | 3 |
| consensus-simplex | consensus-simplex.md | `src/consensus` except `marshal/`, `aggregation/` | 3 |
| deployer | deployer.md | `src/deployer` | 3 |
| curve25519 | curve25519.md | `src/cryptography/curve25519` | 3 |

Later waves start as their dependencies land; [../ROADMAP.md](../ROADMAP.md) lists them.

## Lane protocol

1. Read `AGENTS.md`, `docs/TIGER_STYLE.md`, `docs/ARCHITECTURE.md`, and your lane file.
2. Take the first unchecked item. Study the matching code and tests in
   `~/.cache/zigware/commonware-ref/<crate>`. Port it with its tests, vectors, and a fuzz test.
3. `zig build test && just tidy`, then `git fetch origin main && git rebase origin/main` and
   `git push origin HEAD:main`.
4. Tick the item, add a log line, push. Repeat. When the backlog is empty, extend it with
   the next most valuable piece of the crate until the whole crate is ported.
