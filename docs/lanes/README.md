# Lanes

Work is split into lanes. Each lane is owned by one autonomous agent session working in its
own clone and owns the directories listed in its file. A lane file is the lane's living
backlog and log: the owning agent keeps its checklist current, records decisions, and
appends a short dated log line after each push. Other lanes read it to find interfaces.

| Lane | File | Owns | Wave |
| --- | --- | --- | --- |
| codec | codec.md | `src/{formatting,conformance,invariants,codec}` | 1 |
| utils | utils.md | `src/{utils,parallel,allocator,bench}` | 1 |
| crypto | crypto.md | `src/cryptography` except `bls12381/` | 1 |
| bls-math | bls-math.md | `src/{math,simd}`, `src/cryptography/bls12381` | 1 |
| runtime | runtime.md | `src/runtime` | 1 |
| storage-merkle | storage-merkle.md | `src/storage/{merkle,bmt,bitmap,index,rmap}`, `src/storage/translator.zig`, `src/storage/root.zig` | 1 |

Later waves start as their dependencies land; [../ROADMAP.md](../ROADMAP.md) lists them.

## Lane protocol

1. Read `AGENTS.md`, `docs/TIGER_STYLE.md`, `docs/ARCHITECTURE.md`, and your lane file.
2. Take the first unchecked item. Study the matching code and tests in
   `~/.cache/zigware/commonware-ref/<crate>`. Port it with its tests, vectors, and a fuzz test.
3. `zig build test && just tidy`, then `git fetch origin main && git rebase origin/main` and
   `git push origin HEAD:main`.
4. Tick the item, add a log line, push. Repeat. When the backlog is empty, extend it with
   the next most valuable piece of the crate until the whole crate is ported.
