# TigerStyle in zigware

Our coding style, in our own words, after the TigerBeetle approach. Design goals in
order: **safety, performance, developer experience**.

## Safety

- **Assertions everywhere.** Assert arguments, return values, and invariants. Pair
  assertions: check data before writing it and after reading it. Assert what must
  never happen as well as what must. A crashed node is better than a corrupted one.
- **Compile-time assertions** for struct sizes, alignment, and constant relationships.
- **Bounded everything.** Every loop has a known maximum iteration count; every queue
  and buffer has a fixed capacity set from config at startup. Hitting a bound is an
  explicit, handled condition.
- **No recursion.** Use explicit, bounded stacks (tree walks, decoders, graph searches).
- **Bounded memory.** Allocate at init where the design allows; hot paths do not
  allocate. Pass allocators explicitly; prefer fixed pools and ring buffers.
- **Simple control flow.** Keep branching shallow; push `if`s up and `for`s down.
  Handle every error. No hidden allocation, no hidden I/O.
- **Smallest scope** for variables. Compute values right before use.
- **Explicit types.** Use sized integers (`u64`, `u32`). Avoid `usize` except
  for indexing and lengths of in-memory slices.
- **Function size ≤ 70 lines**, line length ≤ 100 columns.

## Performance

- Think about performance at design time with back-of-envelope numbers for network,
  disk, memory, and CPU — in that order of cost.
- Batch work. Amortize syscalls (io_uring submission batching), cache misses, and
  hashing. Avoid copies; parse in place.
- Separate control plane from data plane. Hot loops are branch-light and
  allocation-free. Use SIMD (`@Vector`) where it clearly wins.
- Claim a speedup only with numbers from a benchmark that is committed and reproducible.

## Determinism and testing

- All I/O (network, disk, time, randomness, task spawning) flows through the runtime
  (`runtime.Context` and the `std.Io` it carries) so the deterministic runtime can replace
  it. Library code never touches the OS directly.
- Components are actors: tasks that own their state and talk over bounded mailboxes.
- The deterministic runtime runs real component code on simulated network, disk, and time
  with fault injection (latency, reorder, drop, partition, crash, restart, disk faults).
  Every run reproduces from its seed.
- Every decoder, parser, and state transition is fuzzed.
- Zig 0.17.1's debug backend (the self-hosted x86_64 one `zig build test` uses) miscompiles
  `==`/`!=` between two runtime optional error sets (`?anyerror`, `?SomeError`): two nulls
  or two equal errors can compare unequal, depending on stale stack bytes. Unwrap first and
  compare the plain errors. Null checks and other optional types are fine; LLVM builds are
  correct.

## Naming and docs

- `snake_case` functions and variables, `PascalCase` types, `SCREAMING` never.
- Units and qualifiers last, most significant first: `latency_ms_max`.
- No abbreviations except well-known protocol terms (`rlp`, `evm`, `rpc`, `tx`).
- Comments explain *why*. Every file starts with a `//!` doc comment.
