# AGENTS.md — zigware

zigware is a from-scratch Zig rewrite of the public
[commonwarexyz/monorepo](https://github.com/commonwarexyz/monorepo) (the Commonware Library:
codec, cryptography, runtime, storage, p2p, broadcast, consensus, and their examples).
Zero dependencies, TigerStyle, deterministic simulation testing (DST), heavy fuzzing,
io_uring, and extreme performance.

Read this whole file before you change anything. These rules are not optional.

## Hard rules

1. **Push straight to `main`.** No branches on the remote, no pull requests. Publish with:
   ```sh
   git fetch origin main && git rebase origin/main
   zig build test && just tidy        # must pass
   git push origin HEAD:main
   ```
   If the push is rejected, fetch and rebase, then run only `zig build check` and your own
   packages' tests (`zig build test-<package>`) before pushing again: the full suite already
   passed on a nearly identical base, and CI runs it on every push. Run the full suite again
   only if the rebase brought in changes to a package yours depends on, or one that depends on
   yours. Push small commits often: every coherent, green step (at least every hour of work).
   Never force-push `main`.
   Stop processes only through your own tool's PIDs (`shell_command_kill`). Never `kill` a
   parent PID, a reparented process, or anything you did not start: lanes share one desktop.
2. **Public content only.** Only port what is in the public commonware monorepo (reference
   clone: `~/.cache/zigware/commonware-ref`, refresh with
   `git -C ~/.cache/zigware/commonware-ref pull`), public papers and RFCs, and public test
   vectors. Never commit anything from private systems or repositories.
3. **No secrets, no personal data.** Never commit private keys, tokens, `.env` files, API
   keys, home directory paths, usernames, or email addresses. `just tidy` scans for these;
   it is a backstop, not a license.
4. **Zero dependencies.** `build.zig.zon` `.dependencies` stays empty. Only the Zig
   standard library. No C libraries, no linking libc unless a syscall needs it. Implement it
   yourself. `std.crypto` may be used where it is correct and fast enough.
5. **Zig 0.17.1 exactly.** APIs changed a lot (`std.Io`, `std.process.Init`, new
   `std.Io.Writer`/`Reader`, unmanaged `ArrayList`). When unsure, read the std source in
   `$(zig env | grep lib_dir)`; do not guess from older Zig versions. A pinned toolchain is at
   `~/.cache/zigware/zig` (`export PATH=$HOME/.cache/zigware/zig:$PATH`); `just release`
   downloads one into `.cache/zig` otherwise.
6. **Main stays green.** `zig build test` and `just tidy` must pass before every push. If
   main is broken by someone else, fixing it is your top priority (smallest fix).
7. **Never stop, never block.** You are autonomous. When a decision is ambiguous, pick the
   option closest to commonware's behavior and TigerStyle, write the decision in your lane
   file, and continue. If a task is too big, split it and do the first piece. If blocked on
   another lane, build the minimal piece you need behind an interface in your own lane and
   keep going, then switch to the real one when it lands.
8. **Own your lane.** Each lane owns the directories listed in `docs/lanes/<lane>.md`. Edit
   other lanes' files only for tiny integration fixes (a build break, a missing `pub`).
   Shared files (`build.zig`, `src/zigware.zig`, `Justfile`, `README.md`) take small,
   additive edits; resolve rebase conflicts by keeping both sides.
9. **Same packages, same graph.** One commonware crate is one package at
   `src/<crate>/root.zig`. A package may import only the packages listed for it in
   `build.zig`, which mirrors the crate's `Cargo.toml`. Wire formats (codec encodings,
   storage layouts, network messages, signatures, hashes) must be byte-identical to
   commonware's so the two can interoperate; check with commonware's own test vectors and
   conformance hashes.

## Style: TigerStyle (see docs/TIGER_STYLE.md)

- Safety, then performance, then developer experience.
- Assert preconditions, postconditions, invariants. Aim for ≥ 2 asserts per function.
  Assert both the positive and negative space. Use `comptime` asserts for sizes/layout.
- Bounded everything: every queue, buffer, mailbox, and loop has an explicit upper bound.
  Pass allocators explicitly; allocate at init where the design allows and keep hot paths
  allocation-free.
- No recursion (bounded iteration with explicit stacks instead).
- Functions ≤ 70 lines. Lines ≤ 100 columns. `zig fmt` always.
- Explicitly-sized integer types (`u64`, `u32`), not `usize`, except for indexing.
- Names: `snake_case` functions/vars, `PascalCase` types, units last (`timeout_ms`,
  `size_bytes`). No abbreviations beyond well-known terms.
- Errors are handled, never ignored. `catch unreachable` only with a proof comment.
- Library code never touches the OS directly: time, randomness, tasks, network, and
  storage come from the runtime (`runtime.Context` / `std.Io`), so the deterministic
  runtime can replace them. See docs/ARCHITECTURE.md.

## Testing

- `zig build test` runs every package; `zig build test-<package>` runs one;
  `-Dtest-filter=...` narrows.
- **Port the tests.** Every commonware test that checks behavior gets a Zig counterpart,
  including fixed test vectors and conformance hashes, so the port is checked against the
  original.
- **Fuzz**: every decoder, parser, and state machine gets a `std.testing.fuzz` test and a
  deterministic seeded fuzz that runs in the normal `zig build test` (iterations scale with
  `build_options.fuzz_soak`, seed mixes in `build_options.fuzz_seed`).
  Long fuzz: `zig build test --fuzz -Doptimize=ReleaseSafe`.
- **DST**: protocols (p2p, broadcast, resolver, consensus) are tested the way commonware
  tests them: many nodes in one deterministic runtime with a simulated network, fault
  injection (latency, drops, partitions, crashes, Byzantine actors), and a seed that replays
  the run exactly. A failing seed is a bug report.
- Linux io_uring tests: `just test-linux` runs the suite in a Docker Linux container.

## Zig 0.17.1 pitfalls

- `std.Io.Threaded`'s `Future.create` ignores the result's alignment. `io.concurrent` on a
  function whose result is 16-byte aligned (anything holding an `Io.Duration` or
  `Io.Clock.Timestamp`, which are i96) overruns the future by up to 8 bytes and corrupts the
  heap. Keep such fields as `u64` nanoseconds in values returned from concurrent tasks.
- `std.Io.Uring` does not compile; `runtime.production.Runner` runs on `std.Io.Threaded`.
  `Threaded` panics on connect with a timeout and its poll timeouts can fire up to 1 ms
  early; `runtime.production.network` works around both (docs/lanes/runtime-telemetry.md).

## Layout (mirrors commonware, Zig conventions)

```
src/<crate>/root.zig       one package per commonware crate (codec, cryptography, runtime, ...)
src/<crate>/<module>/      sub-modules mirror the crate's src/<module>
src/zigware.zig            the `zigware` module: every package re-exported
examples/<name>/main.zig   commonware's examples (log, chat, dkg, bridge, estimator, flood)
docs/                      architecture, style, lanes, roadmap
docs/assets/               README demo recordings
etc/                       scripts, CI helpers
```

Inside a package, files import each other by relative path; other packages by name,
`@import("codec")`.

## Commits

- Conventional, imperative subject: `feat(codec): add varint encoding`.
- Small and frequent. Never commit `zig-out/`, `.zig-cache/`, `.cache/`, `.claude/`.
- Commits are GPG-signed (global git config already does this; never bypass hooks).
