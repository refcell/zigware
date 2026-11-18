# Lane: examples-dkg

Owner: the broadcast-resolver thread. Owns `examples/dkg` (commonware `examples/dkg`).

## Backlog

- [x] `config.zig`: `node.json` and `network.json`, written exactly as `serde_json::to_string_pretty`
      writes them; Rust `SocketAddr` text form.
- [x] `types.zig`: constants, `Block` (codec, digest, `ReshareBlock`), committee rotation
      (`Participants`, a glue `ParticipantsProvider`), `Secrets` (a glue `SecretStore` over
      `storage.metadata`), and `genesis.json`.
- [x] `setup.zig` and the `setup` subcommand.
- [ ] `application.zig`, `bootstrap.zig`, `validator.zig` on glue.dkg's actor, bootstrap,
      probe, and orchestrator (coding lane, in progress).
- [ ] Demo recording (`just` recipe `dkg`, etc/scripts/record-demo.sh).

## Decisions

- Vectors in `testdata/` come from a scratch Rust test run against commonware's own types
  (block and genesis encodings and digests, `node.json`, `network.json`, `genesis.json`).
- `setup`'s printed commands run `zig build run-dkg -- ...` where commonware's run
  `cargo run --bin commonware-dkg -- ...`.
- Test names start with `dkg: ` so `-Dtest-filter="dkg: "` runs exactly this example.
- `Secrets` is shared by pointer (commonware clones an `Arc`); a failed write drops the store
  and later calls fail with `error.SecretsFailed` (commonware panics on next use).

## Log

- 2026-11-18: config, types, and setup with commonware's tests and vectors.
