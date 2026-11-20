# Lane: examples-estimator

Owns `examples/estimator/`, `examples/flood/`, `examples/chat/`, `examples/log/`,
`examples/bridge/`, `examples/ui/` (the terminal UI, clap, and Rust-parsing support the
examples share, the `ui` module in `build.zig`), their entries in
`build.zig`'s `examples` list, and their recipes in `etc/scripts/record-demo.sh`. The estimator is
zigware's first runnable example and the first README demo.

Reference: `~/.cache/zigware/commonware-ref/examples/estimator` (lib.rs, main.rs, p50/p90
latency JSON, the `.lazy` task files). It simulates a mechanism described in the `.lazy`
DSL (propose, broadcast, reply, wait/collect thresholds, AND/OR) on peers spread across AWS
regions with real region-to-region latencies, in virtual time on the deterministic runtime,
and prints latency statistics. It needs p2p's `simulated` network (`Oracle`, links with
latency and jitter, `Recipients`); the p2p lane is landing it now. Until then, build
everything that does not need it (DSL parser, region/latency tables, distribution parsing,
statistics, output, CLI) and run against a minimal in-lane stand-in, then switch.

## Decisions
- `rust.zig` reproduces the Rust std behavior the output depends on: `{:.2}` (exact decimal,
  ties to even; Zig's `{d:.2}` differs on values like 0.125), `Duration::from_secs_f64`,
  `str::lines`, and `parse::<f64/u32>` with their error kinds.
- Commands are stored in postfix order and parsed with an explicit operator stack (no
  recursion). Leaves are evaluated left to right, as commonware's recursive evaluation does.
- Where commonware panics, the estimator prints `error: <commonware's panic message>` and
  exits 101. clap's help, version, and usage errors are reproduced as text with exit code 2.
- Statistics agree with commonware in distribution, not sample for sample (coordinator
  decision): the scheduler consumes the RNG in a different order. `simulate_test.zig` checks
  means and medians against a captured commonware run, with tolerances.
- `--version` prints the build's `version` option (`0.0.0` today), not commonware's crate
  version.
- `--reload` downloads through `std.http.Client` on the process's `std.Io` in `main`, before
  any simulation; it is the estimator's only real network access.
- flood reads YAML with an in-lane subset parser (`examples/flood/yaml.zig`) because no
  serde_yaml exists in zigware; it rejects anything outside what serde_yaml writes for flood's
  config and the deployer's hosts file.
- flood binds `0.0.0.0` for p2p and metrics as commonware does, except that a peer whose host
  IP is loopback binds that IP. Peers on one machine then share flood's fixed ports on
  127.0.0.1, 127.0.0.2, ... (`examples/flood/local.sh` writes such a deployment and
  `demo.sh` runs it). Logs are tracing-subscriber's JSON lines on stdout, written by
  `lib.write_json_event`.
- flood `setup` embeds commonware's `dashboard.json` (shipped in `examples/flood`) and writes
  it when `--dashboard dashboard.json` is missing from the working directory, so the README's
  command runs from the repository root as well as from `examples/flood`. Any other missing
  dashboard fails as commonware's `unwrap` does.
- bridge accepts the configurations commonware accepts (rule 7). A validator whose
  `--other-public` is its own network's key bridges its own finalizations, which verify
  (c111d676 dropped zigware's startup assert). The indexer serves a network listed twice in
  `--networks` once, as commonware's `HashMap` keeps one entry. It serves at most
  `store.networks_max` (16) networks and says so at startup beyond that; commonware has no
  bound.
- flood's `messages` counter also counts sends made before any peer connects, as
  commonware's does (an empty `Recipients::All` send is accepted); the demo shows received
  messages instead.
- chat's TUI reimplements the slice of ratatui 0.30.2 and crossterm 0.29 it draws with
  (`tui.zig`, `keys.zig`): percentage layouts, bordered titled blocks, scrolled truncated
  paragraphs, the buffer diff, and crossterm's key parser. Frames are checked cell by cell
  against ratatui's TestBackend (`testdata/ratatui_screens.txt`). Graphemes are a base plus
  extending characters, from tables generated out of unicode-width 0.2.2 and
  unicode-segmentation 1.13.3; Hangul jamo and Prepend clusters split differently.
- chat logs through a `traces.Collector` instead of a tracing subscriber; `logger.zig` prints
  each event as commonware's logger.rs prints tracing's JSON. Field values are text in the
  collector, so a value prints bare when it reads as a JSON number or boolean. Message stamps
  use the local zone from `$TZ` or `/etc/localtime` (TZif plus its POSIX footer), as chrono's
  `Local` does.
- commonware's chat README points at a `p2p_connections` gauge that commonware removed
  (#3324); the Metrics pane shows `network_tracker_directory_connected` samples, one per
  connected friend, instead.
- chat runs under `runner.start_context`, so `network` and `handler_keyboard` show in
  `runtime_tasks_spawned` and `runtime_tasks_running` as in commonware. p2p's own tasks
  (`network_dialer` and the like) do not: discovery's `Net` starts them on a bare `Io`.
- chat's release builds allocate from `allocator.Heap`; Debug and ReleaseSafe keep `init.gpa`
  for its leak check. commonware's chat uses the system allocator. Under `smp_allocator` a
  peer's RSS grew without bound (2.2 MB/min at 5 lines/s each way, mostly on the listening
  peer) while its live heap stayed flat: payloads are allocated on the peer's receive thread
  and freed on the handler's, and `smp_allocator` keeps those slots. On `Heap` the same
  traffic grows 0.5 to 0.9 MB/min, the messages and log lines chat keeps as commonware does.

- log's Logs pane shows p2p's and simplex's events at debug and above (gui.rs's
  `with_max_level(DEBUG)`), through the runner's subscriber.
- log's application events are strings in tracing (`%view`, `?payload`, `hex(..)`), so its
  Activity lines quote every value (`view="7"`), as gui.rs prints them.

## Backlog
- [x] `.lazy` DSL parser and task model, with lib.rs's parser tests. Copy the `.lazy` files and
  p50/p90 latency data into `examples/estimator/` (they are public data in the repo).
- [x] CLI (`<TASK> --distribution region:count[:bandwidth],... --reload-latencies` etc. as in
  main.rs), statistics (mean, median, std dev per proposer and averaged), output format
  matching commonware's.
- [x] Simulation on `runtime.deterministic.Runner` and `p2p.simulated`: same seed, same
  output. `zig build run-estimator -- examples/estimator/simplex.lazy --distribution ...`.
- [x] Every `.lazy` file in the reference runs; port main.rs/lib.rs tests. (Every file runs
  end to end with and without bandwidth caps; all 16 match commonware's output line for line
  with numbers masked, and stall.lazy exits 101 in both.)
- [x] A short `examples/estimator/README.md` with the commands the README demo uses.

- [x] `--reload`: fetch cloudping.co.

### flood (commonware `examples/flood`)
- [x] Config and deployer hosts files (`yaml.zig`: the subset serde_yaml 0.9 writes, with its
  quoting rules), `SmallRng` (rand 0.10 xoshiro256++, checked against Rust), and the sender and
  receiver tasks over p2p's sender/receiver interfaces, tested flooding on p2p.simulated.
- [x] Binary on `runtime.production.Runner` and p2p `authenticated::discovery`, with the
  metrics endpoint; 4 local peers flood each other over TCP.
- [x] Demo recording (`etc/scripts/record-demo.sh flood`): docs/assets/flood-demo.{gif,mp4}.
- [x] `setup` (config generation) on `deployer.aws`: ported by the deployer lane in 746eb43.

### chat (commonware `examples/chat`)
- [x] Logger and handler (TUI with plain ANSI, no deps), CLI, `peer_set_limit` test. The
  handler is tested chatting over p2p.simulated; the CLI matches clap's output for 23 cases.
- [x] Wire to `authenticated::discovery` on the production runner; 3 friends chat over TCP
  in tmux and quit cleanly on ESC.
- [x] Demo recipe and recording: docs/assets/chat-demo.{gif,mp4} (3 friends in tmux).

### log (commonware `examples/log`)
- [x] CLI (clap's text for 52 cases from `commonware-log`, and main's panics), application,
  reporter, and GUI (Activity and Logs, gui.rs's Writer lines). 4 validators running log's
  application finalize on simplex over p2p.simulated.
- [x] Binary on the production runner over discovery with `--storage-dir`; 4 local
  validators finalize over TCP, and a restarted one resumes from its journal.
- [x] Demo recipe and recording: docs/assets/log-demo.{gif,mp4} (4 validators in tmux).

### bridge (commonware `examples/bridge`)
- [x] `dealer` (`zig build run-bridge-dealer`): matches commonware's binary byte for byte for
  three dealings and 13 clap cases. Its README shows an older polynomial encoding (without the
  6-byte header the binary writes); the tests follow the binary.
- [x] Types (block, inbound, outbound) in `types.zig`, shared constants in `lib.zig`: every
  variant's encoding matches commonware's (`testdata/types_vectors.txt`, printed by commonware
  for the values its own codec tests build), plus invalid tags and a seeded fuzz of the
  decoders on mutated vectors.
- [x] The indexer's store (`store.zig`): blocks by digest and the highest verified
  finalization per network; tested with threshold-signed finalizations.
- [x] The application (`application.zig`): propose, verify, report, and posting
  finalizations, tested against the store as an in-process indexer. Propose and verify run on
  the voter's tasks and share the indexer connection under a mutex instead of commonware's
  single actor; finalizations to post go through a mailbox to `run`.
- [x] `indexer` (`zig build run-bridge-indexer`): clap output matches commonware's binary
  (`testdata/indexer_clap_cases.txt`), its panics match, and it logs through `ui.fmt`
  (tracing_subscriber's default `fmt()` format, checked against the binary's colored output).
  Interop: commonware's Rust validators on two networks of 4 finalize through it and bridge
  each other's finalizations. Field values over 128 bytes are cut by runtime's traces
  (`field_value_size_max`), so `network=` (192 hex digits) prints shortened.
- [x] `validator` (`zig build run-bridge-validator`): clap output and every argument panic
  match commonware's binary (`testdata/validator_clap_cases.txt`). Two networks of 4
  zigware validators and zigware's indexer finalize and bridge each other's finalizations
  at commonware's rate.
- [x] Demo: `examples/bridge/local.sh` runs an indexer and two networks of 4;
  `record-demo.sh bridge` records docs/assets/bridge-demo.{gif,mp4} (indexer and one
  validator per network in tmux, once both networks finalize).

### Follow-ups
- [x] Pass `.subscriber = collector.subscriber()` to the runner (runtime 1ead8cc) once p2p and
  simplex emit commonware's events; re-record the log demo (and chat's, if its logs gain
  events) so the Logs panes show them.
- [x] flood `setup` on `deployer.aws`: moved to the deployer lane.

## Log
- 2026-11-13: DSL parser, latency data, statistics, clap-identical CLI, colored output, and
  the simulation on runtime.deterministic + p2p.simulated. `zig build run-estimator` works.
- 2026-11-13: end-to-end test of every completing .lazy file, uncapped and bandwidth-capped.
- 2026-11-13: `--reload` downloads cloudping.co P50/P90 matrices.
- 2026-11-13: flood config/hosts YAML, SmallRng, sender/receiver tasks on p2p.simulated.
- 2026-11-13: chat logger, ratatui-identical TUI, crossterm key parser, clap-identical CLI,
  and the handler tested on p2p.simulated.

- 2026-11-16: flood runs on the production runner over discovery, with local.sh and demo.sh.
- 2026-11-16: chat demo recorded; shared `examples/ui` (tui, keys, clock, logger, clap).
- 2026-11-16: log ported and running on 4 local validators over discovery.
- 2026-11-16: log demo recorded; production storage now reports a canceled write as Canceled.
- 2026-11-16: bridge's dealer; build.zig builds `<name>/<binary>` entries as `<name>-<binary>`.
- 2026-11-16: log and chat Logs panes show p2p and simplex events; bridge wire types.
- 2026-11-16: bridge's indexer store and application.
- 2026-11-16: bridge's indexer binary; `ui.fmt` (tracing's default log format).
- 2026-11-18: bridge's validator binary; bootstrapper parsing moves to `ui.rust`.
- 2026-11-18: bridge demo recorded.
- 2026-11-19: example READMEs for chat, dkg, flood, log, and bridge; bridge finishes each
  indexer request before honoring a cancel (fcec398, test 8211852).
- 2026-11-19: flood's setup and flood binaries parse through `ui.clap`, matching commonware's
  help and errors (e4afaf8); `ui.fmt` and the dkg bootstrap and floor waits keep cancels
  (536602d, 1906179).
