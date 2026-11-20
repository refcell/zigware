# Bugs found in upstream commonware

Bugs in commonware itself (`commonwarexyz/monorepo`, pinned at `a9ffc25f3`) that came up while
porting it, testing the two implementations together, or benchmarking them. zigware's own bugs
and mistakes in our bench harnesses are not listed. AGENTS.md rule 12 asks every lane to add
new findings here in the same push, and to say whether each is filed upstream. Filing an issue
or posting a patch upstream needs Andreas's approval first.

| Finding | Kind | Filed upstream |
| --- | --- | --- |
| [flood's sender loop never yields](#flood-sender-starves-its-tokio-worker) | bug | yes, [#5809](https://github.com/commonwarexyz/monorepo/issues/5809) |
| [flood binds `0.0.0.0` for every peer](#flood-binds-0000-for-every-peer) | limitation | no |
| [bulletproofs ipa `verify` can panic on a short setup](#bulletproofs-ipa-verify-can-panic-on-a-short-setup) | hardening | no |

Everywhere else that commonware panics and zigware returns an error (glue, marshal, codec,
the dkg example's `bootstrap DKG failed`), the panic is commonware's documented behavior and
zigware's error is a design choice, so those are not listed.

## flood sender starves its tokio worker

Filed as [#5809](https://github.com/commonwarexyz/monorepo/issues/5809), with Andreas's
approval. Nothing else has been posted.

`examples/flood/src/bin/flood.rs`: `flood_sender` loops on `check(Recipients::All)` and
`checked.send(msg, true)`, and awaits only when the check is rate-limited. When the check
passes but no send is accepted (before discovery has connected any peer, or at a rate the
quota never limits), the loop never yields. The network tasks it wakes sit in that worker's
LIFO slot, which other tokio workers cannot steal, so they never run: no peer sends its
discovery greeting, about 140 bytes cross each connection after the handshakes, and every
peer's `flood_receiver_latency_count` stays 0. It reproduces with 2 or 8 worker threads and
with 2 or 4 peers.

The fix is one `commonware_runtime::reschedule().await` when a send is not accepted. With it,
a two-peer deployment receives 600 msg/s per peer. Even with it, an unthrottled rate
(1,000,000 msg/s) still receives 0 on commonware, while zigware's flood receives 450k to
740k per peer: zigware's port has the same loop, but its sender runs on its own
`std.Io.Threaded` thread, so the spin starves nothing.

- Evidence: [p2p.md, "Upstream finding"](lanes/p2p.md#upstream-finding-commonwares-flood-sender-starves-its-tokio-worker)
  has the repro steps and both patches;
  [BENCHMARKS.md, end-to-end flood](BENCHMARKS.md#end-to-end-flood-4-peers-2026-11-19-p2p-lane)
  has the run that found it.
- Commits: b98907f3 (write-up with repro and patches), 89c89961 (links the filed issue).

## flood binds 0.0.0.0 for every peer

Not filed. A usability limitation rather than a correctness bug.

flood listens on `0.0.0.0:4545` and serves metrics on `0.0.0.0:9090`, so a second peer on the
same machine cannot bind and a local multi-peer run fails. zigware's flood binds a peer's own
IP when that IP is loopback. The head-to-head ran commonware with the same change (patch 1 in
[p2p.md](lanes/p2p.md#upstream-finding-commonwares-flood-sender-starves-its-tokio-worker)).

## bulletproofs ipa verify can panic on a short setup

Not filed. Input-validation hardening; whether it is reachable depends on the caller.

`cryptography/src/zk/bulletproofs/ipa.rs` `verify` takes `claim.log_len` from the claim,
checks that the proof has that many rounds, and then slices `&setup.g()[..claimed_len]` and
`&setup.h()[..claimed_len]` without checking the setup's length, so a claim longer than the
setup panics instead of returning `None`. A proof is decoded with a `max_len` bound, which
limits its rounds, so a caller that derives `max_len` from its own setup is safe. A caller
that decodes with a larger bound, or takes the claim from a peer, can be made to panic.
zigware's `verify` returns null there ([crypto.md](lanes/crypto.md), "zk bulletproofs ipa").
