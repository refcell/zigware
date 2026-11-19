#!/usr/bin/env python3
"""Run commonware's and zigware's log validators in one simplex network and compare finality.

Usage: interop_log.py <rust-log> <zig-log> <base-port> [timeout-seconds] [views]

Starts four validators sharing one committee (ed25519 seeds 0..3): 0 and 1 run commonware's
`commonware-log`, 2 and 3 run zigware's `log`, each in its own tmux window (both are terminal
UIs) with validator 0 as the bootstrapper. Their Activity panes are captured repeatedly and
every `finalized (payload=.. view=..)` line is collected. Passes once `views` views were seen
finalized by all four validators with one digest each, at least 5 of them proposed by each
implementation. Views are not consecutive: the example nullifies some views, in commonware and
zigware alike. Fails on any view finalized with two digests, or on timeout. Then zigware's
validator 3 is stopped for 10 s and restarted, and must finalize later views with the others'
digests (INTEROP_LOG_RESTART=0 skips this).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

FINALIZED = re.compile(r'\] => finalized \(payload="([0-9a-f]{64})" view="(\d+)"')
NULLIFIED = re.compile(r'\] => nullified \(view="(\d+)"')
PROPOSED = re.compile(r'\] => proposed \(msg="[0-9a-f]+" payload="([0-9a-f]{64})"')
# Which implementation runs each validator: INTEROP_LOG_MIX, one letter per seed (r or z).
MIX = os.environ.get("INTEROP_LOG_MIX", "rrzz")
NODES = [("rust" if letter == "r" else "zig", seed) for seed, letter in enumerate(MIX)]


def tmux(socket, *args, check=True):
    return subprocess.run(["tmux", "-L", socket, "-f", "/dev/null", *args],
                          check=check, capture_output=True, text=True).stdout


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    rust_bin, zig_bin, base = sys.argv[1], sys.argv[2], int(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 120.0
    wanted = int(sys.argv[5]) if len(sys.argv) > 5 else 30
    socket = f"zigware-interop-log-{os.getpid()}"
    storage = tempfile.mkdtemp(prefix="zigware-interop-log-")
    commands = {}
    participants = ",".join(str(seed) for _, seed in NODES)
    for index, (implementation, seed) in enumerate(NODES):
        binary = rust_bin if implementation == "rust" else zig_bin
        command = [binary, "--me", f"{seed}@{base + seed}", "--participants", participants,
                   "--storage-dir", f"{storage}/{seed}"]
        if seed != 0:
            command[1:1] = ["--bootstrappers", f"0@127.0.0.1:{base}"]
        line = " ".join(command)
        commands[seed] = line
        if index == 0:
            tmux(socket, "new-session", "-d", "-s", "log", "-x", "250", "-y", "60",
                 "-n", "node0", line)
        else:
            tmux(socket, "new-window", "-t", "log", "-n", f"node{seed}", line)
    finalized = {seed: {} for _, seed in NODES}
    proposer = {}
    nullified = {seed: set() for _, seed in NODES}
    start = time.time()
    result, detail = None, ""
    try:
        while result is None and time.time() - start < timeout_s:
            time.sleep(0.4)
            for implementation, seed in NODES:
                screen = tmux(socket, "capture-pane", "-p", "-t", f"log:node{seed}", check=False)
                nullified[seed].update(int(view) for view in NULLIFIED.findall(screen))
                for payload in PROPOSED.findall(screen):
                    proposer.setdefault(payload, implementation)
                for payload, view in FINALIZED.findall(screen):
                    view = int(view)
                    seen = finalized[seed].setdefault(view, payload)
                    if seen != payload:
                        result, detail = 1, f"validator {seed} finalized view {view} twice"
            common = sorted(set.intersection(*(set(views) for views in finalized.values())))
            for view in common:
                digests = {finalized[seed][view] for _, seed in NODES}
                if len(digests) > 1:
                    result, detail = 1, f"view {view} finalized with digests {sorted(digests)}"
            by = {kind: sum(proposer.get(finalized[0][v]) == kind for v in common)
                  for kind in ("rust", "zig")}
            needed = {kind for kind, _ in NODES}
            if result is None and len(common) >= wanted and all(by[k] >= 5 for k in needed):
                result = 0
                detail = (f"{len(common)} views ({common[0]}..{common[-1]}) finalized with "
                          f"identical digests by all {len(NODES)} validators ({by['rust']} "
                          f"proposed by commonware, {by['zig']} by zigware) after "
                          f"{time.time() - start:.0f}s")
        if result == 0 and os.environ.get("INTEROP_LOG_RESTART", "1") == "1":
            result, restart_detail = restart(socket, commands, finalized, NODES[-1][1],
                                             timeout_s)
            detail += "; " + restart_detail
    finally:
        tmux(socket, "kill-server", check=False)
        shutil.rmtree(storage, ignore_errors=True)
    if result is None:
        counts = {seed: len(views) for seed, views in finalized.items()}
        common = sorted(set.intersection(*(set(views) for views in finalized.values())))
        run = longest_run(common)
        kinds = sorted({str(proposer.get(finalized[0][view])) for view in run})
        lo, hi = common[0], common[-1]
        gaps = [v for v in range(lo, hi) if v not in finalized[0]]
        null = [v for v in gaps if v in nullified[0]]
        result, detail = 1, (f"timed out; finalized views seen per validator: {counts}, "
                             f"{len(common)} by all, longest run {len(run)}, proposers {kinds}; "
                             f"node 0 gaps in {lo}..{hi}: {len(gaps)}, nullified among them "
                             f"{len(null)}; first gaps {gaps[:12]}")
    print(f"interop-log: {detail}")
    return result


def restart(socket, commands, finalized, seed, timeout_s):
    """Stops validator `seed` for 10 s while the others advance, restarts it on its storage,
    and waits until it finalizes later views with the others' digests. It catches up from the
    certificates its peers broadcast; the example's catch-up does not reach simplex's resolver
    (no `received certificate for request` event), so this checks recovery, not the resolver."""
    window = f"log:node{seed}"
    tmux(socket, "respawn-pane", "-k", "-t", window, "sleep 1000")
    stopped_at = max(finalized[seed], default=0)
    time.sleep(10)
    tmux(socket, "respawn-pane", "-k", "-t", window, commands[seed])
    others = [s for s in finalized if s != seed]
    start = time.time()
    while time.time() - start < timeout_s:
        time.sleep(0.4)
        screen = tmux(socket, "capture-pane", "-p", "-t", window, check=False)
        for payload, view in FINALIZED.findall(screen):
            view = int(view)
            if view <= stopped_at:
                continue
            expected = {finalized[s].get(view) for s in others} - {None}
            if expected and payload not in expected:
                return 1, f"restarted validator {seed} finalized view {view} differently"
            finalized[seed][view] = payload
        for s in others:
            other = tmux(socket, "capture-pane", "-p", "-t", f"log:node{s}", check=False)
            for payload, view in FINALIZED.findall(other):
                finalized[s].setdefault(int(view), payload)
        caught = [v for v in finalized[seed] if v > stopped_at and
                  all(finalized[s].get(v) == finalized[seed][v] for s in others)]
        if len(caught) >= 10:
            return 0, (f"validator {seed} stopped at view {stopped_at}, restarted, and "
                       f"finalized {len(caught)} later views with the same digests after "
                       f"{time.time() - start:.0f}s")
    return 1, f"restarted validator {seed} did not catch up"


def longest_run(views):
    """The longest run of consecutive views in sorted `views`."""
    best, current = [], []
    for view in views:
        current = current + [view] if current and view == current[-1] + 1 else [view]
        if len(current) > len(best):
            best = current
    return best


if __name__ == "__main__":
    sys.exit(main())
