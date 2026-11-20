#!/usr/bin/env python3
"""End-to-end consensus head-to-head: commonware's examples against zigware's, on loopback.

Usage: consensus-compare.py <commonware-target> <zigware-bin> [rounds] [scenario ...]

<commonware-target> is a cargo release directory holding commonware's example binaries (built
with RUSTFLAGS="-C target-cpu=native"), and <zigware-bin> zigware's (`zig-out/bin`, ReleaseFast).
Each scenario runs once per side per round, in ABBA order (round 1 commonware then zigware,
round 2 zigware then commonware, and so on; default 4 rounds), so both sides see the same
machine load. A scenario is a function `run(side, binary_dir, port) -> {metric: value}`
registered in SCENARIOS with, per metric, whether lower is better. For each metric the table
shows both sides' medians and the median of the per-round ratios (zigware / commonware, flipped
for higher-is-better metrics so a ratio below 1 always means zigware is better). The verdict is
"faster" only when that median is below 0.95 and at most n/8 of the n rounds reach 1 (none of
4, one of 8); otherwise "not yet faster". Each round's pair of runs holds the machine-wide bench
lock (~/.cache/zigware/bench.lock, as bench-compare.sh), so no other lane benches meanwhile.
Raw measurements go to stderr as `round\\tside\\tscenario\\tmetric\\tvalue`.

Scenarios:
- `log`: four `log` validators of one implementation (ed25519 seeds 0..3, validator 0
  bootstrapping), as examples/log/README.md runs them, each in a tmux window (both are terminal
  UIs). After WARMUP_S it counts, over WINDOW_S, the views each validator shows finalized per
  second and the views nullified per view finalized (medians over the four validators). This
  compares the examples as shipped, with their timeouts and their 10 messages per second per
  peer and channel. Propose-to-finalize latency is not measured: the examples print timestamps
  to the second and serve no metrics, so simplex's `finalization_latency` histogram cannot be
  read from outside, and on loopback nearly every view finalizes within the second it was
  proposed.
"""

import fcntl
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

WARMUP_S = float(os.environ.get("WARMUP_S", "20"))
WINDOW_S = float(os.environ.get("WINDOW_S", "60"))
BASE_PORT = int(os.environ.get("BASE_PORT", "23600"))

# An Activity line: `[time] => finalized (payload=".." view="N" ..)` or `nullified (view="N"`.
ACTIVITY = re.compile(r'\] => (finalized|nullified) \((?:payload="[0-9a-f]{64}" )?view="(\d+)"')
BINARIES = {"log": {"commonware": "commonware-log", "zigware": "log"}}


def tmux(socket, *args, check=True):
    return subprocess.run(["tmux", "-L", socket, "-f", "/dev/null", *args], check=check,
                          capture_output=True, text=True).stdout


def run_log(side, binary_dir, port):
    """Finalized views per second and nullified views per finalized view (medians over the
    validators) for four validators of `side`."""
    binary = os.path.join(binary_dir, BINARIES["log"][side])
    socket = f"zigware-consensus-compare-{os.getpid()}-{port}"
    storage = tempfile.mkdtemp(prefix="zigware-consensus-compare-")
    seeds = range(4)
    for seed in seeds:
        command = [binary, "--me", f"{seed}@{port + seed}", "--participants", "0,1,2,3",
                   "--storage-dir", f"{storage}/{seed}"]
        if seed != 0:
            command[1:1] = ["--bootstrappers", f"0@127.0.0.1:{port}"]
        line = " ".join(command)
        if seed == 0:
            tmux(socket, "new-session", "-d", "-s", "log", "-x", "250", "-y", "200",
                 "-n", "node0", line)
        else:
            tmux(socket, "new-window", "-t", "log", "-n", f"node{seed}", line)
    finalized = {seed: set() for seed in seeds}
    nullified = {seed: set() for seed in seeds}
    start = time.time()
    marks = None
    try:
        while time.time() - start < WARMUP_S + WINDOW_S:
            time.sleep(0.3)
            for seed in seeds:
                screen = tmux(socket, "capture-pane", "-p", "-t", f"log:node{seed}", check=False)
                for kind, view in ACTIVITY.findall(screen):
                    (finalized if kind == "finalized" else nullified)[seed].add(int(view))
            if marks is None and time.time() - start >= WARMUP_S:
                marks = (time.time(), {s: (len(finalized[s]), len(nullified[s])) for s in seeds})
    finally:
        tmux(socket, "kill-server", check=False)
        shutil.rmtree(storage, ignore_errors=True)
    elapsed = time.time() - marks[0]
    counted = {s: len(finalized[s]) - marks[1][s][0] for s in seeds}
    if min(counted.values()) == 0:
        raise RuntimeError(f"{side}: a validator finalized nothing in the window ({counted})")
    rate = [counted[s] / elapsed for s in seeds]
    null = [(len(nullified[s]) - marks[1][s][1]) / counted[s] for s in seeds]
    return {"finalized_views_per_s": statistics.median(rate),
            "nullified_per_finalized": statistics.median(null)}


# scenario -> (run, {metric: lower_is_better})
SCENARIOS = {
    "log": (run_log, {"finalized_views_per_s": False, "nullified_per_finalized": True}),
}


def ratio(commonware, zigware, lower_better):
    """Below 1 when zigware is better; 1 when both are zero."""
    better, worse = (zigware, commonware) if lower_better else (commonware, zigware)
    if better == worse:
        return 1.0
    return better / worse if worse else float("inf")


def verdict(ratios):
    slow = sum(r >= 1 for r in ratios)
    if statistics.median(ratios) < 0.95 and slow <= len(ratios) // 8:
        return "faster"
    return "not yet faster"


def bench_lock():
    """The machine-wide bench lock, held until the returned file is closed."""
    path = os.path.expanduser("~/.cache/zigware/bench.lock")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handle = open(path, "a")
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    dirs = {"commonware": os.path.abspath(sys.argv[1]), "zigware": os.path.abspath(sys.argv[2])}
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    names = sys.argv[4:] or list(SCENARIOS)
    values = {}  # (scenario, metric) -> {side: [values per round]}
    run_index = 0
    for round_index in range(rounds):
        order = ["commonware", "zigware"] if round_index % 2 == 0 else ["zigware", "commonware"]
        for name in names:
            run, metrics = SCENARIOS[name]
            lock = bench_lock()
            for side in order:
                # Every run gets fresh ports, so none waits on the last run's sockets.
                run_index += 1
                port = BASE_PORT + 10 * run_index
                for metric, value in run(side, dirs[side], port).items():
                    values.setdefault((name, metric), {"commonware": [], "zigware": []})
                    values[(name, metric)][side].append(value)
                    print(f"{round_index + 1}\t{side}\t{name}\t{metric}\t{value:.4g}",
                          file=sys.stderr, flush=True)
            lock.close()
    print("| scenario | metric | commonware | zigware | ratio | verdict |")
    print("|---|---|---|---|---|---|")
    counts = {}
    for (name, metric), sides in values.items():
        lower_better = SCENARIOS[name][1][metric]
        pairs = zip(sides["commonware"], sides["zigware"])
        ratios = [ratio(c, z, lower_better) for c, z in pairs]
        result = verdict(ratios)
        counts[result] = counts.get(result, 0) + 1
        print(f"| `{name}` | `{metric}` | {statistics.median(sides['commonware']):.3g} | "
              f"{statistics.median(sides['zigware']):.3g} | {statistics.median(ratios):.2f}× "
              f"| {result} |")
    print(f"\nRatios are zigware over commonware for lower-is-better metrics and commonware over "
          f"zigware otherwise, so below 1 means zigware is better; median of {rounds} ABBA "
          f"rounds. Verdicts: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())
