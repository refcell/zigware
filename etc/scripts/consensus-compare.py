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
- `dkg_catchup_100`, `dkg_catchup_1000`: one implementation's `dkg` example (`setup` with 6
  peers and committees of 4, the epoch-0 `bootstrap` of players 0-3, then validators 0-4, as
  examples/dkg/README.md runs them). Once every validator has finalized N heights, validator 5
  starts with `--state-sync` (the README's late joiner: dkg probe, QMDB state sync, marshal
  backfill), and `catchup_s` is the time from its start until it logs a finalized block at the
  tip the others had reached when it started. The joiner's sync floor is that tip, so this
  times p2p connection and the dkg probe, not N heights of backfill.
- `dkg_replay_100`, `dkg_replay_1000`: the same with validator 5 started without
  `--state-sync`, so it replays every height from genesis: marshal backfills each finalized
  block and the application applies it. `catchup_s` as above, plus `replay_ms_per_block`, the
  joiner's log time from height 1 to the tip divided by the heights between.
"""

import fcntl
import functools
import datetime
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
BINARIES = {"log": {"commonware": "commonware-log", "zigware": "log"},
            "dkg": {"commonware": "commonware-dkg", "zigware": "dkg"}}
# The dkg example's reporter line, the same on both sides (escape codes stripped first).
FINALIZED = re.compile(r"finalized block epoch=\d+ height=(\d+) digest=[0-9a-f]{64}")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
CATCHUP_TIMEOUT_S = float(os.environ.get("CATCHUP_TIMEOUT_S", "1800"))


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


def top_height(path):
    """The highest height `path`'s validator logged as finalized, or -1."""
    with open(path, errors="replace") as handle:
        found = FINALIZED.findall(ANSI.sub("", handle.read()))
    return max((int(height) for height in found), default=-1)


class DkgNodes:
    """One side's dkg processes, each logging to `<name>.log` under `root`."""

    def __init__(self, binary, root):
        self.binary, self.root, self.procs = binary, root, {}

    def spawn(self, name, index, *args):
        log = open(self.log(name), "w")
        node = os.path.join(self.root, "data", f"validator-{index}")
        self.procs[name] = subprocess.Popen([self.binary, *args, "--node-dir", node],
                                            stdout=log, stderr=subprocess.STDOUT)

    def log(self, name):
        return os.path.join(self.root, f"{name}.log")

    def check(self, side):
        for name, proc in self.procs.items():
            if proc.poll() is not None:
                raise RuntimeError(f"{side}: {name} exited ({proc.returncode}); see {self.root}")

    def stop(self, names=None):
        for name in list(names or self.procs):
            proc = self.procs.pop(name)
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def wait(self, side, what, done, deadline):
        while not done():
            if time.time() > deadline:
                raise RuntimeError(f"{side}: timed out waiting for {what}; see {self.root}")
            self.check(side)
            time.sleep(0.2)


def finalized_at(path, height):
    """When `path`'s validator logged `height` as finalized (its log line's timestamp)."""
    with open(path, errors="replace") as handle:
        for line in ANSI.sub("", handle.read()).splitlines():
            found = FINALIZED.search(line)
            if found and int(found.group(1)) == height:
                return datetime.datetime.fromisoformat(line.split()[0].rstrip("Z"))
    raise RuntimeError(f"{path} never finalized height {height}")


def run_dkg_catchup(side, binary_dir, port, heights, state_sync=True):
    """Seconds a late joiner takes to finalize the tip that validators 0-4 of `side` reached
    once each had finalized `heights` heights: syncing from a recent floor with `state_sync`,
    else replaying from genesis (then also its milliseconds per replayed block)."""
    root = tempfile.mkdtemp(prefix="zigware-consensus-compare-dkg-")
    nodes = DkgNodes(os.path.join(binary_dir, BINARIES["dkg"][side]), root)
    deadline = time.time() + CATCHUP_TIMEOUT_S
    try:
        subprocess.run([nodes.binary, "setup", "--node-dir", os.path.join(root, "data"),
                        "--peers", "6", "--committee-size", "4", "--base-port", str(port)],
                       check=True, capture_output=True)
        players = [f"boot{index}" for index in range(4)]
        for index, name in enumerate(players):
            nodes.spawn(name, index, "bootstrap")
        nodes.wait(side, "bootstrap", lambda: all(
            "bootstrap complete" in ANSI.sub("", open(nodes.log(n), errors="replace").read())
            for n in players), deadline)
        nodes.stop(players)
        validators = [f"val{index}" for index in range(5)]
        for index, name in enumerate(validators):
            nodes.spawn(name, index, "validator")
        nodes.wait(side, f"{heights} heights", lambda: min(
            top_height(nodes.log(n)) for n in validators) >= heights, deadline)
        tip = max(top_height(nodes.log(n)) for n in validators)
        start = time.time()
        nodes.spawn("joiner", 5, "validator", *(["--state-sync"] if state_sync else []))
        nodes.wait(side, f"the joiner to reach height {tip}",
                   lambda: top_height(nodes.log("joiner")) >= tip, deadline)
        result = {"catchup_s": time.time() - start}
        if not state_sync:
            replay = finalized_at(nodes.log("joiner"), tip) - finalized_at(nodes.log("joiner"), 1)
            result["replay_ms_per_block"] = replay.total_seconds() * 1000 / (tip - 1)
    finally:
        nodes.stop()
    shutil.rmtree(root, ignore_errors=True)
    return result


# scenario -> (run, {metric: lower_is_better})
SCENARIOS = {
    "log": (run_log, {"finalized_views_per_s": False, "nullified_per_finalized": True}),
    "dkg_catchup_100": (functools.partial(run_dkg_catchup, heights=100), {"catchup_s": True}),
    "dkg_catchup_1000": (functools.partial(run_dkg_catchup, heights=1000), {"catchup_s": True}),
    "dkg_replay_100": (functools.partial(run_dkg_catchup, heights=100, state_sync=False),
                       {"catchup_s": True, "replay_ms_per_block": True}),
    "dkg_replay_1000": (functools.partial(run_dkg_catchup, heights=1000, state_sync=False),
                        {"catchup_s": True, "replay_ms_per_block": True}),
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
