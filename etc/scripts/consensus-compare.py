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
"faster" only when that median is below 0.95 and at most n/8 of the n rounds reach 1 (none of 4,
one of 8); otherwise "not yet faster". Each round's pair of runs holds a slot of the
machine-wide bench queue (etc/scripts/bench-lock.sh, first come first served) and runs pinned to
it; set BENCH_WHOLE=1 to wait for both slots and use every CPU, as the multi-node scenarios
need. Raw measurements go to stderr as `round\\tside\\tscenario\\tmetric\\tvalue`.

Scenarios:
- `log`: four `log` validators of one implementation (ed25519 seeds 0..3, validator 0
  bootstrapping), as examples/log/README.md runs them, each in a tmux window (both are terminal
  UIs). After WARMUP_S it counts, over WINDOW_S, the views each validator shows finalized per
  second and the views nullified per view finalized (medians over the four validators). This
  compares the examples as shipped, with their timeouts and their 10 messages per second per
  peer and channel. With LOG_LATENCY=1 it also reports propose-to-finalize latency, p50 and
  p99 in milliseconds over every view proposed in the window: the time between the leader's
  `proposed` line and its `finalized` line for the same payload. The examples print stamps to
  the second, so this mode builds both from local patches that print microseconds
  (etc/scripts/consensus-compare/*.patch, applied to throwaway clones under
  ~/.cache/zigware/p2p-latency; never commit them to commonware-ref or upstream) and runs those
  binaries for `log` instead of the ones given. Both stamp a line with its event's time.
- `dkg_catchup_100`, `dkg_catchup_1000`: one implementation's `dkg` example (`setup` with 6
  peers and committees of 4, the epoch-0 `bootstrap` of players 0-3, then validators 0-4, as
  examples/dkg/README.md runs them). Once every validator has finalized N heights, validator 5
  starts with `--state-sync` (the README's late joiner: dkg probe, QMDB state sync, marshal
  backfill), and `catchup_s` is the time from its start until the timestamp of its first log
  line finalizing a block at or above the tip the others had reached when it started. The
  joiner's sync floor is that tip, so this times p2p connection and the dkg probe, not N
  heights of backfill.
- `dkg_replay_100`, `dkg_replay_1000`: the same with validator 5 started without
  `--state-sync`, so it replays every height from genesis: marshal backfills each finalized
  block and the application applies it. `catchup_s` as above, plus `replay_ms_per_block`, the
  joiner's log time from height 1 to the tip divided by the heights between.
"""

import functools
import datetime
import os
import re
import shutil
import signal
import socket
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
# A leader's `proposed` line and any `finalized` line, with their stamps (microseconds with the
# LOG_LATENCY patches).
PROPOSED = re.compile(r'\[([0-9T:.-]+)\] => proposed \(msg="[0-9a-f]*" payload="([0-9a-f]{64})"')
FINALIZED_AT = re.compile(r'\[([0-9T:.-]+)\] => finalized \(payload="([0-9a-f]{64})"')
LOG_LATENCY = os.environ.get("LOG_LATENCY") == "1"
PATCHES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "consensus-compare")
LATENCY_ROOT = os.path.expanduser("~/.cache/zigware/p2p-latency")
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
    proposed = {seed: {} for seed in seeds}  # payload -> stamp, on the leader's screen
    finalized_at = {seed: {} for seed in seeds}  # payload -> stamp
    start = time.time()
    marks = None
    try:
        while time.time() - start < WARMUP_S + WINDOW_S:
            time.sleep(0.3)
            for seed in seeds:
                screen = tmux(socket, "capture-pane", "-p", "-t", f"log:node{seed}", check=False)
                for kind, view in ACTIVITY.findall(screen):
                    (finalized if kind == "finalized" else nullified)[seed].add(int(view))
                for stamps, pattern in ((proposed, PROPOSED), (finalized_at, FINALIZED_AT)):
                    for stamp, payload in pattern.findall(screen):
                        stamps[seed].setdefault(payload, stamp)
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
    result = {"finalized_views_per_s": statistics.median(rate),
              "nullified_per_finalized": statistics.median(null)}
    if LOG_LATENCY:
        window = datetime.datetime.fromtimestamp(marks[0])
        result.update(latency_percentiles(side, proposed, finalized_at, window))
    return result


def parse_stamp(stamp):
    """A local `%Y-%m-%dT%H:%M:%S.ffffff` stamp, as the patched examples print."""
    if "." not in stamp:
        raise RuntimeError(f"stamp {stamp!r} has no fraction; LOG_LATENCY needs the patches")
    return datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%f")


def latency_percentiles(side, proposed, finalized_at, window):
    """p50 and p99 milliseconds from each leader's proposal to its own finalization of the same
    payload, over proposals made from `window` on."""
    latencies = []
    for seed, proposals in proposed.items():
        for payload, stamp in proposals.items():
            at = parse_stamp(stamp)
            done = finalized_at[seed].get(payload)
            if at < window or done is None:
                continue
            latencies.append((parse_stamp(done) - at).total_seconds() * 1000)
    if len(latencies) < 10:
        raise RuntimeError(f"{side}: only {len(latencies)} proposals finalized in the window")
    latencies.sort()
    pick = lambda q: latencies[min(len(latencies) - 1, int(q * len(latencies)))]
    return {"propose_to_finalize_p50_ms": pick(0.50), "propose_to_finalize_p99_ms": pick(0.99)}


def build_latency_binaries(commonware_ref, zigware_repo):
    """Builds each side's `log` from a throwaway clone with its microsecond-stamp patch applied,
    and returns {side: binary_dir}. The patches are never committed anywhere."""
    os.makedirs(LATENCY_ROOT, exist_ok=True)
    targets = {}
    for side, repo in (("commonware", commonware_ref), ("zigware", zigware_repo)):
        clone = os.path.join(LATENCY_ROOT, side)
        # Reuse the clone (and its build cache), reset to the repository's HEAD.
        if not os.path.isdir(clone):
            subprocess.run(["git", "clone", "-q", "--local", repo, clone], check=True)
        subprocess.run(["git", "-C", clone, "fetch", "-q", repo, "HEAD"], check=True)
        subprocess.run(["git", "-C", clone, "reset", "-q", "--hard", "FETCH_HEAD"], check=True)
        patch = os.path.join(PATCHES, f"{side}-log-us.patch")
        subprocess.run(["git", "-C", clone, "apply", patch], check=True)
        if side == "commonware":
            target = os.path.join(LATENCY_ROOT, "commonware-target")
            env = dict(os.environ, RUSTFLAGS="-C target-cpu=native", CARGO_TARGET_DIR=target)
            subprocess.run(["cargo", "build", "--release", "--offline", "-p", "commonware-log"],
                           cwd=clone, env=env, check=True)
            targets[side] = os.path.join(target, "release")
        else:
            prefix = os.path.join(LATENCY_ROOT, "zigware-out")
            subprocess.run(["zig", "build", "install", "-Doptimize=ReleaseFast", "--prefix",
                            prefix], cwd=clone, check=True)
            targets[side] = os.path.join(prefix, "bin")
    return targets


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
    """When `path`'s validator first logged a finalized height of at least `height` (its log
    line's UTC timestamp)."""
    with open(path, errors="replace") as handle:
        for line in ANSI.sub("", handle.read()).splitlines():
            found = FINALIZED.search(line)
            if found and int(found.group(1)) >= height:
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
        start = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        nodes.spawn("joiner", 5, "validator", *(["--state-sync"] if state_sync else []))
        nodes.wait(side, f"the joiner to reach height {tip}",
                   lambda: top_height(nodes.log("joiner")) >= tip, deadline)
        # The joiner's own log time, not when the 0.2 s poll above noticed it.
        reached = finalized_at(nodes.log("joiner"), tip)
        result = {"catchup_s": (reached - start).total_seconds()}
        if not state_sync:
            replay = finalized_at(nodes.log("joiner"), tip) - finalized_at(nodes.log("joiner"), 1)
            result["replay_ms_per_block"] = replay.total_seconds() * 1000 / (tip - 1)
    finally:
        nodes.stop()
    shutil.rmtree(root, ignore_errors=True)
    return result


# scenario -> (run, {metric: lower_is_better})
SCENARIOS = {
    "log": (run_log, {"finalized_views_per_s": False, "nullified_per_finalized": True,
                      "propose_to_finalize_p50_ms": True, "propose_to_finalize_p99_ms": True}),
    "dkg_catchup_100": (functools.partial(run_dkg_catchup, heights=100), {"catchup_s": True}),
    "dkg_catchup_1000": (functools.partial(run_dkg_catchup, heights=1000), {"catchup_s": True}),
    "dkg_replay_100": (functools.partial(run_dkg_catchup, heights=100, state_sync=False),
                       {"catchup_s": True, "replay_ms_per_block": True}),
    "dkg_replay_1000": (functools.partial(run_dkg_catchup, heights=1000, state_sync=False),
                        {"catchup_s": True, "replay_ms_per_block": True}),
}


def free_port_block(port):
    """The first block of 10 ports from `port` that nothing listens on, so a run never meets
    nodes a killed earlier harness left behind on the block its run index would pick."""
    while True:
        try:
            for offset in range(10):
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", port + offset))
            return port
        except OSError:
            port += 1000


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


BENCH_LOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench-lock.sh")


class BenchSlot:
    """A slot of the machine-wide bench queue (bench-lock.sh), held until `close`. While held,
    this process and every process it starts run pinned to the slot's CPUs."""

    def __init__(self):
        # The holder prints its CPU list, then keeps the slot until its stdin closes.
        self.holder = subprocess.Popen(
            [BENCH_LOCK, "bash", "-c", 'echo "$BENCH_CPUS"; cat > /dev/null'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        cpus = self.holder.stdout.readline().strip()
        if not cpus:
            raise RuntimeError("bench-lock.sh exited without a slot")
        self.previous = os.sched_getaffinity(0)
        os.sched_setaffinity(0, parse_cpus(cpus))

    def close(self):
        os.sched_setaffinity(0, self.previous)
        self.holder.stdin.close()
        self.holder.wait()


def parse_cpus(text):
    """The CPUs of a taskset list such as `0-7,16-23`."""
    cpus = set()
    for part in text.split(","):
        low, _, high = part.partition("-")
        cpus.update(range(int(low), int(high or low) + 1))
    return cpus


def main():
    # A SIGTERM unwinds like Ctrl-C, so each run's `finally` stops the nodes it started.
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    dirs = {"commonware": os.path.abspath(sys.argv[1]), "zigware": os.path.abspath(sys.argv[2])}
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    names = sys.argv[4:] or list(SCENARIOS)
    log_dirs = dirs
    if LOG_LATENCY and "log" in names:
        commonware_ref = os.environ.get("COMMONWARE_REF",
                                        os.path.expanduser("~/.cache/zigware/commonware-ref"))
        zigware_repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        log_dirs = build_latency_binaries(commonware_ref, zigware_repo)
    values = {}  # (scenario, metric) -> {side: [values per round]}
    run_index = 0
    for round_index in range(rounds):
        order = ["commonware", "zigware"] if round_index % 2 == 0 else ["zigware", "commonware"]
        for name in names:
            run, metrics = SCENARIOS[name]
            lock = BenchSlot()
            for side in order:
                # Every run gets fresh ports, so none waits on the last run's sockets.
                run_index += 1
                port = free_port_block(BASE_PORT + 10 * run_index)
                binary_dir = (log_dirs if name == "log" else dirs)[side]
                for metric, value in run(side, binary_dir, port).items():
                    values.setdefault((name, metric), {"commonware": [], "zigware": []})
                    values[(name, metric)][side].append(value)
                    print(f"{round_index + 1}\t{side}\t{name}\t{metric}\t{value:.4g}",
                          file=sys.stderr, flush=True)
            lock.close()
    print("| scenario | metric | better | commonware | zigware | ratio | verdict |")
    print("|---|---|---|---|---|---|---|")
    counts = {}
    for (name, metric), sides in values.items():
        lower_better = SCENARIOS[name][1][metric]
        pairs = zip(sides["commonware"], sides["zigware"])
        ratios = [ratio(c, z, lower_better) for c, z in pairs]
        result = verdict(ratios)
        counts[result] = counts.get(result, 0) + 1
        better = "lower" if lower_better else "higher"
        print(f"| `{name}` | `{metric}` | {better} | "
              f"{statistics.median(sides['commonware']):.3g} | "
              f"{statistics.median(sides['zigware']):.3g} | {statistics.median(ratios):.2f}× "
              f"| {result} |")
    print(f"\nRatios are zigware over commonware for lower-is-better metrics and commonware over "
          f"zigware otherwise, so below 1 means zigware is better; median of {rounds} ABBA "
          f"rounds. Verdicts: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())
