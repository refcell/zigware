#!/usr/bin/env python3
"""Run commonware's and zigware's dkg validators in one network, with a late joiner.

Usage: interop_dkg.py <rust-dkg> <zig-dkg> <base-port> [timeout-seconds]

Two runs, each from one `commonware-dkg setup` (6 participants, committees of 4):

- Mix `rrzz` bootstraps the epoch-0 DKG with commonware players 0 and 1 and zigware players 2
  and 3; every player must complete and every `genesis.json` must be identical. Validators 0-4
  (`rrzzr`) then run the chain: simplex consensus, buffered broadcast, marshal, and a threshold
  reshare each epoch. They must finalize at least 200 heights with identical digests and each
  complete 3 reshares. Then zigware's validator 5 joins with `--state-sync`: it fetches a
  recent finalized block and its epoch's public material from peers (glue's dkg probe), syncs
  QMDB from it, and backfills blocks through marshal's resolver instead of replaying from
  genesis. It must start above height 0 and finalize 20 heights with the others' digests.
- Mix `zzrr` (validators `zzrrz`) does the same with commonware's validator 5 as the joiner,
  whose debug log must show its probe requesting the boundary block from peers; marshal's
  floor fetch and resolver deliveries are reported when seen. Both joiners log at debug so a
  failure leaves a full log.

Fails on a view finalized with two digests, a validator that exits (zigware or commonware), or
timeout.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

FINALIZED = re.compile(r"finalized block epoch=\d+ height=(\d+) digest=([0-9a-f]{64})")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RESHARE = "completed reshare ceremony"
# Commonware's joiner at debug: glue's dkg probe asking peers for the boundary block (required:
# the joiner cannot start above genesis without their answer), and marshal's floor fetch and
# resolver deliveries (`handle_deliver`), reported when seen: the floor block often arrives by
# broadcast or the probe first, which retires marshal's request.
PROBE = "requesting boundary block"
FLOOR_FETCH = "starting fetch for floor block"
DELIVERIES = ("repaired block", "received block", "received finalization",
              "received notarization")


def text(path):
    with open(path, errors="replace") as handle:
        return ANSI.sub("", handle.read())


def heights(path):
    found = {}
    for height, digest in FINALIZED.findall(text(path)):
        if found.setdefault(int(height), digest) != digest:
            raise RuntimeError(f"{path} finalized height {height} twice")
    return found


class Run:
    """One network: its directory, binaries, and running processes."""

    def __init__(self, binaries, mix, port, root):
        self.binaries, self.mix, self.port = binaries, mix, port
        self.dir = os.path.join(root, mix)
        self.procs = {}

    def spawn(self, name, index, kind, *args):
        log = open(os.path.join(self.dir, f"{name}.log"), "w")
        command = [self.binaries[kind], *args, "--node-dir",
                   os.path.join(self.dir, "data", f"validator-{index}")]
        self.procs[name] = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)

    def stop(self, names=None):
        for name in list(names or self.procs):
            proc = self.procs.pop(name)
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def exited(self):
        for name, proc in self.procs.items():
            if proc.poll() is not None:
                lines = [l for l in text(self.log(name)).splitlines() if "panic" in l]
                return f"{name} exited ({proc.returncode}) {lines[:1]}"
        return None

    def log(self, name):
        return os.path.join(self.dir, f"{name}.log")


def bootstrap(run, deadline):
    """Runs the epoch-0 DKG with players 0-3 of `run.mix`; genesis must agree everywhere."""
    subprocess.run([run.binaries["r"], "setup", "--node-dir", os.path.join(run.dir, "data"),
                    "--peers", "6", "--committee-size", "4", "--base-port", str(run.port)],
                   check=True, capture_output=True)
    for index, kind in enumerate(run.mix):
        run.spawn(f"boot{index}", index, kind, "bootstrap")
    names = [f"boot{index}" for index in range(4)]
    while time.time() < deadline:
        time.sleep(0.5)
        if all("bootstrap complete" in text(run.log(name)) for name in names):
            break
        if run.exited():
            return run.exited()
    else:
        return "bootstrap timed out"
    run.stop(names)
    genesis = {open(os.path.join(run.dir, "data", f"validator-{i}", "genesis.json")).read()
               for i in range(6)}
    return None if len(genesis) == 1 else f"{len(genesis)} different genesis files"


def launch(run, deadline):
    """Runs validators 0-4 until they share 200 heights and each completed 3 reshares."""
    kinds = run.mix + run.mix[0]
    for index, kind in enumerate(kinds):
        run.spawn(f"val{index}", index, kind, "validator")
    while time.time() < deadline:
        time.sleep(1)
        if run.exited():
            return run.exited(), None
        seen = [heights(run.log(f"val{i}")) for i in range(5)]
        common = set.intersection(*(set(s) for s in seen))
        bad = [h for h in common if len({s[h] for s in seen}) > 1]
        if bad:
            return f"height {min(bad)} finalized with different digests", None
        reshares = min(text(run.log(f"val{i}")).count(RESHARE) for i in range(5))
        if len(common) >= 200 and reshares >= 3:
            return None, (f"validators {kinds} finalized {len(common)} heights with identical "
                          f"digests and completed {reshares}+ reshares each")
    return "launch timed out", None


def join(run, kind, deadline):
    """Starts validator 5 with --state-sync; it must sync and follow with the same digests."""
    # Debug on both: commonware's marshal shows its fetches, and a failure leaves a full log.
    run.spawn("val5", 5, kind, "--log-level", "debug", "validator", "--state-sync")
    while time.time() < deadline:
        time.sleep(1)
        if run.exited():
            return run.exited(), None
        joiner = heights(run.log("val5"))
        seen = [heights(run.log(f"val{i}")) for i in range(5)]
        common = [h for h in joiner if all(h in s for s in seen)]
        bad = [h for h in common if any(s[h] != joiner[h] for s in seen)]
        if bad:
            return f"joiner finalized height {min(bad)} differently", None
        if len(common) >= 20:
            if min(joiner) == 0:
                return "joiner replayed from genesis instead of syncing", None
            evidence = ""
            if kind == "r":
                log = text(run.log("val5"))
                if PROBE not in log:
                    return "the joiner's probe never requested a boundary block", None
                counts = {line: log.count(line) for line in (FLOOR_FETCH, *DELIVERIES)}
                seen = ", ".join(f"{k} x{v}" for k, v in counts.items() if v) or "nothing"
                evidence = f"; probe {PROBE}; marshal {seen}"
            return None, (f"joiner ({kind}) synced to height {min(joiner)} and finalized "
                          f"{len(common)} heights with the same digests{evidence}")
    return "joiner timed out", None


def free_base(port):
    """The first base at or above `port` whose six validator ports bind on 127.0.0.1: other
    processes on a shared machine may hold some (commonware's listener panics on BindFailed)."""
    for base in range(port, port + 300, 6):
        if all(bindable(base + offset) for offset in range(6)):
            return base
    raise RuntimeError(f"no six free ports from {port}")


def bindable(port):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def network(binaries, mix, joiner, port, root, timeout_s):
    run = Run(binaries, mix, free_base(port), root)
    os.makedirs(run.dir)
    deadline = time.time() + timeout_s
    try:
        failure = bootstrap(run, deadline)
        if failure:
            return 1, f"{mix}: {failure}"
        failure, launched = launch(run, deadline)
        if failure:
            return 1, f"{mix}: {failure}"
        failure, joined = join(run, joiner, deadline)
        if failure:
            return 1, f"{mix}: {failure}"
        return 0, f"{mix} bootstrap agreed on genesis; {launched}; {joined}"
    finally:
        run.stop()


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    binaries = {"r": sys.argv[1], "z": sys.argv[2]}
    port = int(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 180.0
    root = tempfile.mkdtemp(prefix="zigware-interop-dkg-")
    try:
        for offset, (mix, joiner) in enumerate((("rrzz", "z"), ("zzrr", "r"))):
            result, detail = network(binaries, mix, joiner, port + offset * 10, root, timeout_s)
            print(f"interop-dkg: {detail}", flush=True)
            if result:
                print(f"interop-dkg: logs kept in {root}")
                return result
    except Exception:
        print(f"interop-dkg: logs kept in {root}")
        raise
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
