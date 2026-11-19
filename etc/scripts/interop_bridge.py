#!/usr/bin/env python3
"""Run commonware's and zigware's bridge validators and indexers together.

Usage: interop_bridge.py <rust-bin-dir> <zig-bin-dir> <base-port> [timeout-seconds] [views]

<rust-bin-dir> holds commonware's `dealer`, `indexer`, and `validator` (cargo's
target/release); <zig-bin-dir> holds zigware's `bridge-dealer`, `bridge-indexer`, and
`bridge-validator`. One dealing sets both networks up: zigware's dealer deals network 1
(seed 1, validators 1-4) and network 2 (seed 2, validators 5-8), and commonware's dealer must
print the same bytes for both. Each network then runs two validators of each implementation
(MIX, one letter per validator 1..8, r or z), all posting finalizations to one indexer and
fetching the other network's latest finalization from it. A validator puts a fetched
certificate in a `Bridge` block only after verifying it against the other network's public
key, and panics ("indexer is corrupt") when that fails; every validator that votes on the
block verifies it again.

Passes once each network has `views` views (default 20) finalized with one payload by all four
of its validators, and in each network validators of both implementations have proposed a
`Bridge` block that the network finalized. Runs twice: with commonware's indexer, then with
zigware's, each with the opposite mix. Fails on a view finalized with two payloads, a
validator that exits, or a timeout; logs are kept under $TMPDIR on failure.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ANSI = re.compile(r"\x1b\[[0-9;]*m")
FINALIZED = re.compile(r"actor: finalized view=(\d+) payload=([0-9a-f]+)")
PROPOSED_BRIDGE = re.compile(r"actor: proposed block=Bridge\(.* payload=([0-9a-f]+)")
NETWORKS = {1: (1, 2, 3, 4), 2: (5, 6, 7, 8)}
# (indexer, mix of validators 1..8): both networks mixed, two validators of each kind.
RUNS = (("r", "rrzzzzrr"), ("z", "zzrrrrzz"))


def text(path):
    try:
        with open(path, errors="replace") as log:
            return ANSI.sub("", log.read())
    except FileNotFoundError:
        return ""


def deal(binary, seed, participants):
    output = subprocess.run([binary, "--seed", str(seed), "--participants", participants],
                            check=True, capture_output=True, text=True).stdout
    fields = {}
    for line in output.splitlines():
        key, _, value = line.partition(": ")
        if key in ("polynomial", "public"):
            fields[key] = value.strip()
        match = re.match(r"share \(index=\d+ validator=(\d+)\): ([0-9a-f]+)", line)
        if match:
            fields[int(match.group(1))] = match.group(2)
    return output, fields


def free_base(port):
    """The first base at or above `port` whose nine ports (indexer and 8 validators) bind."""
    for base in range(port, port + 400, 10):
        if all(bindable(base + offset) for offset in range(9)):
            return base
    raise RuntimeError(f"no nine free ports from {port}")


def bindable(port):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def binaries(rust_dir, zig_dir):
    return {
        "r": {kind: os.path.join(rust_dir, kind) for kind in ("dealer", "indexer", "validator")},
        "z": {kind: os.path.join(zig_dir, f"bridge-{kind}")
              for kind in ("dealer", "indexer", "validator")},
    }


def dealings(bins):
    """Both networks' dealings, checked byte for byte between the two dealers."""
    deals = {}
    for network, members in NETWORKS.items():
        participants = ",".join(str(v) for v in members)
        zig_out, fields = deal(bins["z"]["dealer"], network, participants)
        rust_out, _ = deal(bins["r"]["dealer"], network, participants)
        if zig_out != rust_out:
            raise RuntimeError(f"network {network}: the dealers' outputs differ")
        deals[network] = fields
    return deals


def spawn(procs, root, name, command):
    log = open(os.path.join(root, f"{name}.log"), "w")
    procs[name] = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)


def stop(procs):
    for proc in procs.values():
        if proc.poll() is None:
            proc.terminate()
    for proc in procs.values():
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


def launch(bins, deals, indexer, mix, base, root):
    procs = {}
    networks = f"{deals[1]['public']},{deals[2]['public']}"
    spawn(procs, root, "indexer", [bins[indexer]["indexer"], "--me", f"0@{base}",
                                   "--participants", "1,2,3,4,5,6,7,8", "--networks", networks])
    # Validators panic when they cannot dial the indexer, so wait until it listens.
    deadline = time.time() + 30
    while bindable(base) and time.time() < deadline:
        time.sleep(0.1)
    for network, members in NETWORKS.items():
        other = 2 if network == 1 else 1
        first = members[0]
        for v in members:
            command = [bins[mix[v - 1]]["validator"], "--me", f"{v}@{base + v}",
                       "--participants", ",".join(str(m) for m in members),
                       "--storage-dir", os.path.join(root, f"storage-{v}"),
                       "--indexer", f"0@127.0.0.1:{base}",
                       "--identity", deals[network]["polynomial"],
                       "--share", deals[network][v], "--other-public", deals[other]["public"]]
            if v != first:
                command[1:1] = ["--bootstrappers", f"{first}@127.0.0.1:{base + first}"]
            spawn(procs, root, f"validator-{v}", command)
    return procs


def network_state(root, members):
    """(common finalized views, conflict view or None, implementations whose Bridge block was
    finalized) for one network's validator logs."""
    finals, bridges = [], {}
    for v in members:
        log = text(os.path.join(root, f"validator-{v}.log"))
        views = {}
        for view, payload in FINALIZED.findall(log):
            views.setdefault(int(view), payload)
        finals.append(views)
        for payload in PROPOSED_BRIDGE.findall(log):
            bridges[payload] = v
    common = set.intersection(*(set(views) for views in finals))
    for view in sorted(common):
        if len({views[view] for views in finals}) > 1:
            return common, view, set()
    finalized_payloads = {finals[0][view] for view in common}
    return common, None, {v for payload, v in bridges.items() if payload in finalized_payloads}


def run(bins, deals, indexer, mix, port, root, timeout_s, wanted):
    base = free_base(port)
    procs = launch(bins, deals, indexer, mix, base, root)
    start, parts = time.time(), []
    try:
        while time.time() - start < timeout_s:
            time.sleep(1)
            for name, proc in procs.items():
                if proc.poll() is not None:
                    return 1, f"{name} exited with {proc.returncode}"
            done, parts = True, []
            for network, members in NETWORKS.items():
                common, conflict, bridged = network_state(root, members)
                if conflict is not None:
                    return 1, f"network {network} finalized view {conflict} twice"
                kinds = {mix[v - 1] for v in bridged}
                parts.append(f"network {network}: {len(common)} views by all 4, Bridge blocks "
                             f"finalized from validators {sorted(bridged)}")
                done = done and len(common) >= wanted and kinds == {"r", "z"}
            if done:
                return 0, (f"indexer {indexer}, mix {mix}: " + "; ".join(parts) +
                           f" after {time.time() - start:.0f}s")
        return 1, f"indexer {indexer}, mix {mix}: timed out; " + "; ".join(parts)
    finally:
        stop(procs)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    bins = binaries(sys.argv[1], sys.argv[2])
    port = int(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 180.0
    wanted = int(sys.argv[5]) if len(sys.argv) > 5 else 20
    root = tempfile.mkdtemp(prefix="zigware-interop-bridge-")
    deals = dealings(bins)
    print("interop-bridge: commonware's and zigware's dealers printed identical dealings")
    for offset, (indexer, mix) in enumerate(RUNS):
        directory = os.path.join(root, f"run-{offset}")
        os.makedirs(directory)
        result, detail = run(bins, deals, indexer, mix, port + 20 * offset, directory,
                             timeout_s, wanted)
        print(f"interop-bridge: {detail}", flush=True)
        if result:
            print(f"interop-bridge: logs kept in {root}")
            return result
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
