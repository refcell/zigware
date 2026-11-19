#!/usr/bin/env python3
"""End-to-end p2p throughput: commonware's flood against zigware's, on one local deployment.

Usage: flood-compare.py <commonware-flood> <zigware-flood> <dir> [seconds] [rounds] [warmup]

<dir> is a deployment written by examples/flood/local.sh (hosts.yaml and one config per peer,
peer i on 127.0.0.<i>); both binaries read the same files, so they run with the same keys,
message size, rate, worker threads, and mailbox. Each round runs every peer with one binary,
then with the other: after `warmup` seconds (default 10) it reads each peer's metrics
(`GET 127.0.0.<i>:9090/metrics`), waits `seconds` (default 20), reads them again, and prints
per peer the messages received per second (`flood_receiver_latency_count`), their mean latency
(`flood_receiver_latency_sum` over the count), and sends per second (`flood_sender_messages`).

commonware's flood needs two local patches (docs/BENCHMARKS.md): it binds 0.0.0.0 for p2p and
metrics, so four peers cannot share one machine, and its sender loop must yield when a send
is not accepted, or it starves the network's tasks on its tokio worker.
"""

import os
import re
import signal
import subprocess
import sys
import time
import urllib.request

METRIC = re.compile(
    r"^\w*?(flood_receiver_latency_count|flood_receiver_latency_sum|flood_sender_messages)"
    r"(?:_total)?(?:\{[^}]*\})? (\S+)"
)
KEYS = {"flood_receiver_latency_count": "count", "flood_receiver_latency_sum": "sum",
        "flood_sender_messages": "sent"}


def scrape(ip):
    """The flood counters a peer serves, or None when it does not answer."""
    try:
        page = urllib.request.urlopen(f"http://{ip}:9090/metrics", timeout=2).read().decode()
    except OSError:
        return None
    values = {}
    for line in page.splitlines():
        match = METRIC.match(line)
        if match:
            key = KEYS[match.group(1)]
            values[key] = values.get(key, 0.0) + float(match.group(2))
    return values


def run(binary, directory, seconds, warmup):
    """Per-peer (received/s, mean latency ms, sent/s) over one measured window, or None."""
    names = [line.split()[2] for line in open(os.path.join(directory, "hosts.yaml"))
             if line.startswith("- name:")]
    procs = [subprocess.Popen([binary, "--hosts", "hosts.yaml", "--config", f"{name}.yaml"],
                              cwd=directory, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
             for name in names]
    ips = [f"127.0.0.{i + 1}" for i in range(len(names))]
    try:
        time.sleep(warmup)
        before, start = [scrape(ip) for ip in ips], time.time()
        time.sleep(seconds)
        after, end = [scrape(ip) for ip in ips], time.time()
    finally:
        for proc in procs:
            os.killpg(proc.pid, signal.SIGTERM)
        for proc in procs:
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
    rows = []
    for first, last in zip(before, after):
        if not first or not last:
            rows.append(None)
            continue
        count = last.get("count", 0) - first.get("count", 0)
        total = last.get("sum", 0) - first.get("sum", 0)
        sent = last.get("sent", 0) - first.get("sent", 0)
        latency = 1000 * total / count if count else float("nan")
        rows.append((count / (end - start), latency, sent / (end - start)))
    return rows


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    commonware, zigware, directory = sys.argv[1], sys.argv[2], sys.argv[3]
    seconds = float(sys.argv[4]) if len(sys.argv) > 4 else 20
    rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 3
    warmup = float(sys.argv[6]) if len(sys.argv) > 6 else 10
    binaries = (("commonware", os.path.abspath(commonware)), ("zigware", os.path.abspath(zigware)))
    for round_index in range(rounds):
        for name, binary in binaries:
            rows = run(binary, directory, seconds, warmup)
            load = open("/proc/loadavg").read().split()[0]
            cells = "  ".join("-" if row is None else
                              f"{row[0]:8.0f}/s {row[1]:8.3f} ms (sent {row[2]:7.0f}/s)"
                              for row in rows)
            print(f"round {round_index + 1} {name:10s} load {load:>6s}  {cells}", flush=True)
            time.sleep(3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
