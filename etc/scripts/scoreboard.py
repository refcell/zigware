#!/usr/bin/env python3
"""Head-to-head scoreboard: every lane's latest bench-compare rounds, counted by verdict.

Usage: scoreboard.py [--rows] [docs/bench/*.tsv]

Each lane commits its latest `etc/scripts/bench-compare.sh` rounds as docs/bench/<lane>.tsv:
`# key: value` header lines (at least `date: YYYY-MM-DD`; also `zigware`, `commonware`, and
`method`), then one tab-separated line per bench per round:

    round  package  bench  commonware_ns  zigware_ns  load1

`package` is the zigware package the bench lives in (codec, cryptography, storage, ...);
`bench` is the full criterion name both sides print. A failed side is `nan`. When two files
measure the same bench, the one with the later `date` wins.

A bench's ratio is the median of its per-round zigware / commonware ratios. Its verdict is
"faster" when that median is below 0.95 and at most n/8 of its n rounds (rounded down) reach
1, "slower" when the median is above 1.05 and at most n/8 rounds are at or below 1, and "tie"
otherwise (noise counts as not yet faster), as etc/scripts/bench-compare.sh decides.
"""

import math
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLUMNS = ("round", "package", "bench", "commonware_ns", "zigware_ns", "load1")
VERDICTS = ("faster", "tie", "slower")


def read(path):
    """Returns (header, {bench: (package, [ratios], [loads])}) for one lane file."""
    header, rows = {}, {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith("#"):
            key, _, value = line[1:].partition(":")
            header[key.strip()] = value.strip()
            continue
        fields = line.split("\t")
        if len(fields) != len(COLUMNS):
            sys.exit(f"scoreboard: {path}:{number}: want {len(COLUMNS)} tab-separated fields")
        _, package, bench, cw, zw, load = fields
        cw, zw = float(cw), float(zw)
        entry = rows.setdefault(bench, (package, [], []))
        if math.isnan(cw) or math.isnan(zw) or cw <= 0:
            continue
        entry[1].append(zw / cw)
        entry[2].append(float(load))
    if "date" not in header:
        sys.exit(f"scoreboard: {path}: missing a '# date: YYYY-MM-DD' header line")
    return header, rows


def verdict(ratios):
    median = statistics.median(ratios)
    allowed = len(ratios) // 8
    if median < 0.95 and sum(r >= 1 for r in ratios) <= allowed:
        return "faster"
    if median > 1.05 and sum(r <= 1 for r in ratios) <= allowed:
        return "slower"
    return "tie"


def main(argv):
    show_rows = "--rows" in argv
    paths = [Path(a) for a in argv if a != "--rows"] or sorted((ROOT / "docs/bench").glob("*.tsv"))
    latest = {}  # bench -> (date, lane, package, ratios, loads)
    for path in paths:
        header, rows = read(path)
        for bench, (package, ratios, loads) in rows.items():
            if not ratios:
                continue
            candidate = (header["date"], path.stem, package, ratios, loads)
            if bench not in latest or candidate[0] >= latest[bench][0]:
                latest[bench] = candidate
    if not latest:
        print("scoreboard: no measured benches")
        return 0
    per_package = {}
    for bench, (date, lane, package, ratios, loads) in sorted(latest.items()):
        counts = per_package.setdefault(package, dict.fromkeys(VERDICTS, 0))
        counts[verdict(ratios)] += 1
    total = dict.fromkeys(VERDICTS, 0)
    print("| package | faster | tie | slower |")
    print("|---|---|---|---|")
    for package, counts in sorted(per_package.items()):
        print(f"| {package} | " + " | ".join(str(counts[v]) for v in VERDICTS) + " |")
        for v in VERDICTS:
            total[v] += counts[v]
    print("| **all** | " + " | ".join(f"**{total[v]}**" for v in VERDICTS) + " |")
    if show_rows:
        print("\n| bench | lane | date | rounds | median | range | load | verdict |")
        print("|---|---|---|---|---|---|---|---|")
        for bench, (date, lane, package, ratios, loads) in sorted(latest.items()):
            print(f"| `{bench}` | {lane} | {date} | {len(ratios)} | "
                  f"{statistics.median(ratios):.2f}× | {min(ratios):.2f}–{max(ratios):.2f} | "
                  f"{min(loads):.0f}–{max(loads):.0f} | {verdict(ratios)} |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
