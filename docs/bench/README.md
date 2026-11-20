# Head-to-head bench results, one file per lane

Each lane commits its latest `etc/scripts/bench-compare.sh` rounds here as `<lane>.tsv`, next to
the rows it adds to [BENCHMARKS.md](../BENCHMARKS.md), by copying
`.cache/bench-compare/raw.tsv` unchanged. `just scoreboard` (etc/scripts/scoreboard.py) reads
every file and prints the faster/tie/slower counts per package and overall; `--rows` lists
each bench.

The format is `# key: value` header lines (`date: YYYY-MM-DD` is required; `zigware`,
`commonware`, and `method` name the revisions and how the rounds ran), then one tab-separated
line per bench per round:

```
<round>	<package>	<bench>	<commonware_ns>	<zigware_ns>	<load1>
```

`package` is the zigware package whose bench binary runs the bench, `bench` the full criterion
name with its parameters, and a failed side is `nan`. When two files measure one bench, the
later `date` wins. A bench is faster when the median of its per-round zigware / commonware
ratios is below 0.95 and at most n/8 of its n rounds (rounded down) reach 1, slower when the
median is above 1.05 and at most n/8 rounds are at or below 1, and a tie otherwise.
