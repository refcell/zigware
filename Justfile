# zigware — the Commonware Library in Zig. `just` lists recipes.

set positional-arguments := true

alias t := test
alias b := build

default:
    @just --list

# Build every example (debug)
build *args:
    zig build {{ args }}

# Build every example optimized; downloads Zig 0.17.1 into .cache/zig if it is not on PATH
release:
    #!/usr/bin/env sh
    set -eu
    if [ "$(zig version 2>/dev/null || true)" != "0.17.1" ]; then
        if [ "$(.cache/zig/zig version 2>/dev/null || true)" != "0.17.1" ]; then
            sh etc/scripts/install-zig.sh .cache/zig
        fi
        PATH="$PWD/.cache/zig:$PATH"
    fi
    zig build -Doptimize=ReleaseFast -Dgit-rev=$(git rev-parse --short HEAD)

# Run unit tests, optionally filtered: just test varint
test filter='':
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{ filter }}" ]; then zig build test -Dtest-filter="{{ filter }}"; else zig build test; fi

# Run one package's tests: just test-package codec
test-package package:
    zig build test-{{ package }} --summary all

# Run the test suite inside a Linux container (exercises io_uring)
test-linux:
    docker run --rm --security-opt seccomp=unconfined --security-opt label=disable -v "$PWD":/src -w /src \
      alpine:3.20 sh -c 'apk add --no-cache curl xz >/dev/null && \
      etc/scripts/install-zig.sh /tmp/zig && /tmp/zig/zig build test'

# Coverage-guided fuzzing of all fuzz tests
fuzz:
    zig build test --fuzz -Doptimize=ReleaseSafe

# Seeded fuzz soak: every seeded fuzz test, `factor` times the iterations, fresh seed
fuzz-soak factor='100' seed='1':
    zig build test -Doptimize=ReleaseSafe -Dtest-filter=fuzz -Dfuzz-soak={{ factor }} -Dfuzz-seed={{ seed }}

# Format sources
fmt:
    zig fmt build.zig build.zig.zon src $(test -d examples && echo examples)

# Formatting, line length, function length, secrets, and dependency checks
tidy:
    etc/scripts/tidy.sh

# Everything CI runs
ci: tidy test

clean:
    rm -rf zig-out .zig-cache
