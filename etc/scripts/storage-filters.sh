#!/bin/sh
# Print the -Dtest-filter values, one per line, for one macOS test-storage shard.
#
# On macOS, test-storage's RSS grows with its run time (7 GB over 26 minutes in Debug), so it
# splits into three processes. Test names start with their file's module path
# (`journal.segmented.manager.test.x`), and a filter matches anywhere in the name.
# `qmdb-sync` takes `qmdb.sync.`, the generic sync harness tests (`qmdb.sync.harness.Tests(..)`);
# `qmdb` takes `<path>.test` for every other qmdb file that declares a test, and `rest` the same
# for every file outside qmdb (`root.test_0` included). A bare `merkle.` or `journal.` would also
# match generic tests whose names embed type names such as `merkle.mmb.mod.Family`.
# Usage: storage-filters.sh qmdb-sync|qmdb|rest.
set -eu

shard=${1:?usage: storage-filters.sh qmdb-sync|qmdb|rest}
root=src/storage
[ -d "$root/qmdb/sync" ] || { echo "run from the repository root" >&2; exit 1; }

# A test nested in a container (`<path>.Tests(..).test.x`) or a decltest
# (`<path>.decltest.x`) matches no `<path>.test` filter, so outside qmdb/sync it fails here
# instead of being left out.
nested=$(grep -rlE --include='*.zig' '^[[:space:]]+test[[:space:]{"]|^test [A-Za-z_@]' "$root" |
    grep -v "^$root/qmdb/sync/" || true)
[ -z "$nested" ] || { echo "tests no shard filter matches, in: $nested" >&2; exit 1; }

# `<path>.test` for each file under the given `find` arguments that declares a test.
files() {
    paths=$(find "$@" -name '*.zig' | sort)
    [ -n "$paths" ] || { echo "no files under $1" >&2; exit 1; }
    echo "$paths" | while read -r path; do
        grep -q '^test[ {"]' "$path" || continue
        module=${path#"$root"/}
        module=${module%.zig}
        echo "$(echo "$module" | tr / .).test"
    done
}

case $shard in
    qmdb-sync) echo "qmdb.sync." ;;
    qmdb) files "$root/qmdb" -not -path "$root/qmdb/sync/*" ;;
    rest) files "$root" -not -path "$root/qmdb/*" ;;
    *) echo "bad shard: $shard" >&2; exit 1 ;;
esac
