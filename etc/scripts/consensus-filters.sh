#!/bin/sh
# Print the -Dtest-filter values, one per line, for one nightly test-consensus group.
#
# Test names start with their file's module path (`simplex.types_test.test.x`), so a filter
# `<dir>.<entry>.` selects one file or directory. The simplex DST files take minutes per test,
# so `simplex-engine-<i>` and `simplex-fixtures-<i>` split their tests round-robin into
# `engine_shards` and `fixtures_shards` groups, by the names in their `test "..."`
# declarations: `.test.<name>` also matches a test of a generic `Suite(F)`. `rest` takes
# every entry of src/consensus/simplex that no other group names, plus consensus's top-level
# files, so a new file always lands in some group. A filter may match a cheap test of another group too; no test is left out.
# Usage: consensus-filters.sh <group>.
set -eu

group=${1:?usage: consensus-filters.sh <group>}
root=src/consensus
[ -d "$root/simplex" ] || { echo "run from the repository root" >&2; exit 1; }

engine_shards=3
# Four: with three, one fixtures group ran 56 minutes on arm (6e50645).
fixtures_shards=4
simplex_engine="engine_test engine_optimistic_test"
simplex_fixtures="fixtures_test"
simplex_twins="twins_campaign_test mocks"

entries() {
    for path in "$1"/*; do
        case $path in
            *.zig) basename "$path" .zig ;;
            *) [ -d "$path" ] && basename "$path" ;;
        esac
    done
}

prefixed() {
    prefix=$1
    shift
    for entry in "$@"; do echo "$prefix.$entry."; done
}

# Every shards-th distinct test name of the given simplex files, starting at the shard-th.
shard_names() {
    shards=$1
    shard=$2
    shift 2
    [ "$shard" -ge 1 ] && [ "$shard" -le "$shards" ] || { echo "bad shard: $shard" >&2; exit 1; }
    for entry in "$@"; do
        sed -n 's/^[[:space:]]*test "\([^"]*\)".*/\1/p' "$root/simplex/$entry.zig"
    done | awk -v shards="$shards" -v shard="$shard" \
        '!seen[$0]++ { if ((count++ % shards) + 1 == shard) print ".test." $0 }'
}

case $group in
    marshal | aggregation) echo "$group." ;;
    simplex-engine-*) shard_names "$engine_shards" "${group#simplex-engine-}" $simplex_engine ;;
    simplex-fixtures-*)
        shard_names "$fixtures_shards" "${group#simplex-fixtures-}" $simplex_fixtures
        ;;
    simplex-twins) prefixed simplex $simplex_twins ;;
    rest)
        for entry in $(entries "$root/simplex"); do
            case " $simplex_engine $simplex_fixtures " in
                # The sharded files' unnamed `test {}` blocks match no test name.
                *" $entry "*) echo "simplex.$entry.test_" ;;
                *)
                    case " $simplex_twins " in
                        *" $entry "*) ;;
                        *) echo "simplex.$entry." ;;
                    esac
                    ;;
            esac
        done
        for entry in $(entries "$root"); do
            case $entry in
                simplex | marshal | aggregation) ;;
                fuzz) prefixed fuzz $(entries "$root/fuzz") ;;
                # Top-level files test as `<file>.test` (`types.test_0`, `traits.test.x`).
                *) echo "$entry.test" ;;
            esac
        done
        ;;
    *)
        echo "unknown group: $group" >&2
        exit 1
        ;;
esac
