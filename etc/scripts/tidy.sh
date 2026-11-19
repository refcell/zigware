#!/usr/bin/env bash
# Repository hygiene checks: formatting, line length, function length, and a
# secrets/private-data backstop. Run before every push: `just tidy`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
zig_paths=(build.zig src)
[ -d examples ] && zig_paths+=(examples)

if ! zig fmt --check "${zig_paths[@]}" >/dev/null; then
  echo "tidy: zig fmt needed:"; zig fmt --check "${zig_paths[@]}" || true
  fail=1
fi

# Line length <= 100 for Zig sources (multiline string literals excepted).
if long=$(git ls-files -co --exclude-standard '*.zig' \
  | xargs awk 'length > 100 && $0 !~ /^[[:space:]]*\\\\/ { print FILENAME ":" FNR }' 2>/dev/null) \
  && [ -n "$long" ]; then
  echo "tidy: lines over 100 columns:"; echo "$long"; fail=1
fi

# Function length <= 70 lines (TigerStyle). Generic type constructors are exempt.
if long_fns=$(git ls-files -co --exclude-standard '*.zig' \
  | xargs awk -v max=70 -f etc/scripts/fn-length.awk 2>/dev/null) && [ -n "$long_fns" ]; then
  echo "tidy: functions over 70 lines:"; echo "$long_fns"; fail=1
fi

# Secrets and private data. Patterns are assembled so this file does not match itself.
p_home='/Us''ers/|/ho''me/[a-z]'
p_keys='BEGIN [A-Z ]*PRIV''ATE KEY|AK''IA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}'
p_mail='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(com|net|org|io|dev|xyz)'
files=$(git ls-files -co --exclude-standard | grep -v '^etc/scripts/tidy.sh$' \
  | grep -vE '\.(gif|mp4|png|jpg|webm)$' || true)
if [ -n "$files" ]; then
  hits=$(echo "$files" | xargs grep -nIE "$p_home|$p_keys" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "tidy: possible secret/private data:"; echo "$hits"; fail=1
  fi
  mails=$(echo "$files" | xargs grep -nIoE "$p_mail" 2>/dev/null \
    | grep -vE 'noreply|example\.(com|org)' || true)
  if [ -n "$mails" ]; then
    echo "tidy: email addresses found:"; echo "$mails"; fail=1
  fi
fi

for f in .env .claude/settings.local.json; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "tidy: $f must never be committed"; fail=1
  fi
done

if grep -qE '^\s*\.[a-z_]+\s*=\s*\.\{\s*\.url' build.zig.zon; then
  echo "tidy: build.zig.zon must have no dependencies"; fail=1
fi

# Markdown links, anchors, and code-span paths resolve (under 0.2 s): `just check-links`.
python3 -I etc/scripts/check-links.py >/dev/null || { python3 -I etc/scripts/check-links.py; fail=1; }

[ "$fail" -eq 0 ] && echo "tidy: ok"
exit "$fail"
