#!/usr/bin/env bash
# Regenerate and verify the hashcat rule-compatibility corpus.
#
#   scripts/rules-oracle.sh verify   # (default) compare Hashsmith against a
#                                    # local hashcat over its stock rule files
#   scripts/rules-oracle.sh sweep    # print per-file candidate coverage
#
# The committed vectors in cmd/hashsmith/rules_hashcat_compat_test.go let CI
# run without hashcat installed. This script is the other half: it checks those
# vectors still describe the real hashcat, and measures end-to-end coverage
# over every stock rule file — the number that actually matters to a user
# pasting `-r best64.rule` from a writeup.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hashsmith="${HASHSMITH:-$root/hashsmith}"
hashcat_bin="${HASHCAT:-hashcat}"

if ! command -v "$hashcat_bin" >/dev/null 2>&1; then
  echo "hashcat not found (set HASHCAT=/path/to/hashcat) — skipping" >&2
  exit 0
fi
[ -x "$hashsmith" ] || { echo "build hashsmith first: go build -o hashsmith ./cmd/hashsmith" >&2; exit 2; }

rules_dir="${HASHCAT_RULES:-}"
if [ -z "$rules_dir" ]; then
  hc_path="$(command -v "$hashcat_bin")"
  for guess in \
    "$(dirname "$hc_path")/../share/doc/hashcat/rules" \
    "$(dirname "$hc_path")/../share/hashcat/rules" \
    "$(dirname "$hc_path")/rules"; do
    [ -d "$guess" ] && { rules_dir="$(cd "$guess" && pwd)"; break; }
  done
fi
[ -n "$rules_dir" ] && [ -d "$rules_dir" ] || {
  echo "hashcat rules dir not found (set HASHCAT_RULES=/path/to/rules)" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A deliberately varied word set: mixed case, digits, punctuation, embedded
# spaces, single characters and an empty-ish edge, so position, separator and
# length-capped commands are all exercised.
cat > "$tmp/words.txt" <<'WORDS'
password
P@ssw0rd!
hi
a
Summer2024
foo bar
hELLO wORLD
abcdef
12345
X
admin123
zzz
Test_Case-99
qwerty
letmein
MixedCASE
0
longer_password_string_here
cafe
A1b2C3
WORDS

total_ok=0 total_all=0 failed=0
printf '%-46s %10s %10s %9s\n' FILE HASHSMITH HASHCAT COVERAGE
for f in "$rules_dir"/*.rule; do
  name="$(basename "$f")"
  "$hashsmith" -N crack --stdout -w "$tmp/words.txt" --rules "$f" 2>/dev/null | sort -u > "$tmp/hs.out"
  "$hashcat_bin" --stdout -r "$f" "$tmp/words.txt" 2>/dev/null | sort -u > "$tmp/hc.out"
  hs=$(wc -l < "$tmp/hs.out" | tr -d ' ')
  hc=$(wc -l < "$tmp/hc.out" | tr -d ' ')
  miss=$(comm -13 "$tmp/hs.out" "$tmp/hc.out" | wc -l | tr -d ' ')
  cov=$(awk -v m="$miss" -v b="$hc" 'BEGIN{ if (b>0) printf "%.2f%%", 100*(b-m)/b; else print "n/a" }')
  printf '%-46s %10s %10s %9s\n' "$name" "$hs" "$hc" "$cov"
  if [ "$miss" != "0" ]; then
    failed=$((failed + 1))
    comm -13 "$tmp/hs.out" "$tmp/hc.out" | head -5 | sed 's/^/      missing: /'
  fi
  total_ok=$((total_ok + hc - miss))
  total_all=$((total_all + hc))
done

echo
awk -v a="$total_ok" -v b="$total_all" \
  'BEGIN{ printf "TOTAL: %d of %d hashcat candidates reproduced = %.4f%%\n", a, b, 100*a/b }'

if [ "$failed" -ne 0 ]; then
  echo "FAIL: $failed rule file(s) lost candidates against hashcat." >&2
  exit 1
fi
echo "OK: every hashcat candidate is reproduced."
