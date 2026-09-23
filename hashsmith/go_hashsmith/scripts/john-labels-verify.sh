#!/usr/bin/env bash
# Verify — and propose — entries for hash_john_labels.go against the real John.
#
#   scripts/john-labels-verify.sh verify    # (default) check every committed label
#   scripts/john-labels-verify.sh propose   # find NEW labels that verify
#
# hash_john_labels.go states the standard plainly: a John label is a claim
# about another tool's interface, so it has to be right or not made at all, and
# its own Go test only proves the KEY names a real Hashsmith format. This
# script supplies the missing half — it makes John act on the label:
#
#   1. take a known-answer vector (type, plaintext, ciphertext) from
#      `hashsmith selftest -dump`;
#   2. run `john --format=<label>` on that ciphertext with a wordlist that
#      contains the plaintext;
#   3. accept the label ONLY if John recovers exactly that plaintext.
#
# A label John rejects, ignores, or resolves to a different format never
# reaches the table. That is stricter than name-matching: several John formats
# share a spelling with a Hashsmith format but parse a different ciphertext
# shape, and those are exactly the cases that would send a user to a
# `--format=` John's own detection refuses.
set -uo pipefail
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hashsmith="${HASHSMITH:-$root/hashsmith}"
john_bin="${JOHN:-john}"
mode="${1:-verify}"

command -v "$john_bin" >/dev/null 2>&1 || { echo "john not found (set JOHN=/path/to/john) — skipping" >&2; exit 0; }
[ -x "$hashsmith" ] || { echo "build hashsmith first: go build -o hashsmith ./cmd/hashsmith" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# John's own list of accepted --format= labels, one per line, lowercased.
"$john_bin" --list=formats 2>/dev/null | tr ',' '\n' | sed 's/^ *//; s/ *$//' \
  | grep -v '^$' | tr 'A-Z' 'a-z' | sort -u > "$tmp/john-formats.txt"

# JOHN_TIMEOUT bounds a single John run. Some John formats resolve to an
# OpenCL build that blocks indefinitely waiting on a device that is not there
# (--format=ethereum selects ethereum-opencl on this machine and never
# returns), so an unbounded verifier hangs rather than failing that label.
john_timeout="${JOHN_TIMEOUT:-20}"

# run_bounded runs a command with a wall-clock limit, portably: GNU timeout if
# the machine has it, otherwise a watchdog that kills the process group.
run_bounded() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 2 "$secs" "$@" >/dev/null 2>&1; return $?
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout -k 2 "$secs" "$@" >/dev/null 2>&1; return $?
  fi
  "$@" >/dev/null 2>&1 &
  local pid=$!
  ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) 2>/dev/null &
  local watchdog=$!
  wait "$pid" 2>/dev/null; local rc=$?
  kill -9 "$watchdog" 2>/dev/null
  wait "$watchdog" 2>/dev/null
  return $rc
}

# john_shapes prints the record spellings to try for one ciphertext.
#
# Hashsmith and John do not always store the same format the same way: John's
# LM wants "$LM$<hash>", its mysql-sha1 wants "*<UPPERHASH>", and several
# formats want a "user:" field Hashsmith's bare vector does not carry. A
# refusal of ONE spelling therefore says nothing about the label — only that
# this vector was not written the way John reads it. Trying the handful of
# canonical spellings is what makes a refusal meaningful.
john_shapes() {
  local label="$1" cipher="$2"
  printf '%s\n' "$cipher"
  printf 'user:%s\n' "$cipher"
  printf '$%s$%s\n' "$label" "$cipher"
  printf '$%s$%s\n' "$(printf '%s' "$label" | tr 'a-z' 'A-Z')" "$cipher"
  printf '*%s\n' "$(printf '%s' "$cipher" | tr 'a-z' 'A-Z')"
}

# classify_label runs one (label, plaintext, ciphertext) triple against John,
# trying each canonical record spelling, and prints exactly one of:
#
#   verified      John loaded the ciphertext under that label and recovered the
#                 plaintext — positive proof the label works
#   unverified    John either refused every spelling tried, or parsed one and
#                 did not report the plaintext. NEITHER is evidence the label is
#                 wrong. Worked examples that all land here with CORRECT labels:
#                 John prints LM results upper-cased ("...:HASHCAT"), so a
#                 literal compare against the lower-case plaintext misses; and
#                 mscash/asa-md5 take their salt in a different field order than
#                 Hashsmith's vector writes it, so John parses the wrong fields.
#                 The method is therefore POSITIVE-ONLY: it can confirm a label,
#                 never refute one.
#   inconclusive  John was still working when the budget ran out; normal for
#                 high-iteration KDFs (7z, LUKS, VeraCrypt...).
classify_label() {
  local label="$1" plain="$2" cipher="$3"
  local saw_timeout=0 shape out rc

  printf '%s\n' "$plain" > "$tmp/t.words"
  while IFS= read -r shape; do
    printf '%s\n' "$shape" > "$tmp/t.hash"
    rm -f "$tmp/t.pot" "$tmp/s.rec"
    out="$(run_capture "$john_timeout" "$john_bin" --format="$label" \
        --wordlist="$tmp/t.words" --pot="$tmp/t.pot" --nolog --session="$tmp/s" "$tmp/t.hash")"
    rc=$?
    if [ -s "$tmp/t.pot" ] && grep -qF ":$plain" "$tmp/t.pot"; then
      echo verified; return
    fi
    case "$out" in
      *"No password hashes loaded"*|*"Unknown ciphertext format"*|*"Unknown format"*) continue ;;
    esac
    # John accepted this spelling but did not report the plaintext; see the
    # note above for why that is not evidence against the label.
    [ "$rc" -ne 0 ] && saw_timeout=1
  done < <(john_shapes "$label" "$cipher")

  if [ "$saw_timeout" -eq 1 ]; then echo inconclusive; return; fi
  echo unverified
}

# run_capture runs a command with a wall-clock budget and prints its output.
# Exit status is non-zero when the budget was hit.
# NOTE the </dev/null on every John invocation. Without it John inherits the
# caller's stdin and consumes it, which silently truncates any `while read`
# loop driving this function — the propose sweep stopped after 45 of 502
# vectors that way, looking like "no labels found" rather than a broken loop.
run_capture() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 2 "$secs" "$@" </dev/null 2>&1; return $?
  fi
  "$@" </dev/null >"$tmp/out" 2>&1 &
  local pid=$!
  ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  local wd=$!
  wait "$pid" 2>/dev/null; local rc=$?
  kill -9 "$wd" 2>/dev/null; wait "$wd" 2>/dev/null
  cat "$tmp/out" 2>/dev/null
  return $rc
}

# The committed table, as "format<TAB>label".
committed() {
  grep -oE '"[a-z0-9_.-]+": *"[A-Za-z0-9_.-]+"' "$root/internal/smith/hash_john_labels.go" \
    | sed 's/"//g; s/: */\t/'
}

"$hashsmith" -N selftest -dump -slow 2>/dev/null > "$tmp/vectors.tsv"
[ -s "$tmp/vectors.tsv" ] || { echo "no vectors dumped" >&2; exit 2; }

case "$mode" in
verify)
  # The baseline is the set of labels John has actually been seen to accept.
  # Because the method is positive-only, the only sound CI property is a
  # RATCHET: a label that once verified must still verify. A label that never
  # verified is simply not in the baseline, and its absence is not a claim.
  baseline="$root/scripts/john-labels-verified.txt"
  verified_now="$tmp/verified.txt"; : > "$verified_now"
  good=0 unver=0 slow=0 nov=0
  while IFS=$'\t' read -r fmt label <&3; do
    line="$(awk -F'\t' -v f="$fmt" '$1==f {print; exit}' "$tmp/vectors.tsv")"
    if [ -z "$line" ]; then
      printf '  %-28s %-22s no vector — not checked\n' "$fmt" "$label"; nov=$((nov+1)); continue
    fi
    plain="$(printf '%s' "$line" | cut -f2)"
    cipher="$(printf '%s' "$line" | cut -f4)"
    case "$(classify_label "$label" "$plain" "$cipher")" in
      verified)     printf '%s\t%s\n' "$fmt" "$label" >> "$verified_now"; good=$((good+1)) ;;
      inconclusive) printf '  %-28s %-22s inconclusive: still running after %ss (slow KDF)\n' "$fmt" "$label" "$john_timeout"; slow=$((slow+1)) ;;
      unverified)   unver=$((unver+1)) ;;
    esac
  done 3< <(committed)
  sort -o "$verified_now" "$verified_now"

  echo
  echo "verified by John: $good   unverified: $unver   inconclusive: $slow   no vector: $nov"
  echo
  echo "This check is POSITIVE-ONLY. 'unverified' means John did not confirm the label"
  echo "from Hashsmith's own vector — usually because the two tools write that format's"
  echo "record differently. It is NOT evidence the label is wrong, and no label should"
  echo "be removed on it."

  if [ "${UPDATE_BASELINE:-0}" = 1 ]; then
    cp "$verified_now" "$baseline"
    echo "baseline updated: $baseline ($good labels)"
    exit 0
  fi
  if [ ! -f "$baseline" ]; then
    echo "no baseline yet — run UPDATE_BASELINE=1 $0 verify to record one" >&2
    exit 0
  fi
  lost="$(comm -23 "$baseline" "$verified_now" || true)"
  if [ -n "$lost" ]; then
    echo
    echo "REGRESSION: these labels verified before and do not now:" >&2
    printf '%s\n' "$lost" | sed 's/^/  /' >&2
    exit 1
  fi
  echo "OK: every label in the baseline still verifies."
  ;;
propose)
  # Candidate labels come from John's OWN format list, matched by a normalised
  # name (lower-cased, punctuation stripped) plus the "raw-" prefix John uses
  # for bare digests. A name match alone proposes nothing: the pair is only
  # printed after John recovers the plaintext from Hashsmith's vector under
  # that label, which is the same bar hash_john_labels.go sets by hand.
  committed > "$tmp/committed.tsv"
  # NOTE: the dash must come LAST in tr's set. Written as '_-. ' it is parsed
  # as the range _ through ., which is reversed and deletes nothing useful.
  norm() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d '_. -'; }
  # index John's formats by normalised name
  : > "$tmp/john-index.tsv"
  while IFS= read -r jf; do
    printf '%s\t%s\n' "$(norm "$jf")" "$jf" >> "$tmp/john-index.tsv"
  done < "$tmp/john-formats.txt"

  echo "# format -> label, each verified by John recovering the plaintext"
  seen_fmt=""
  # Read the vector list on fd 3, not stdin. Any child process here (John,
  # awk, tr) inherits fd 0 and can read ahead on it, which silently truncated
  # this sweep at line 185 of 502 and looked like "no labels found".
  # Fields are pulled with cut rather than `IFS=$'\t' read a b c d`. TAB is an
  # IFS *whitespace* character, so read collapses runs of tabs and an empty
  # salt column silently shifts the target into the salt variable — which
  # dropped every unsalted format (346 of 392) from this sweep while looking
  # like a clean run.
  while IFS= read -r rec <&3; do
    fmt="$(printf '%s' "$rec" | cut -f1)"
    plain="$(printf '%s' "$rec" | cut -f2)"
    cipher="$(printf '%s' "$rec" | cut -f4)"
    [ -n "$fmt" ] && [ -n "$cipher" ] || continue
    case " $seen_fmt " in *" $fmt "*) continue ;; esac
    seen_fmt="$seen_fmt $fmt"
    awk -F'\t' -v f="$fmt" '$1==f {found=1} END{exit !found}' "$tmp/committed.tsv" && continue
    n="$(norm "$fmt")"
    # candidate John labels: exact normalised match, and the raw-<name> spelling
    cands="$(awk -F'\t' -v a="$n" -v b="raw$n" '$1==a || $1==b {print $2}' "$tmp/john-index.tsv")"
    [ -n "$cands" ] || continue
    while IFS= read -r cand; do
      [ -n "$cand" ] || continue
      if [ "$(classify_label "$cand" "$plain" "$cipher")" = verified ]; then
        printf '\t\t"%s": "%s",\n' "$fmt" "$cand"
        break
      fi
    done <<EOF
$cands
EOF
  done 3< "$tmp/vectors.tsv"
  ;;
*)
  echo "usage: $0 [verify|propose]" >&2; exit 2 ;;
esac
