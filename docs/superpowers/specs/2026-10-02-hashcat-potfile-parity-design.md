# Hashcat potfile format parity — design

## Context

Work Package 1 of the pasted "Hashsmith advancement roadmap" asked for two
things: hashcat potfile format parity, and rule-engine deterministic
verification against `best64.rule`/`generated2.rule`.

**The rule-engine half is already done and was re-verified live, not
assumed.** `scripts/rules-oracle.sh` (existing) ran Hashsmith's `--stdout`
output against the real hashcat 7.1.2 binary over **every** stock rule file
hashcat ships (`generated2.rule` included) plus John-jumbo's bundled
`best64.rule`, byte-for-byte via `sort -u` + `comm -13`:

```
TOTAL: 2878178 of 2878178 hashcat candidates reproduced = 100.0000%
OK: every hashcat candidate is reproduced.
```

No new harness is built for that half — it would duplicate a working one.
This spec covers only the remaining real gap: **potfile format parity.**

## Current state (`internal/smith/pot.go`)

Hashsmith's potfile is `hash<TAB>plaintext`, one entry per line, keyed by
the bare target-hash string exactly as given on the command line. TAB was
chosen deliberately because many target strings already contain `:`
(NetNTLMv2, Kerberos, HMAC:salt). Lookups go through `verifiedPlain`, which
re-derives the hash from the recorded plaintext before trusting a hit (see
the long comment on `potHitStatus` — this is load-bearing and untouched by
this change).

Real hashcat 7.1.2 behaviour, confirmed empirically against the live binary
(not assumed from docs), run 2026-10-02:

| plaintext | potfile line |
|---|---|
| `hello` (plain ASCII, no colon, no control byte) | `hash:hello` |
| `café` (non-ASCII UTF-8) | `hash:café` — **not** hex-escaped |
| `a b` (space) | `hash:a b` — **not** hex-escaped |
| `ab:cd` (contains `:`) | `hash:$HEX[61623a6364]` |
| `a\tb` (contains a control byte, 0x09) | `hash:$HEX[610962]` |
| `$HEX[zz]` (literal text, happens to look like the escape) | `hash:$HEX[zz]` — written **raw, unescaped** |

So the real rule, observed directly: hashcat hex-encodes the plaintext as
`$HEX[<lowercase hex>]` iff it contains `:` or any byte `< 0x20`; otherwise
it writes the raw bytes verbatim, unicode included. The last row is a real,
inherited ambiguity in hashcat's own format — a plaintext that is literally
the string `$HEX[zz]` is indistinguishable on read-back from an escaped
one. Hashsmith's decoder reproduces this ambiguity rather than "fixing" it,
because the goal is parity with the real tool, not a corrected format of
our own that a real hashcat potfile would no longer round-trip through.

For salted modes, hashcat's potfile LEFT side is whatever string it read as
the hash input — for modes whose input line is itself `hash:salt`
(hashcat's `-m 10`, confirmed directly: `8e832...:abc123:secretpw`), that
means the stored key already has the salt folded in via its own colon.
Hashsmith's `-s`/`-S` flags pass salt as a separate CLI argument instead of
folding it into the target string, so a plain `p.lookup(target)` on an
imported hashcat entry would miss for this family of modes. Rather than
parsing hashcat's mode-specific line grammar (the same per-mode positional
complexity `compat.go` already had to reckon with for `-a`), the fix is
mode-agnostic: on a miss, also try `target + ":" + salt` when a salt was
supplied. This mirrors hashcat's own convention (colon-join hash and salt)
without needing to know which of the 350+ modes produced the entry.

## What this spec adds

1. **Read**: `loadPotfile` auto-detects, per line, whether it is Hashsmith's
   native TAB format or a hashcat colon-format line, and decodes
   `$HEX[...]` plaintexts on the colon path. No new flag needed to read a
   foreign `.pot` file — point `--pot` at it and it works.
2. **Lookup fallback**: `verifiedPlain` additionally tries `target+":"+salt`
   when the direct lookup misses and a salt was supplied, so imported
   hash:salt-keyed hashcat entries are reachable from Hashsmith's own
   separate-salt-flag invocations.
3. **Write**: a new `--potfile-format {native,hashcat}` flag (default
   `native`, so existing behaviour and existing potfiles are unchanged)
   controls the format of newly appended entries, with `$HEX[]` encoding
   applied on the exact trigger condition measured above (`:` or any byte
   `< 0x20`).

## Explicitly out of scope

- John the Ripper's own `.pot` file is a different, non-text format
  (encrypted/obfuscated under `john.conf`'s `[Options]` section in some
  builds) — the pasted roadmap named hashcat specifically; John's pot
  format is not attempted here.
- No attempt to parse hashcat's per-mode positional grammar to recover an
  embedded salt into a separate field — the `target+":"+salt` fallback
  above is the mode-agnostic substitute, not a precise parse.
