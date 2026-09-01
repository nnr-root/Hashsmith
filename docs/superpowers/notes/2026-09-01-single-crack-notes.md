> **Correction (2026-09-01, `gecos-single` branch):** The "What GECOS
> support would take" section below is wrong about there being a blocker,
> and the note is left in place — not silently rewritten — so the mistake
> and its correction are both on the record.
>
> The claim was that GECOS support needed an output-format change to
> `shadow2smith`'s `user:hash` lines to carry the name field through. It
> doesn't, and trying to do it that way would in fact be unsafe: `crack.go`'s
> `splitUsername` is deliberately first-colon-only, because several of the
> 461 supported formats legitimately contain colons in the hash itself
> (NetNTLMv2, salted digests, IKE, IPMI, CHAP, CMS, ...). A third
> colon-delimited field tacked onto `user:hash` can't be parsed back out
> unambiguously against those formats — the "consumers that parse it" risk
> the note itself flags in point 2 below is real, and a format change is the
> wrong way to route around it.
>
> The design actually taken: a new `--passwd FILE` flag on `crack` reads an
> `/etc/passwd`-format file directly and builds a `username -> GECOS` map
> in-process (`parsePasswdGecos` in `extract_shadow.go`, reusing the line
> parser `parsePasswdUsers` already had). `--single` (`single.go`) consults
> that map for name-derived seeds (`gecosSeeds`) alongside its existing
> username-derived ones (`singleSeeds`), keyed per-account exactly the same
> way. `shadow2smith`'s output format and `splitUsername` are both
> completely untouched — there was never a compatibility risk to design
> around, because the name never needs to travel through the hash-list
> format at all. Operationally this is also the natural shape: an operator
> extracting `/etc/shadow` already has `/etc/passwd` sitting right next to
> it.
>
> See `single_test.go` (`TestSingleCrackGecos*`, `TestGecosSeeds*`,
> `TestSingleCrackPasswd*`) for the resulting behavior and its tests,
> including the no-cross-contamination property extended to GECOS-derived
> seeds.

# Single-crack: interactions, and what GECOS would take

Companion to `docs/superpowers/plans/2026-09-01-single-crack.md`, covering its
Tasks 2 and 3. Everything below was verified against the built binary, not
inferred from the code.

## How `--single` composes with the other flags

| combination | behaviour | why |
|---|---|---|
| `--single` without `--username` | **errors, exit 2**, naming `--username` | without usernames there are no seeds; silently producing zero and reporting "not found" is the failure mode this codebase keeps producing |
| `--single --show` | runs **zero** single-crack passes | `--show`'s contract is that it never attacks. A real bug violated this two tasks ago, so `--single` is gated on `cc.showOnly` and verified by test |
| `--single --left` | accounts cracked by single-crack are **not** listed as left | otherwise a second pass redoes work the first already did |
| `--single --loopback` | loopback consumes single-crack's recoveries | verified end to end: `eve`'s password is single-crack-reachable, `erin` shares that plaintext under a different salt and is reachable no other way. Without `--loopback`, erin stays uncracked (exit 1); with it, loopback pass 1 cracks her (exit 0) |
| `--single --skip N` / `--limit N` | single-crack passes are **not** bounded by them | see below |

### Why `--skip`/`--limit` do not bound single-crack

Those flags divide the **main attack's keyspace** so N machines can tile it —
the union of disjoint slices must cover exactly what an unsplit run covers.
Single-crack's candidate source is per-account seeds: a different space
entirely, and a tiny one. Slicing it by main-attack indices would be
meaningless and could skip accounts outright.

Verified: `--single -r` finds the target with `--limit 1` and with `--skip 100`
just as it does unbounded.

This matches the same decision made for `--loopback`, and for the same reason.
Tiling is unaffected either way, because the main attack completes under its
real bounds before single-crack or loopback runs at all.

## What GECOS support would take

JtR's single mode mines the GECOS field as well as the login name — "John
Smith" yielding `jsmith`, `johns`, `smithj`. Hashsmith does not, and the
blocker is upstream of the cracker.

**`shadow2smith` discards it.** It emits one `user:hash` line per account
(`extract_shadow.go`), reading `/etc/passwd` only to merge and filter which
accounts appear. The name field never reaches the output, so by the time the
cracker sees a target, the information is gone.

Supporting it needs three decisions, none of which belong in a bolt-on:

1. **An output format that carries it.** `user:hash` is deliberately
   hashcat-compatible, so scripts can move between tools. A third field would
   break that compatibility unless it is opt-in — e.g. a `--gecos` flag on the
   extractor emitting `user:gecos:hash`, which then collides with the
   first-colon-only rule `--username` relies on. That interaction needs
   designing, not guessing.
2. **Consumers that parse it.** `splitUsername` is first-colon-only precisely
   because many of the 461 formats embed colons in the target itself
   (`hash:salt`, IKE, IPMI, CHAP, CMS). Any richer format has to survive that.
3. **Seed generation from a free-text name.** Login names are constrained;
   GECOS is arbitrary text with spaces, commas, and office/phone subfields.
   Turning "Smith, John Q.,Room 4,x1234" into useful seeds is its own small
   parser.

Until then, username-only captures the common case: login-derived passwords
are what single-crack mostly finds.

## Scale

Seeds stay bounded. A stress test with 2001 distinct usernames sharing one
hash produced ~8000 deduplicated seeds and **one** attack pass, in 0.065s —
growth is linear in distinct usernames per hash, deduplicated, not multiplied
per input line.
