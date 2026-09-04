# Hashsmith: Unified Identification Engine

**Date:** 2026-09-04
**Status:** Approved design, pending implementation plan
**Scope:** Sub-project A of four. B (rule-engine parity + long-tail formats),
C (attack autopilot) and D (GPU kernel expansion) are named here only so this
design does not foreclose them; they are not specified.

---

## 1. Goal

Make `hashsmith identify` the best hash identification tool that exists, and
make it the same engine `hashsmith crack` uses to choose a mode.

"Best" is measured against `hashid`, `Name-That-Hash`, `haiti`,
`hash-identifier`, `hashcat --identify` and John's format auto-detection, on
four axes:

1. **Breadth** — how many formats are recognized at all.
2. **Discrimination** — whether an answer narrows the field or just lists
   everything of the right length.
3. **Actionability** — whether the answer tells you what to run next.
4. **Honesty** — whether stated confidence is defensible.

Hashsmith already wins axis 1 by a wide margin and loses axes 2, 3 and 4
today. This design closes those three.

---

## 2. Where identification stands today

Measured against the tree at `91cb93a`, not estimated.

### 2.1 There are two detection engines and they do not know about each other

| | `scoreCandidates` (`identify`) | `detectHashTypes` (`crack`) |
|---|---|---|
| Consumers | `identify` command only | 8 call sites: `crack`, `batch`, `auto`, `interactive`, `scan2smith`, `crack_ldap` |
| Vocabulary | ~209 **display names** ("MD5", "Bubble Babble") | ~242 **`-t` tokens** (`md5`, `krb5tgs`) |
| Output | normalized percentage scores | ordered candidate list |
| Structure | 4 goroutines over 4 scoring groups + a 144-case signature switch | one ~640-line first-match-wins cascade |

The two vocabularies are not interchangeable. `identify` says `MD5`; `crack`
needs `md5`. `identify`'s display names cannot be fed to `crack` at all, which
is why the tool's own error message tells the user to run `identify` and then
translate the result by hand.

### 2.2 The percentages are not probabilities

```
$ hashsmith identify 5f4dcc3b5aa765d61d8327deb882cf99
%24 MD5 (32-char lowercase hex, entropy 3.80)
%16 MD4 (32-char lowercase hex, entropy 3.80)
%15 NTLM (32-char lowercase hex, entropy 3.80)
%15 LM (LAN Manager) (32-char lowercase hex legacy Windows digest)
%13 MD2 (32-char lowercase hex legacy digest)
%9  Crockford Base32
%8  Base32hex
```

These numbers are heuristic scores divided by their own sum. `%24 MD5` does not
mean "24% chance of MD5"; nothing in the codebase computed such a probability.
Three specific defects follow:

- **The denominator is arbitrary.** Adding a seventh candidate lowers MD5's
  number without any new evidence about MD5.
- **Negative evidence is not represented.** LM digests are upper-case. This
  input is lower-case, which is evidence *against* LM — yet LM scores level
  with NTLM.
- **Prevalence is not represented.** In practice a bare 32-char lowercase hex
  string is overwhelmingly MD5. The output spreads 83 points across five
  candidates and commits to nothing.

### 2.3 The answer is not actionable

The registry holds 706 aliases including 503 numeric Hashcat modes, and 395 of
457 formats carry at least one. `identify` prints none of them. A user who gets
`%24 MD5` still has to look up `-m 0` themselves.

### 2.4 John labels exist but are not machine-recoverable

`canonicalHashType` strips a `john:`/`jtr:` prefix and resolves the remainder
against the same flat alias map used for spelling variants. So `john:raw-md5`,
`raw-md5`, `md-5` and `0` all work as *input* — but there is no way to ask the
registry "what is the John label for `md5`?", because `raw-md5` is stored
indistinguishably from `md-5`. Measured: **0 of 457 formats can report a John
label**, despite many having one.

### 2.5 Recognition coverage is unmeasured

457 formats ship with 502 known-answer vectors, and `selftest` proves the
*hashing* is correct. Nothing proves the *detection* is. There is no test
asserting that a `sha512crypt` vector is identified as sha512crypt. The true
recognition rate over the 457 formats is currently unknown.

### 2.6 Text-only input

`identify` accepts a string, a comma list, or a file read as one hash per line.
Handing it a `.kdbx`, `.pdf` or `.pcap` produces a meaningless answer, even
though the same binary contains 47 extractors that handle those files.

---

## 3. Design

### 3.1 Placement: a new `internal/hashid` package

The detection engine and the prototype table move to `internal/hashid`,
following the existing `internal/gpubackend` and `internal/argon2d` pattern.

Rationale, weighed against the two rejected alternatives:

- **Rejected — extend `hashFormat` in place.** `cmd/hashsmith` is a single Go
  package holding ~62,000 lines. It is the largest structural liability in the
  repository and this change would add ~3,000 more to it.
- **Rejected — embedded JSON/TOML prototype file.** More diffable, but a
  mistyped `-t` name becomes a runtime failure instead of a build failure. The
  project's self-test culture is built on compile-time and known-answer
  guarantees; trading one away for readability is the wrong trade here.
- **Chosen — `internal/hashid`.** Independently testable, does not grow the
  large package, and the safety property the data-file approach loses is
  recovered by an integrity test (§5.2) that walks every prototype and asserts
  its `-t` names exist in `universalHashRegistry`.

**Dependency direction is one-way.** `internal/hashid` knows only canonical
`-t` name strings. It does not know Hashcat modes, John labels, or descriptions.
`cmd/hashsmith` receives detection results and decorates them from its registry.
No import cycle; `internal/hashid` is testable standalone.

### 3.2 The prototype

```go
type Tier uint8

const (
    TierChecksum   Tier = iota // a checksum/polymod verified — mathematical proof
    TierSignature              // unique record prefix ($2y$, $krb5tgs$)
    TierStructural             // field count, lengths and encodings agree
    TierShape                  // length and alphabet only
)

type Prototype struct {
    Types      []string // canonical -t names, in the order crack must try them
    Display    string   // human name, e.g. "Kerberos 5 TGS-REP, etype 23"
    Tier       Tier
    Exclusive  bool     // a match suppresses every lower-precedence prototype
    Match      func(Input) (Evidence, bool)
    Against    func(Input) (string, bool) // optional negative evidence
    Prevalence uint8    // 0-100, tie-breaker only
    Rationale  string   // why Prevalence is what it is; MUST be non-empty
}
```

Four fields carry the design:

**`Exclusive` encodes the current cascade as data.** `detectHashTypes` is a
first-match-wins cascade whose *order is load-bearing*: once `isLDAP` returns,
the trailing `switch len(t)` shape fallback never runs. Every `return
[]string{...}` in today's cascade becomes `Exclusive: true`; the trailing
length switch becomes `Exclusive: false`. Behaviour is preserved exactly, but
becomes readable and individually testable.

**`Types` is a slice, not a scalar,** because today's ordered groups must
survive verbatim — `$krb5asrep$23$` yields `{krb5asrep, krb5asrep-nt}` and that
order is a deliberate precedence decision.

**`Against` introduces negative evidence,** which does not exist today. LM
declares "LM digests are upper-case"; a lower-case input demotes LM to
`unlikely` with that string shown as the reason. This is what fixes §2.2's
second defect.

**`Rationale` may not be empty** and §5.2 enforces it at test time. Claiming
"MD5 dominates in practice" is allowed; claiming it without writing down why is
not. This extends the provenance discipline `selftest` already applies to
vectors (`published` / `cross-checked` / `regression`) to the detection side.

`Evidence` carries the human-readable justification — "32-char lowercase hex",
"Bech32 polymod verified" — replacing today's `reason` string, and appears in
both the human and JSON output.

### 3.3 The pipeline

One entry point, two presentations:

```
Input
  │  normalize: strip shadow "user:" prefix, base58/base64 -> hex, trim
  ▼
Evaluate every prototype  ──►  []Match{Prototype, Evidence}
  │
  ▼
Suppression (see below)
  │
  ├──►  DetectTypes()  -> []string      // crack: byte-identical to today
  └──►  Identify()     -> []Candidate   // identify: tier + prevalence
```

**Suppression rule, stated precisely** — this is what keeps `crack`
byte-identical:

- If any `Exclusive` prototype matched, the **earliest one in precedence
  order wins outright**. `DetectTypes` returns exactly its `Types` and nothing
  else, reproducing the cascade's early `return`.
- If none did, every non-exclusive match is returned in precedence order —
  today's trailing `switch len(t)` list.

`Identify` consumes the same evaluation but is allowed to *also* surface the
suppressed lower-precedence matches, demoted to `unlikely` and labelled as
ruled out, so a user can see what was excluded and why. `crack` never sees
them, so this extra visibility cannot affect cracking behaviour.

Both consumers read one evaluation of one prototype table. It becomes
architecturally impossible for `crack` and `identify` to disagree about what a
hash is — which is the concrete meaning of "unified".

### 3.4 Confidence model

Confidence is derived first from structural evidence, and only then from
curated prevalence.

| Tier | Unrivalled | Rivalled |
|---|---|---|
| Checksum, Signature | `certain` | `likely`, ordered by `Prevalence` |
| Structural | `likely` | `possible` |
| Shape | `possible` | `likely` if `Prevalence >= 60`; `unlikely` if `Against` fires or `Prevalence < 15` |

A candidate demoted by `Against` prints that predicate's string as its reason
("LM digests are upper-case"); one demoted by low `Prevalence` prints its
`Rationale` instead ("effectively extinct"). Both appear in the §4.1 example.

`Prevalence` never promotes a candidate past `likely` and never invents a
percentage. Ordering among equals is the only thing it decides. Every weight
carries its `Rationale` and the top candidate's rationale is printed.

### 3.5 Performance

`scoreCandidates` currently spawns four goroutines per input. For one hash that
cost is not recovered; for the batch mode in §4.5 it is actively harmful
(8,000 lines x 4 goroutines). The new pipeline is single-pass and
allocation-free on the hot path; parallelism in batch mode is per *line*, not
per prototype. Both cases are benchmarked and the numbers recorded in the plan.

---

## 4. Surface

### 4.1 Human output

```
$ hashsmith identify 5f4dcc3b5aa765d61d8327deb882cf99

  MD5      likely     -m 0      raw-md5   -t md5     most common raw digest
  NTLM     possible   -m 1000   NT        -t ntlm
  MD4      possible   -m 900    raw-md4   -t md4
  LM       unlikely   -m 3000   LM        -t lm      LM digests are upper-case
  MD2      unlikely   -m -      -         -t md2     effectively extinct

  32-char lowercase hex; no discriminating structural evidence.
  hashsmith crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99
```

This replaces the `%NN Name (reason)` format. Scripts parsing the old output
break; `--json` is the supported replacement and is introduced in the same
change.

A format with no Hashcat mode or no John label prints `-`. This is deliberate:
it makes Hashsmith's coverage advantage visible on every invocation rather than
asserted in a README table.

### 4.2 JSON and exit codes

```json
{
  "schema": "hashsmith.identify/1",
  "input": "5f4dcc3b5aa765d61d8327deb882cf99",
  "normalized": "5f4dcc3b5aa765d61d8327deb882cf99",
  "candidates": [
    {
      "name": "MD5", "type": "md5",
      "confidence": "likely", "tier": "shape",
      "hashcat": 0, "john": "raw-md5",
      "evidence": "32-char lowercase hex",
      "rationale": "most common raw digest in leaked dumps",
      "command": "hashsmith crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99"
    }
  ]
}
```

`schema` is present from day one so fields can be added without breaking
consumers. `hashcat` is `null` and `john` is `null` when the format has none.

Exit codes align with `crack`'s existing `0/1/2` contract:

- `0` — at least one `certain` or `likely` candidate
- `1` — only `possible`/`unlikely` candidates, or none
- `2` — usage or I/O error

so `hashsmith identify h.txt && hashsmith crack h.txt` is a meaningful chain.

### 4.3 Recovering John labels

§2.4 blocks the `john` column. Fix: `compatibilityHashAliasSeed` gains
provenance. Aliases are tagged at their definition site as `hashcat` (numeric),
`john` (a real JtR `--format=` label) or `spelling` (a convenience variant).
Input resolution is unchanged — every alias keeps working exactly as today —
but the registry gains a reverse lookup that can answer "the John label for
`md5` is `raw-md5`, not `md-5`".

Tagging is incremental: an untagged alias defaults to `spelling` and simply
does not appear in the `john` column. `identify --coverage` reports how many
formats still lack a tagged John label, so the gap is visible and closeable
rather than silently wrong.

### 4.4 File and container input

`extractorDefinition` gains one optional field:

```go
Sniff func(head []byte) (Evidence, bool)  // sees the first ~4 KiB
```

```
$ hashsmith identify Database.kdbx

  KeePass KDBX 4          certain    -t keepass
  signature 0x9AA2D903 0xB54BFB67, version 4.0, KDF Argon2d

  This is a container, not a hash. Extract the record first:
      hashsmith keepass2smith -f Database.kdbx
```

No other identification tool accepts a container file: `hashid`, `haiti` and
`Name-That-Hash` take text only, while Hashcat and John recognize the file but
delegate to an out-of-tree converter script. Hashsmith has all 47 extractors in
the same binary, so identify -> extract -> crack becomes one chain.

Not all 47 must implement `Sniff` immediately. Those that do not are skipped
silently, and `identify --coverage` lists them.

### 4.5 Batch mode

```
$ hashsmith identify -i dump.txt --summary

  8,412 lines scanned - 8,398 identified - 14 unidentified

  bcrypt        5,977   71.2%   certain    -m 3200
  NTLM          1,848   22.0%   likely     -m 1000
  sha512crypt     573    6.8%   certain    -m 1800

  Split by type:  --split-by-type ./out/
  Unidentified:   --unmatched unmatched.txt
```

These percentages are counts over lines — measured quantities, unlike §2.2's
scores. `/etc/shadow`, `user:hash`, LDIF and pwdump line shapes are parsed, and
the username field is preserved and carried into the output.

Line and token scanning reuses `scan2smith`'s existing scanner
(`extractScannedRecords`) rather than reimplementing it; that function's
`detectHashTypes` call becomes a call into the new engine like every other.

### 4.6 Record decoding (`--explain`)

Off by default so ordinary output stays short.

```
$ hashsmith identify --explain '$krb5tgs$23$*svc_sql$CORP.LOCAL$...'

  Kerberos 5 TGS-REP        certain    -m 13100   krb5tgs   -t krb5tgs
    etype     23 (RC4-HMAC) - the etype most exposed to offline cracking
    user      svc_sql
    realm     CORP.LOCAL
    SPN       MSSQLSvc/db01.corp.local:1433
```

Covers JWT (header/payload decoded, `alg` surfaced, `none` and `HS256` flagged),
PEM (key type, whether encrypted), and the field structure of `$krb5*`,
`$netntlm*` and `$office$` records.

---

## 5. Testing

`crack` regression is the only real risk in this work, and item 1 exists to
make that risk unable to escape review.

### 5.1 Golden cascade test — written first, before any refactor

Run today's `detectHashTypes` over all 502 self-test vectors plus inputs
covering every branch of the cascade, and freeze the output to
`testdata/detect_golden.txt`. The new engine must reproduce that file
**byte for byte, ordering included**. The refactor does not merge until it does.

### 5.2 Prototype integrity test

Walks every prototype and asserts:

- every `Types` entry resolves in `universalHashRegistry`
- `Rationale` is non-empty
- `Display` names are unique
- `Prevalence` is within 0-100

This is the property the rejected data-file approach could not provide.

### 5.3 Recognition accuracy suite

Every format's self-test vector must be identified as its own format at
`certain` or `likely`. Nothing measures this today (§2.5), so the first run
establishes a baseline that is expected to be poor. **The measured number goes
into the implementation plan as-is**, and raising it is part of this
sub-project rather than a claim made in advance.

### 5.4 False-positive suite

Random hex, plain English text, base64 blobs and UUIDs must not produce a
`certain` candidate.

### 5.5 Benchmarks

Single input and a 100,000-line dump, measured against the current
goroutine-per-group implementation.

---

## 6. Out of scope

Deliberately excluded, to keep this sub-project implementable:

- Network lookups against online hash databases
- Cracked-hash lookup (the potfile already covers this)
- A TUI or GUI identification screen
- Chaining identification straight into a crack run - that belongs to
  sub-project C, the attack autopilot, and this design's `Candidate` type is
  the interface it will consume

---

## 7. Acceptance

This sub-project is done when:

1. `testdata/detect_golden.txt` passes unchanged (§5.1).
2. `identify` and `crack` share one engine, with `detectHashTypes` reduced to
   an adapter over it.
3. `identify` emits Hashcat mode, John label, `-t` name and a runnable command
   for every candidate that has them, and `-` for those that do not.
4. `--json` emits `hashsmith.identify/1` and exit codes follow §4.2.
5. Container files route to their extractor (§4.4), with `--coverage`
   reporting the remaining gap honestly.
6. Batch `--summary`, `--split-by-type` and `--unmatched` work over a dump.
7. `--explain` decodes JWT, PEM and the `$krb5*`/`$netntlm*`/`$office$`
   record families.
8. The §5.3 recognition rate is measured, published in the plan, and improved
   against its own baseline.
