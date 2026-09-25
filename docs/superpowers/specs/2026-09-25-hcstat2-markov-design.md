# hcstat2-compatible positional Markov — design

## 1. Why this exists

`docs/superpowers/specs/2026-08-31-hashsmith-throughput-and-reach-design.md` §6
scoped Phase 2 ("Reach") as a bundle of hashcat/John parity features. An audit
against current source (2026-09-25) found that bundle almost entirely
shipped already — `--keyspace/--skip/--limit`, `--username/--left/--outfile-format`,
single-crack mode, rule stacking, loopback, and PRINCE all exist with real test
coverage. Two items remain: association attack (`-a 9`, not started, scope
undefined) and **hcstat2-compatible 2nd-order Markov with `--markov-threshold`**,
which this document specs.

This project's own Markov mode (`markov.go`) already exists and works: it
trains a first-order (single-previous-character) model live from a `-w`
wordlist and enumerates candidates most-likely-first via a mixed-radix
odometer plugged into the same resumable `keyspaceLayout` every other attack
mode uses. What it cannot do is load one of the pre-built `.hcstat2` files
hashcat ships and the community trades — large corpora (Have I Been Pwned
dumps, leaked-password aggregates) trained once and reused, carrying far more
signal than any wordlist a single run trains on live. That gap is this
project's actual remaining Markov work; the "1st order → 2nd order" framing
in the original roadmap item undersells what's different — see §3.

## 2. What the format actually is

No public spec exists for `.hcstat2`; this section is the result of reading
`hashcat-utils/src/hcstat2gen.c` and `hashcat/src/mpsp.c` directly, and then
proving the reading was correct: `hcstat2gen.c` was compiled locally, run
against a small sample wordlist, the raw output compressed with
`xz --format=raw --lzma1=preset=9e,lc=1,lp=3,pb=0`, and the result decoded in
Go with `github.com/ulikunitz/xz/lzma` (already a dependency of this
project — used today in `codecs_compression.go` for 7z/lzma archive
extraction). The decoded bytes matched the generator's own raw output
byte-for-byte, including the expected `"hcstat\x00\x02"` magic at the start.

**Container.** A `.hcstat2` file is a *raw* LZMA1 stream — no `.xz` container,
no `.lzma`-alone header, nothing self-describing. hashcat's own reader
hardcodes the LZMA properties byte `0x1c` (`lc=1, lp=3, pb=0`) for every
`.hcstat2` file it reads, so any file it can open was necessarily compressed
with those exact parameters — a bare `-9e` on a modern `xz`/`lzma` build does
**not** reproduce them (verified: modern `xz`'s `-9e` defaults to the
standard `lc=3,lp=0,pb=2`, which does not decode). `golang.org/x/crypto`
carries no raw-LZMA1 decoder, but `github.com/ulikunitz/xz/lzma`'s `Reader`
does, provided a synthetic 13-byte LZMA_ALONE-style header (properties byte +
little-endian dict size + little-endian output size) is prepended in memory,
since the on-disk stream has none of that.

**Layout**, once decompressed — a flat stream of **big-endian uint64s**
(`hcstat2gen.c` byte-swaps every value before `fwrite`, which, combined with
a little-endian host, produces big-endian bytes on disk):

| Offset (u64 index) | Count | Meaning |
|---|---|---|
| 0 | 1 | magic: `"hcstat\x00\x02"` as a big-endian u64 |
| 1 | 1 | zero padding |
| 2 | 65,536 (256×256) | `root[pos][byte]` — count of `byte` appearing at position `pos` |
| 65,538 | 16,777,216 (256×256×256) | `markov[pos][prevByte][nextByte]` — count of `nextByte` following `prevByte` at position `pos` |

Total decompressed size is fixed and known in advance: 134,742,032 bytes.
Position and previous-byte both range over the full 256-value byte space
(0–255), and `pos` ranges 0–255 (`PW_MAX` in the original C).

## 3. Why "positional bigram" is the right frame, not "2nd order"

`markov[pos][prevByte][nextByte]` conditions the next byte on **two**
things — the previous byte *and* the position — which is presumably why the
original roadmap item called it "2nd order." It is not a true 2nd-order
Markov chain in the formal sense (conditioned on the previous *two*
characters); it is a **positional first-order** model. This distinction
matters for the design: this project's *existing* `markovModel` (single
global `cond[prevByte]`, no position-awareness) is exactly what hashcat
itself calls `--markov-classic`. What's missing is positionality plus the
ability to load a real trained table instead of training one live — not a
higher Markov order. `docs/superpowers/specs/2026-08-31-...` used the wrong
name for the right feature; this document uses the correct one.

hashcat additionally supports `--markov-threshold N`: it truncates the
per-node ranked character list to the top `N`, shrinking the effective
keyspace (candidates using the `N+1`th-most-likely byte at some node are
simply never generated). This project adopts the flag and its intent but not
its exact mechanics — see §5 for why.

## 4. Scope

**In scope:**
- Load a real `.hcstat2` file via a new `--hcstat2 <path>` flag on `-a
  markov`, as an alternative to today's `-w <wordlist>` live-training path.
- `--markov-threshold N`, applying uniformly to both the hcstat2 path and
  the existing live-trained path (pure list truncation either way).
- The positional model itself: per-position root ranking, per-(position,
  previous-byte) ranking.

**Out of scope (v1), and why:**
- **`--markov-classic` parity.** This project's existing live `-w`-trained
  mode already IS a classic (position-independent) model; there is nothing
  to add.
- **Custom-charset restriction** (hashcat's `-1`/`?a`-style filtering via
  `uniq_tbls`, applied before ranking). Real value, but a separate,
  independent piece of scope — the mask-charset system in this codebase
  would need to compose with Markov ranking, which today's Markov mode
  (standalone, not mask-combined) does not do at all. Left for a follow-up
  once this lands.
- **Hashcat's exact keyspace-count behavior under threshold.** See §5 — this
  project computes an exact count via a deliberate simplification hashcat
  itself does not make.
- Association attack (`-a 9`) — the other open Phase 2 item, tracked
  separately; unrelated scope.

## 5. Model design

Extend `markovModel` (`markov.go`) with a positional mode as a sibling to the
existing fields, not a replacement — the live `-w`-trained path is unchanged:

```go
type markovModel struct {
    charset    []byte
    threshold  int  // 0 = unlimited (keep the full 256-wide ranking)
    positional bool

    // existing, live -w-trained path (untouched):
    first []byte
    cond  [256][]byte

    // new, hcstat2-loaded path:
    posFirst [256][]byte      // posFirst[pos] = byte ranking at that position
    posCond  [256][256][]byte // posCond[pos][prevByte] = ranking for position pos+1
}
```

**Why every node's ranked list is truncated to a *uniform* `min(threshold,
256)` length, unlike hashcat's per-node variable length:** `markovLayout`'s
`decode(idx, L)` is a mixed-radix odometer — `keyspaceLayout.total` and
direct index→candidate mapping (both required for `--skip`/`--limit`/session
resume, which this project's Markov mode already plugs into via the same
`keyspaceLayout.gen` seam every other attack mode uses) depend on every
position having a *fixed*, known-in-advance radix. hashcat's per-node
variable-length lists (a rare bigram might have fewer than `threshold`
distinct observed successors) make its own keyspace-size a documented
approximation (`sp_get_sum` uses `root_css_buf[i].cs_len` as a stand-in for
every node at position `i`, which is not always exact). This project instead
pads a short list by falling back to that position's `posFirst` ranking, and
if `posFirst` itself falls short (possible at a rarely-reached position —
e.g. position 200 in a corpus of mostly short passwords), pads further with
whichever byte values are still unused, in ascending order — a fixed,
deterministic rule that guarantees every node reaches exactly
`min(threshold, 256)` entries unconditionally, however sparse its training
data. The result: exact `total`, exact direct-index decode, at the cost of
occasionally trying a low-probability (or, at the extreme, arbitrary) byte at
a node with sparse training data — a fully acceptable trade given how much
this project's resumability already leans on the odometer being exact.

`loadHCStat2(path string) (*markovModel, error)` (new file, `hcstat2.go`)
does the decode from §2 and the ranking/truncation/padding from above.
`markovLayout` gains a positional branch in `decode` (reads `posFirst`/
`posCond` instead of `first`/`cond` when `m.positional`); everything else
about the mixed-radix walk is unchanged.

CLI: `-a markov --hcstat2 <path>` in place of `-w <wordlist>` (mutually
exclusive — the mode trains from one or the other, never both);
`--markov-threshold N` accepted alongside either.

## 6. Correctness strategy

- **Decoder**: a small, deterministic `.hcstat2` fixture (built once via
  hashcat-utils' own `hcstat2gen` from a fixed short wordlist, committed
  compressed to `testdata/`) decodes to hand-computable expected root/markov
  counts — checked directly, not just internal self-consistency, per this
  project's established standard for correctness-critical binary parsing.
- **Ranking/threshold/padding**: unit-tested against small synthetic count
  tables directly — no compression involved, fast, exercises the padding
  fallback explicitly (a node engineered to have fewer than `threshold`
  observed successors).
- **`decode`/keyspace invariants**: the same statelessness and
  batch-size-independence checks this project already runs for every other
  keyspace generator and lane hasher — `decode(i)` is a pure function of
  `i`, and `--skip`/`--limit` land on the same candidates sequential
  enumeration from 0 would reach.
- **End-to-end**: load the committed fixture, crack a target hashed from a
  password known to be in the fixture's training wordlist, confirm it's
  found — and found at a lower keyspace index than plain brute force would
  reach it, as a sanity check that ranking is doing real work, not just
  passing through.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Getting the raw-LZMA1 properties/header wrong silently produces garbage, not an error | Already de-risked: decode path validated against a real, independently-built fixture before this spec was written (§2), not assumed from documentation alone |
| A real-world `.hcstat2` file (e.g. hashcat's own shipped default) was built with different LZMA parameters than `0x1c` | hashcat's own reader hardcodes `0x1c` for every file it accepts — if a file doesn't match, hashcat itself cannot read it either. Loader must still surface a clear decompression error (not a silent garbage decode) if a file fails |
| Uniform-radix padding changes candidate ORDER at sparse nodes relative to true hashcat behavior | Documented as a deliberate, disclosed simplification (§5), not a bug; exactness of resumability was judged worth more than exact hashcat parity, since the mode's job (surface likely passwords earlier) still holds |
| 134 MB decompressed table per loaded model | In-memory only, one model per run, same order of magnitude as this project's other bulk-data structures (wordlist slices) — no new concern |

## 8. Non-goals

- Custom-charset (`-1`/`?a`) restriction before ranking.
- `--markov-classic`/`--markov-inverse` flag parity (classic is already this
  project's live-trained mode; inverse has no identified use case here).
- Mask-attack integration (`?1?2?3?4` combined with Markov ranking) — this
  project's Markov mode is, and remains, a standalone attack mode.
- Bit-for-bit parity with hashcat's approximate keyspace-count-under-threshold
  behavior.
