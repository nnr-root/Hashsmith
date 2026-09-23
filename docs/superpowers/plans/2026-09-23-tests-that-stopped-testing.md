# Four tests that stopped testing what they named

*2026-09-23. Written because the same failure appeared four times in one day,
in four unrelated subsystems, and I only recognised it as a pattern on the
third.*

## The shape

An assertion rests on a value. The value later moves. The assertion keeps
passing, and now proves nothing.

Nothing fails. No warning appears. The test is still green, still named after
the property it no longer checks, and a reader has no way to tell from the
outside. In three of the four cases below the comment above the test stated the
premise explicitly — which is exactly what made them findable in hindsight and
useless in practice, because **a comment cannot hold an invariant that depends
on a measurement.**

## The four

### 1. john.conf has two comment markers

`TestJohnCorpusCoverageDoesNotRegress` measures how much of John's own rule
corpus Hashsmith can compile, against a 98% floor. It stripped lines beginning
`#`.

John's `doc/CONFIG` says: *"Comment lines start with a hash character ("#") or a
semicolon (";") and are ignored."* Commented-out rules beginning `;` were being
counted as rules and then failing to compile, for the excellent reason that
`;-c T1 Q M T0 Q` is not a rule.

It measured 98.4% on macOS and 90.5% on Ubuntu — because Homebrew's john.conf
keeps its `;`-commented rules outside the `[List.Rules:...]` sections the walk
reads, and Debian's keeps them inside. The number was about the file's comment
style, not about this project.

**Second failure, compounding the first:** the CI step meant to run this test
named a package containing no tests. `go test -run` with a filter that matches
nothing exits 0. The test had not run in CI at all.

*Fix:* strip both markers; extract the classification into a named function;
test it against a file shaped like Debian's, which is the layout no Mac has to
hand.

### 2. A differential test comparing one path with itself

The dictionary vector path shipped with a differential test: for each type,
crack once with the batched core and once with `HASHSMITH_NO_FASTPATH=1`, and
require the same verdict.

sha1 was in the list. sha1 has no vector plan. So both halves of the comparison
ran the same scalar code and agreed trivially. A green subtest asserting
nothing, for a whole commit.

*Fix:* a non-vacuity guard that skips loudly when no batched core resolves, and
`TestDictLaneCoverage`, which asserts which core each type resolves to —
including that some resolve to none, so the assertion cannot become vacuous by
everything qualifying.

Finding it is also what prompted wiring sha1/sha256, then sha224/384/512, then
the UTF-16 constructions to the contiguous core: the test had been hiding the
gap it existed to expose.

### 3. n=1600 stopped spanning batches

`TestDictAttackLanesMultiBatchConcurrent` exists — in its own comment — to
"force multiple batches and four workers so more than one worker's lh.Run
genuinely runs at once". It wrote `const n = 1600` and planted the needle at
positions `{0, 512, 1024, n-1}`, with the comment "n=1600 spans four: 512, 512,
512, 64".

Raising `dictBatchSize` from 512 to 4096 — measured, +8.2% — made those 1600
words a single batch. The test still passed. It no longer exercised concurrency
at all.

*Fix:* derive `n` and the boundaries from `dictBatchSize`. The test follows the
constant instead of falling behind it.

### 4. The premise that a correct fix invalidated

This is the instructive one, because nothing was wrong except the interaction.

The feasibility guard has two tiers. Tier one estimates `work / (workers/perOp)`
from a scalar verify and answers whenever that lands under 60 seconds. Tier two
probes the real dispatch. Two tests assert tier two's accuracy to within 4x, and
both say in their comments that they sized their keyspace at 26^6 *specifically*
so tier one could not resolve it — one of them recording that a mutation had
slipped through at 26^5 for exactly this reason.

Earlier the same day I fixed a real defect: `perOp` was being read from a single
cold call and came out at ~2µs against a true ~650ns. Correct fix, measured,
tested.

And `perOp` is the denominator of tier one's estimate. Improving it dropped the
estimate for 26^6 from ~154s to ~53s, **under** the ceiling. The runs moved out
of tier two into tier one, which models a scalar verify and cannot see a vector
core, so it is ~20x pessimistic for those types. The tests began comparing a
cheap scalar estimate against a vector-cored run and measuring the gap between
them.

*Fix:* `requireTierTwo` recomputes tier one's decision the way `feasibilityRate`
does and fails with the measured numbers and the remedy when the premise no
longer holds. Mutation-checked.

## What actually helps

**Assert the premise, do not describe it.** Every fix above replaced a sentence
with a check. `requireTierTwo`, `TestDictLaneCoverage`, the non-vacuity guards,
`n` derived from `dictBatchSize`. Each is a few lines and each converts a silent
failure into a loud one.

**A differential test needs a third assertion.** "A equals B" is worthless if A
and B can become the same code. It needs "and A and B are genuinely different
paths" alongside.

**A filter that matches nothing must not be silent.** `go test -run NoSuchTest`
exits 0. So does a CI step naming the wrong package. Both failures in §1 were
this.

**Suspect your own recent correct changes.** §4 was caused by a fix that was
right in isolation. When a test fails shortly after unrelated work, the
coupling is more likely than coincidence.

**Keep a control.** Several measurements today were only trustworthy because
something was expected NOT to move: sha512 before it gained a core, ripemd160
and blake2b after. A benchmark where everything improves is a benchmark that may
be measuring the machine.

## Related

- The measurement discipline these sit alongside — paired ratios, deterministic
  allocation counts, and four failed attempts at `dictBatchSize` before an idle
  machine gave a signal — is recorded in
  `2026-09-20-beating-john-and-hashcat.md` §4.1 and §4.2.
- `descrypt_bitslice_test.go` is the same instinct applied to a decision rather
  than a test: bitslicing was measured and declined, with the measurement kept
  so the question is not re-litigated from scratch.
