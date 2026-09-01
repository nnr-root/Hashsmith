# PRINCE Mode — Design

**Status:** design agreed, implementation pending
**Date:** 2026-09-01

## What PRINCE is

Every mode Hashsmith has takes one word and *mutates* it. PRINCE takes several
words and *concatenates* them, emitting chains roughly shortest-first:

    elements: love, you, 123, dog
      -> loveyou, love123, dogdog, loveyou123, ...

It fills a real gap. `correcthorsebattery` is invisible to a dictionary attack
(not a word) and hopeless for a mask attack (19 characters). PRINCE reaches it in
a few million guesses because it is three common words. As passwords get longer,
this is the mode that keeps finding them.

Hashsmith already has `combinator` (exactly two lists, every pair). PRINCE
generalises it: N elements drawn from one list, chosen so the concatenation lands
in a requested length range.

## Architecture: reuse the `gen` seam

`keyspaceLayout` carries an optional `gen func(int64) string` override; `markov`
and `combinator` both use it. PRINCE is a third:

    princeLayout(elems []string, minLen, maxLen, maxElems int) *keyspaceLayout

This is the whole integration. Because `runLayout` drives a layout purely by
index, PRINCE inherits `--skip`, `--limit`, `--session` resume, checkpointing and
multi-target verification **for free**, with no changes to the runner.

### Cost, stated plainly

Setting `gen` disables the NEON/AVX2 fast path — `fastPathEligible` requires
candidates be mixed-radix decodable from segments. PRINCE therefore runs on the
scalar path. This is not a regression and not worth fighting: PRINCE candidates
are variable-length and word-derived, so they cannot use the fixed-length
transposed batch the vector cores require.

## The generator

1. **Bucket** elements by rune length: `buckets[L]`. Drop elements longer than
   `maxLen` (they can never appear).
2. **Chains.** A chain is a composition of a total length `N` (`minLen..maxLen`)
   into `k` parts (`1..maxElems`), every part having a non-empty bucket.
3. **Count** per chain = product over parts of `len(buckets[L])`.
4. **Order** chains deterministically: `N` ascending, then `k` ascending, then
   lexicographic on the composition. Short, simple candidates first — the
   practical point of PRINCE.
5. **Offsets** = prefix sums of chain counts; `total` = the final sum.
6. **`gen(i)`** = binary-search `i` to its chain, then mixed-radix decode the
   local index across that chain's buckets (last part varying fastest), and
   concatenate.

`gen` is a pure function of `i`. That is the property that makes every slicing
feature work, and it is why PRINCE tiles for distributed runs without any
special handling.

## Hazards

- **Zero-count chains must be omitted from the chain list**, not stored with
  count 0. A zero-width entry makes the index-to-chain search ambiguous, and the
  failure is silent: some indices decode to the wrong chain.
- **Overflow.** Chain counts multiply and then sum. Use the existing saturating
  `satMul`/`satAdd`, and refuse an unknowable total rather than print a wrapped
  one — the discipline `maskKeyspace` already follows. (Note `combinatorLayout`
  currently multiplies unsaturated; worth tightening while nearby.)
- **Memory.** Elements load fully into memory, as `combinator`'s right-hand list
  already does. Cap the element count and refuse past it; never silently
  truncate the list, which would mean candidates never tried.

## Deliberate limits

- **No cross-chain dedup.** `ab`+`c` and `a`+`bc` both yield `abc`. Deduplicating
  globally would cost memory proportional to the keyspace. princeprocessor does
  not dedup by default either; document it rather than pay for it.
- **Rules do not apply to PRINCE output in v1.** hashcat's workflow pipes
  princeprocessor into hashcat and applies rules there. Worth adding later; not
  required for the mode to be useful.
