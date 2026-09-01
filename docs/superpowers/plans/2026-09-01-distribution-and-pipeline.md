# Distribution and Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Hashsmith usable in the workflows people actually run — split a job across machines, and fit into a pipeline of other tools.

**Architecture:** Three small, independent slices. Distribution flags (`--keyspace`, `--skip`, `--limit`) ride on machinery that already exists: `runLayout` takes `resumeFrom int64` and `keyspaceLayout` already computes `total`. Pipeline flags (`--username`, `--left`, `--outfile-format`) are I/O plumbing around the existing crack loop. Loopback re-feeds cracked plaintexts as candidates.

**Tech Stack:** Go 1.25+, existing `keyspaceLayout` / `runLayout` / potfile code. No new dependencies.

## Why this, and why now

Every throughput number this project has produced applies to **one machine, one core count**. Hashsmith currently **cannot split a job across two machines at all** — there is no `--keyspace`, no `--skip`, no `--limit`. Every serious cracking setup, from a two-laptop pair to a rented farm, works by dividing the keyspace and handing each worker a slice. A 4x core speedup helps one box; distribution multiplies whatever speed you have by the number of boxes you own.

It is also the cheapest work in the roadmap. `runLayout(ctx, l, resumeFrom, ...)` already starts at an arbitrary index, and `keyspaceLayout.total` is already the number `--keyspace` needs to print. The engine was built for this; nothing exposes it.

## Global Constraints

- **No cgo.** `CGO_ENABLED=0 go build` must keep working.
- **Cross-compilation** for linux/amd64, linux/arm64, windows/amd64, darwin/arm64 — each must BUILD and PASS the suite.
- **No format's observable result may change.** No existing flag may change meaning.
- All work in `hashsmith/go_hashsmith/cmd/hashsmith/` (package `main`), one flat package. No subpackages.
- Test command: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith`
- **Keyspace arithmetic saturates rather than overflowing** (`satMul`/`satAdd` in `mask.go`). A `?a`x10 mask genuinely exceeds int64; `--keyspace` must report that honestly rather than printing a wrapped number.

## The correctness property that matters

**A split run must cover exactly the same candidates as an unsplit one — no gaps, no repeats.** If `--skip A --limit B` slices are unioned across machines, every candidate must be tried exactly once. That is the whole point, and it is the one property whose failure is invisible: a gap means a password that was never tried but was reported "not found".

Every task below is tested against that property directly, not by proxy.

---

## Task 1: `--keyspace`, `--skip`, `--limit`

**Files:**
- Modify: `crack.go` (flag definitions, wiring), `keyspace.go` (bounded runs)
- Test: `distribution_test.go` (new)

**Interfaces:**
- Produces:
  - `--keyspace` — print the layout's total candidate count and exit 0, running no attack
  - `--skip N` — begin at candidate index N
  - `--limit N` — try at most N candidates, then stop and report not-found
  - `runLayoutBounded(...)` or an equivalent `limit` parameter threaded into the existing runners

**Semantics, to match hashcat so existing scripts port:**
- `--skip` and `--limit` are candidate indices into the *whole* layout, across all segments.
- `--limit` is a count, not an end index. `--skip 100 --limit 50` tries candidates 100..149.
- Both apply to brute, mask and hybrid layouts. For a dictionary attack they apply to word indices.
- `--keyspace` prints one integer to stdout and nothing else, so `$(hashsmith --keyspace ...)` works in a shell.
- When the true keyspace exceeds int64, `--keyspace` must say so on stderr and exit non-zero rather than printing a saturated value a script would then divide.

- [ ] **Step 1: Write the failing test**

```go
// The union of disjoint --skip/--limit slices must cover the whole keyspace
// exactly once: no candidate tried twice, none missed. A gap here means a
// password that was never tried but was reported "not found".
func TestSkipLimitSlicesTileTheKeyspace(t *testing.T) {
	l := bruteLayout("abc", 1, 3) // 3 + 9 + 27 = 39
	const slices = 4
	sliceSize := (l.total + slices - 1) / slices

	seen := map[string]int{}
	for s := int64(0); s < slices; s++ {
		skip := s * sliceSize
		if skip >= l.total {
			break
		}
		limit := sliceSize
		var attempts int64
		collect(t, l, skip, limit, &attempts, func(c string) { seen[c]++ })
	}

	if len(seen) != int(l.total) {
		t.Errorf("slices covered %d distinct candidates, want %d", len(seen), l.total)
	}
	for cand, n := range seen {
		if n != 1 {
			t.Errorf("candidate %q tried %d times, want exactly 1", cand, n)
		}
	}
	// And the union must equal the unsplit enumeration, not merely match in count.
	for i := int64(0); i < l.total; i++ {
		if _, ok := seen[l.candidate(i)]; !ok {
			t.Errorf("candidate %q (index %d) was never tried", l.candidate(i), i)
		}
	}
}

// --limit must bound the work actually done, not just the reported total.
func TestLimitStopsEarly(t *testing.T) {
	l := bruteLayout("abcdefghij", 5, 5) // 100,000
	var attempts int64
	collect(t, l, 0, 250, &attempts, func(string) {})
	if attempts > 250+int64(runtime.NumCPU()*keyspaceChunk) {
		t.Errorf("attempts = %d, expected close to the 250 limit", attempts)
	}
	if attempts < 250 {
		t.Errorf("attempts = %d, fewer than the 250 requested", attempts)
	}
}

// --skip past the end is a no-op, not an error or a panic.
func TestSkipBeyondKeyspace(t *testing.T) {
	l := bruteLayout("ab", 1, 2) // 6
	var attempts int64
	n := 0
	collect(t, l, 999, 10, &attempts, func(string) { n++ })
	if n != 0 {
		t.Errorf("tried %d candidates past the end of the keyspace, want 0", n)
	}
}
```

Write `collect` as a small helper that runs the bounded layout single-threaded and calls back per candidate, so the test asserts on the candidate stream itself rather than on timing.

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run 'TestSkipLimit|TestLimitStops|TestSkipBeyond' ./cmd/hashsmith`
Expected: compile failure — the bounded runner does not exist yet.

- [ ] **Step 3: Implement**

Thread a `limit int64` (0 = unbounded) alongside the existing `resumeFrom` through the layout runners. The chunk allocator already hands out `[start, end)` ranges; clamp `end` to `resumeFrom + limit` when a limit is set. Add the three flags in `crack.go` and route `--keyspace` to print `layout.total` and return before any attack starts.

**Do not restructure `runLayout` or `runLayoutFast` beyond adding the bound.** Their chunk allocator, watermark, attempt accounting, cancellation, segment-boundary resets and the `i < used` hit-detection bound are adversarially reviewed.

- [ ] **Step 4: Verify, including the real CLI**

```bash
cd hashsmith/go_hashsmith && go build -o /tmp/hs ./cmd/hashsmith
# --keyspace is machine-readable
K=$(/tmp/hs crack -t md5 -M brute -C abc -n 1 -x 3 --keyspace deadbeef -N); echo "keyspace=$K"  # want 39
# a two-way split finds a password in whichever half holds it
H=$(/tmp/hs hash -t md5 cab -N | tail -1)
/tmp/hs crack -t md5 -M brute -C abc -n 1 -x 3 --skip 0  --limit 20 "$H" -N --no-pot 2>&1 | grep -oE 'Found: .*|Not found'
/tmp/hs crack -t md5 -M brute -C abc -n 1 -x 3 --skip 20 --limit 20 "$H" -N --no-pot 2>&1 | grep -oE 'Found: .*|Not found'
# exactly one of those two must say Found
# an oversized keyspace must refuse rather than print a saturated number
/tmp/hs crack -t md5 -M mask --mask '?a?a?a?a?a?a?a?a?a?a' --keyspace deadbeef -N; echo "exit=$?"
```

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/
git commit -m "feat: --keyspace, --skip and --limit for distributed cracking

Hashsmith could not split a job across machines at all. The engine was
already built for it — runLayout takes resumeFrom and keyspaceLayout
computes total — but nothing exposed it.

Semantics follow hashcat so existing scripts port: skip and limit are
candidate indices across the whole layout, limit is a count rather than
an end index, and --keyspace prints one integer to stdout so it can be
used in a shell substitution. A keyspace exceeding int64 is refused
rather than printed saturated, since a script would divide the result."
```

---

## Task 2: `--username`, `--left`, `--outfile-format`

**Files:** Modify `crack.go`, `pot.go`; test `pipeline_test.go` (new)

- `--username` — accept `user:hash` input lines, carry the username alongside each target, and print it with results. Required groundwork for single-crack mode.
- `--left` — write the still-uncracked targets to stdout (or `-o`), in the input's original form, so a second pass can consume them.
- `--outfile-format` — hashcat's numbered field selection for `-o` output.

The correctness property: `--left` output re-fed as input must produce the same set of targets, so a pipeline can iterate without losing or duplicating work. Test that round trip directly.

---

## Task 3: Loopback

**Files:** Modify `crack.go`; test `loopback_test.go` (new)

Feed successfully cracked plaintexts back as candidates within the same run. Nearly free, and high yield on corpora where people reuse passwords with small variations. Depends on Task 2's plaintext bookkeeping.

---

## Deferred: single-crack mode

JtR's highest-yield mode on real engagements — per-hash candidates derived from that account's own username and GECOS. It depends on `--username` from Task 2 and deserves its own plan, since the candidate-generation model differs fundamentally from every mode Hashsmith has today: candidates are *per target* rather than shared across all of them, which the current runner assumes.

---

## Self-Review Notes

**Coverage:** distribution (Task 1), pipeline I/O (Task 2), loopback (Task 3). Single-crack deferred with its reason.

**The property under test throughout:** a split run covers exactly the candidates an unsplit run does. Task 1 tests it by tiling the keyspace and asserting each candidate appears exactly once — including the union-equals-whole check, since matching counts alone would pass a scheme that both skipped and duplicated.

**Deliberate scope limits:**
- `--skip`/`--limit` for dictionary attacks operate on word indices, not byte offsets.
- No brain/cluster coordination — the flags let an external scheduler split work; Hashsmith does not become one.
