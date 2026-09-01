# Single-Crack Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add John the Ripper's highest-yield attack mode — candidates derived from each account's own identity, tried only against that account's hash.

**Architecture:** Single-crack inverts the assumption every other mode makes. Brute, mask and dictionary all generate one candidate stream shared by every target; single-crack generates a *different, tiny* stream per target. That sounds invasive, but three pieces already exist: a per-target crack path (salted and expensive types already run that way), `usernameFor()` (added with `--username`), and the rule engine. The work is mostly plumbing, not new machinery.

**Tech Stack:** Go 1.25+, existing rule engine and per-target crack loop. No new dependencies.

## Why this is worth building

On real engagements, single-crack out-cracks raw speed. People pick passwords derived from their own login and name — `jsmith`, `Jsmith1`, `jsmith2024!` — and no amount of keyspace throughput finds those faster than simply trying them first. It is also *cheap*: a handful of seeds per target, times a rule set, against one hash. Where a mask attack burns billions of candidates against every target, single-crack burns dozens against one.

This is the last major capability gap against JtR.

## Scope, and what is deliberately deferred

**In scope: username-derived candidates.** For each target carrying a username, seed from the login name and run it through the rule engine.

**Deferred: GECOS.** JtR also mines the full-name field — "John Smith" yielding `jsmith`, `johns`, `smithj`. Hashsmith cannot do this yet for a concrete reason: `shadow2smith` emits `user:hash` and **discards GECOS**. It reads `/etc/passwd` only to merge and filter accounts (`extract_shadow.go:69`), never carrying the name field through. Supporting it means changing the extractor's output format and every consumer of it — a larger change than this plan, and one that should be designed on its own rather than bolted on here. Task 3 records what it would take.

Username-only still captures the bulk of the yield, since login-derived passwords are the common case.

## Global Constraints

- **No cgo.** `CGO_ENABLED=0 go build` must keep working.
- **Cross-compilation** for linux/amd64, linux/arm64, windows/amd64, darwin/arm64 — each must BUILD and PASS the suite.
- **No format's observable result may change, and no existing flag may change meaning.**
- One flat `package main` in `hashsmith/go_hashsmith/cmd/hashsmith/`. No subpackages.
- **`--show` must never attack.** A bug that violated this was fixed recently; single-crack adds new attack paths and must not reintroduce it.
- Test command: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith`

## The property that matters

**A single-crack candidate must only ever be tried against the target it was derived from.** Cross-contamination — trying account A's seeds against account B's hash — would be wrong in a subtle and expensive way: it silently multiplies work by N targets, and worse, a "hit" attributed to the wrong account is a wrong answer of the kind that looks like a success. Test this directly.

---

## Task 1: Per-target seed generation and `--single`

**Files:**
- Create: `single.go`, `single_test.go`
- Modify: `crack.go` (flag, wiring)

**Interfaces:**
- Produces:
  - `singleSeeds(username string) []string` — the seed set for one account, before rules
  - `--single` flag: run single-crack before (or instead of) the main attack

**Seed set** — derive from the login name only, letting the rule engine do the mutation rather than hardcoding variants:
- the username verbatim (`jsmith`)
- case variants the rule engine will not produce on its own if it is not enabled: lower, upper, capitalised
- the username split on common separators (`.`, `_`, `-`, digits), so `john.smith` also yields `john` and `smith`
- the username reversed only if the rule set is not doing it

Keep the seed list SMALL and let `--rules`/`-r` expand it. The point is a per-target set of dozens, not thousands.

- [ ] **Step 1: Write the failing test**

```go
// Seeds must derive from the login name, including its components, so
// "john.smith" reaches both halves — a very common password base.
func TestSingleSeedsFromUsername(t *testing.T) {
	got := map[string]bool{}
	for _, s := range singleSeeds("john.smith") {
		got[s] = true
	}
	for _, want := range []string{"john.smith", "john", "smith", "John.smith", "JOHN.SMITH"} {
		if !got[want] {
			t.Errorf("seeds for john.smith missing %q (got %v)", want, keys(got))
		}
	}
}

// An empty or absent username must yield no seeds rather than a seed of "" —
// an empty candidate would be tried against every target for no reason.
func TestSingleSeedsEmptyUsername(t *testing.T) {
	if s := singleSeeds(""); len(s) != 0 {
		t.Errorf("empty username produced %d seeds, want 0: %v", len(s), s)
	}
}

// THE PROPERTY THAT MATTERS: a seed derived from one account must never be
// tried against another account's hash. Cross-contamination multiplies work by
// N and, worse, can attribute a hit to the wrong account.
func TestSingleCrackDoesNotCrossContaminate(t *testing.T) {
	// Two accounts. alice's password IS bob's username — so if seeds leak
	// across targets, alice's hash cracks from bob's seed and the bug shows.
	// With correct isolation, alice's hash must NOT be cracked by single mode.
	// (Build the two targets, run single-crack, assert alice is uncracked and
	// bob is cracked from his own seed.)
}
```

Write the third test concretely — it is the one that matters most.

- [ ] **Step 2: Run to verify it fails.** `go test -run TestSingle ./cmd/hashsmith` — expect `undefined: singleSeeds`.

- [ ] **Step 3: Implement.** Add `singleSeeds`, the `--single` flag, and per-target wiring. Reuse the existing per-target crack path rather than building a new runner: for each target with a username, build its seed list, feed it as a dict source with the active rule engine, and attack only that target.

- [ ] **Step 4: Verify**

```bash
cd hashsmith/go_hashsmith
go test -count=1 -timeout 400s ./cmd/hashsmith
GOARCH=amd64 GOOS=darwin go test -count=1 -timeout 500s ./cmd/hashsmith
go test -race -count=1 -timeout 900s -run 'TestSingle|TestUsername|TestLeft|TestShow' ./cmd/hashsmith
go vet ./cmd/hashsmith
for t in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/hashsmith; done
```

Plus a live demonstration: a `user:hash` file where one account's password is a rule-mutation of its own login, cracked by `--single -r` and NOT by the same run without `--single`. Include the output.

- [ ] **Step 5: Commit.**

---

## Task 2: Interactions

`--single` must compose with what already exists:
- **`--show`** must run no single-crack passes (its contract is that it never attacks).
- **`--left`** must reflect single-crack results — an account cracked by single mode is not left.
- **`--loopback`** should feed on single-crack's recoveries too; they are exactly the kind of plaintext that mutates well.
- **`--skip`/`--limit`** bound the main attack's keyspace; single-crack is a different candidate source, so state the decision explicitly as loopback did.
- **`--username` is a prerequisite** — without it there are no usernames to seed from. Decide whether `--single` implies it or errors without it, and make that explicit rather than silently producing zero seeds.

---

## Task 3: Record what GECOS would take

No code. Write up, in the measurements/notes directory, what supporting GECOS requires: `shadow2smith` currently emits `user:hash` and discards the name field (`extract_shadow.go`), so it would need an output format carrying it, plus consumers that parse it, plus a decision about whether that format stays compatible with hashcat's `user:hash`. This is the difference between username-only single-crack and JtR's full version, and the next person should not have to rediscover it.

---

## Self-Review Notes

**Coverage:** seed generation and `--single` (Task 1), composition with existing flags (Task 2), GECOS scoping (Task 3).

**The property under test:** a seed derived from one account is never tried against another. Task 1's third test is built so that a leak *cracks something it should not*, which makes the failure visible rather than merely inefficient.

**Deliberate limits:**
- Username-only; GECOS deferred with its reason recorded rather than silently omitted.
- Seeds stay small by design — the rule engine does the expansion, so `--single -r` is the intended usage.
