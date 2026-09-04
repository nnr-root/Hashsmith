# Unified Identification Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `hashsmith identify` and `hashsmith crack` share one detection engine, and turn `identify` into the most capable hash identification tool available.

**Architecture:** A new `internal/hashid` package owns the detection *engine* — the `Prototype` type, table evaluation, suppression, and the confidence model — and knows nothing about any specific format. `cmd/hashsmith` owns the *table*, whose entries close over the ~185 format predicates that already live beside their formats' cracking code. `detectHashTypes` becomes an adapter over the engine, and its behaviour is frozen byte-for-byte by a golden test written before any code moves.

**Tech Stack:** Go 1.25, standard library only. Module `hashsmith-go`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-04-unified-identification-design.md` (read it first; §3.1 carries an amendment made during planning)

## Global Constraints

- Module is `hashsmith-go`; all paths below are relative to `hashsmith/go_hashsmith/`.
- Go 1.25.0 (`go.mod`). No new third-party dependencies — standard library only.
- Default build must stay pure Go with `CGO_ENABLED=0`. Nothing here may introduce cgo.
- `internal/hashid` must never import `cmd/hashsmith` and must never reference a format predicate, a Hashcat mode, or a John label.
- `testdata/detect_golden.txt` is authoritative. If a change alters it, the change is wrong unless the plan explicitly says otherwise (only Task 15 may extend it, never rewrite it).
- Full test suite is `go test ./... -count=1`, currently ~23s. Run it before every commit.
- Every `Prototype` must carry a non-empty `Rationale`. This is enforced by a test, not by review.
- Existing exit-code contract for `crack` is `0` = all cracked, `1` = some not, `2` = error. `identify`'s new codes must not conflict.

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `internal/hashid/hashid.go` | `Tier`, `Prototype`, `Input`, `Evidence`, `Match`, `Candidate` types |
| `internal/hashid/evaluate.go` | Table evaluation + the suppression rule |
| `internal/hashid/confidence.go` | Tier + prevalence + negative evidence → confidence |
| `internal/hashid/evaluate_test.go` | Engine tests over small synthetic tables |
| `internal/hashid/confidence_test.go` | Confidence model tests |
| `cmd/hashsmith/prototypes.go` | The prototype table: shared/structural entries |
| `cmd/hashsmith/prototypes_records.go` | Prototype entries for `$`-prefixed record formats |
| `cmd/hashsmith/prototypes_shape.go` | Non-exclusive length/alphabet prototypes + `Against` predicates |
| `cmd/hashsmith/prototypes_test.go` | Integrity test: names resolve, rationales present, displays unique |
| `cmd/hashsmith/identify_output.go` | Human + JSON rendering for `identify` |
| `cmd/hashsmith/identify_explain.go` | `--explain` record decoding |
| `cmd/hashsmith/identify_batch.go` | `--summary`, `--split-by-type`, `--unmatched` |
| `cmd/hashsmith/sniff.go` | Container `Sniff` implementations |
| `cmd/hashsmith/testdata/detect_golden.txt` | Frozen `detectHashTypes` output |
| `cmd/hashsmith/detect_golden_test.go` | Golden comparison |
| `cmd/hashsmith/recognition_test.go` | Recognition accuracy + false-positive suites |

**Modified:**

| Path | Change |
|---|---|
| `cmd/hashsmith/identify.go:1444-2081` | Cascade progressively emptied, then deleted |
| `cmd/hashsmith/identify.go:63-190` | `runIdentify` gains flags and new rendering |
| `cmd/hashsmith/identify.go:191-1030` | `scoreCandidates` and its four scoring groups replaced |
| `cmd/hashsmith/hash_extra.go:62+` | Alias provenance tagging |
| `cmd/hashsmith/hash_registry.go:37-105` | Reverse lookup for Hashcat mode / John label |
| `cmd/hashsmith/extractor_registry.go:12-19` | `Sniff` field on `extractorDefinition` |
| `cmd/hashsmith/main.go:86-89,160-190` | `identify` flags in dispatch and help |
| `README.md:930-1010` | Comparison table and identify documentation |

---

## Task 1: Freeze today's detection behaviour

Nothing else in this plan is safe until this exists. It captures the current
`detectHashTypes` output so every later task can prove it did not change it.

**Files:**
- Create: `cmd/hashsmith/detect_golden_test.go`
- Create: `cmd/hashsmith/testdata/detect_golden.txt` (generated, then committed)

**Interfaces:**
- Consumes: `detectHashTypes(string) []string`, `universalHashRegistry.vectors` (`[]selfTestVector`, fields `typ`, `password`, `salt`, `target`, `source`)
- Produces: `goldenDetectInputs() []string` — the frozen input corpus, reused by Tasks 4-10 and 15

- [ ] **Step 1: Write the golden test and its input corpus**

Create `cmd/hashsmith/detect_golden_test.go`:

```go
package main

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// goldenDetectInputs is the frozen corpus that pins detectHashTypes' behaviour.
// It is every self-test vector's ciphertext plus hand-written inputs covering
// cascade branches no vector reaches. Entries are never removed; new ones are
// appended, which appends to the golden file rather than rewriting it.
func goldenDetectInputs() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, v := range universalHashRegistry.vectors {
		add(v.target)
	}
	for _, s := range goldenExtraInputs {
		add(s)
	}
	sort.Strings(out)
	return out
}

// goldenExtraInputs covers shapes the vector corpus does not reach: the
// trailing length-switch fallback, shadow-line peeling, encoded inputs, and
// the ambiguity groups whose ORDER is the thing most at risk in a refactor.
var goldenExtraInputs = []string{
	"5f4dcc3b5aa765d61d8327deb882cf99",
	"5F4DCC3B5AA765D61D8327DEB882CF99",
	"aad3b435b51404eeaad3b435b51404ee",
	"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	"0123456789abcdef",
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef",
	"root:$6$salt$hash",
	"user:5f4dcc3b5aa765d61d8327deb882cf99",
	"not a hash at all",
	"",
	"deadbeef:cafebabe",
	"deadbeefdeadbeef:cafebabecafebabe",
}

func TestDetectHashTypesGolden(t *testing.T) {
	var sb strings.Builder
	for _, in := range goldenDetectInputs() {
		sb.WriteString(in)
		sb.WriteString("\t")
		sb.WriteString(strings.Join(detectHashTypes(in), ","))
		sb.WriteString("\n")
	}
	got := sb.String()

	const path = "testdata/detect_golden.txt"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden file written")
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with UPDATE_GOLDEN=1)", err)
	}
	if got != string(want) {
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("detection changed at line %d\n  golden: %s\n  now:    %s",
					i+1, wantLines[i], gotLines[i])
			}
		}
		t.Fatalf("golden has %d lines, output has %d", len(wantLines), len(gotLines))
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd hashsmith/go_hashsmith
go test ./cmd/hashsmith -run TestDetectHashTypesGolden -count=1
```

Expected: FAIL with `read golden: open testdata/detect_golden.txt: no such file or directory`.

- [ ] **Step 3: Generate the golden file**

```bash
cd hashsmith/go_hashsmith
UPDATE_GOLDEN=1 go test ./cmd/hashsmith -run TestDetectHashTypesGolden -count=1
wc -l cmd/hashsmith/testdata/detect_golden.txt
```

Expected: over 500 lines. Open it and read 20 lines at random to confirm each is `<input>\t<comma-separated types>` and the types look right for the input. If any line's types are empty for an input that is obviously a hash, **stop and report it** — that is a pre-existing detection gap and Task 15 needs to know about it.

- [ ] **Step 4: Run it to verify it now passes**

```bash
go test ./cmd/hashsmith -run TestDetectHashTypesGolden -count=1
```

Expected: PASS.

- [ ] **Step 5: Prove the golden file actually catches a regression**

Temporarily break detection to confirm the net has holes in the right places:

```bash
cd hashsmith/go_hashsmith
sed -i.bak 's/return \[\]string{"md5", "md4", "md2", "ntlm", "lm"}/return []string{"md5"}/' cmd/hashsmith/identify.go
go test ./cmd/hashsmith -run TestDetectHashTypesGolden -count=1
```

Expected: FAIL, naming the changed line. Then restore:

```bash
mv cmd/hashsmith/identify.go.bak cmd/hashsmith/identify.go
go test ./cmd/hashsmith -run TestDetectHashTypesGolden -count=1
```

Expected: PASS. A safety net that has not been shown to catch anything is not a safety net.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/detect_golden_test.go cmd/hashsmith/testdata/detect_golden.txt
git commit -m "test: freeze detectHashTypes output before the identification refactor"
```

---

## Task 2: The engine — types, evaluation, suppression

**Files:**
- Create: `internal/hashid/hashid.go`
- Create: `internal/hashid/evaluate.go`
- Create: `internal/hashid/evaluate_test.go`

**Interfaces:**
- Consumes: nothing (leaf package, standard library only)
- Produces:
  - `type Tier uint8` with `TierChecksum`, `TierSignature`, `TierStructural`, `TierShape`
  - `type Input struct { Raw, Normalized string }`
  - `type Evidence string`
  - `type Prototype struct { Types []string; Display string; Tier Tier; Exclusive bool; Match func(Input) (Evidence, bool); Against func(Input) (string, bool); Prevalence uint8; Rationale string }`
  - `type Match struct { Proto *Prototype; Evidence Evidence; Suppressed bool }`
  - `func Evaluate(table []Prototype, in Input) []Match`
  - `func DetectTypes(table []Prototype, in Input) []string`

- [ ] **Step 1: Write the failing tests**

Create `internal/hashid/evaluate_test.go`:

```go
package hashid

import (
	"reflect"
	"testing"
)

func always(e Evidence) func(Input) (Evidence, bool) {
	return func(Input) (Evidence, bool) { return e, true }
}

func never() func(Input) (Evidence, bool) {
	return func(Input) (Evidence, bool) { return "", false }
}

// The cascade's defining property: the first exclusive match wins outright and
// every later prototype is dropped from what crack sees.
func TestFirstExclusiveMatchWinsOutright(t *testing.T) {
	table := []Prototype{
		{Types: []string{"a"}, Display: "A", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
		{Types: []string{"b", "b2"}, Display: "B", Tier: TierSignature, Exclusive: true,
			Match: always("hit b"), Rationale: "x"},
		{Types: []string{"c"}, Display: "C", Tier: TierSignature, Exclusive: true,
			Match: always("hit c"), Rationale: "x"},
		{Types: []string{"d"}, Display: "D", Tier: TierShape, Exclusive: false,
			Match: always("hit d"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "irrelevant"})
	want := []string{"b", "b2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DetectTypes = %v, want %v", got, want)
	}
}

// Identify still gets to see what was ruled out; crack never does.
func TestSuppressedMatchesAreReportedNotDropped(t *testing.T) {
	table := []Prototype{
		{Types: []string{"b"}, Display: "B", Tier: TierSignature, Exclusive: true,
			Match: always("hit b"), Rationale: "x"},
		{Types: []string{"c"}, Display: "C", Tier: TierShape, Exclusive: false,
			Match: always("hit c"), Rationale: "x"},
	}
	ms := Evaluate(table, Input{Normalized: "irrelevant"})
	if len(ms) != 2 {
		t.Fatalf("Evaluate returned %d matches, want 2", len(ms))
	}
	if ms[0].Suppressed {
		t.Error("winning match must not be marked suppressed")
	}
	if !ms[1].Suppressed {
		t.Error("match after an exclusive winner must be marked suppressed")
	}
}

// With no exclusive match, every non-exclusive match is returned in table
// order — this is today's trailing `switch len(t)` behaviour.
func TestNoExclusiveMatchReturnsEveryShapeMatch(t *testing.T) {
	table := []Prototype{
		{Types: []string{"a"}, Display: "A", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
		{Types: []string{"md5"}, Display: "MD5", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
		{Types: []string{"ntlm"}, Display: "NTLM", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	want := []string{"md5", "ntlm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DetectTypes = %v, want %v", got, want)
	}
}

func TestNoMatchReturnsNil(t *testing.T) {
	table := []Prototype{
		{Types: []string{"a"}, Display: "A", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
	}
	if got := DetectTypes(table, Input{Normalized: "zzz"}); got != nil {
		t.Fatalf("DetectTypes = %v, want nil", got)
	}
}

// Duplicate -t names across prototypes must not produce duplicate candidates
// for crack to try twice.
func TestDetectTypesDeduplicates(t *testing.T) {
	table := []Prototype{
		{Types: []string{"md5"}, Display: "MD5", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
		{Types: []string{"md5"}, Display: "MD5 again", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "x"})
	if !reflect.DeepEqual(got, []string{"md5"}) {
		t.Fatalf("DetectTypes = %v, want [md5]", got)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd hashsmith/go_hashsmith
go test ./internal/hashid -count=1
```

Expected: FAIL — the package does not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/hashid/hashid.go`:

```go
// Package hashid is Hashsmith's detection engine.
//
// It owns the shape of a detection rule and the rules for combining matches;
// it owns no knowledge of any particular hash format. Callers supply a table
// of prototypes whose Match functions close over their own predicates, so a
// format's detection logic can live beside that format's cracking code.
//
// The engine deliberately reproduces the semantics of the first-match-wins
// cascade it replaces: see Evaluate.
package hashid

// Tier ranks the KIND of evidence a prototype produced, from proof to guess.
// It is the primary input to confidence, ahead of any prevalence weighting.
type Tier uint8

const (
	// TierChecksum: a checksum or polymod verified. Mathematical proof.
	TierChecksum Tier = iota
	// TierSignature: an unambiguous record prefix, e.g. "$2y$" or "$krb5tgs$".
	TierSignature
	// TierStructural: field count, field lengths and encodings all agree.
	TierStructural
	// TierShape: length and alphabet only. The weakest evidence there is.
	TierShape
)

func (t Tier) String() string {
	switch t {
	case TierChecksum:
		return "checksum"
	case TierSignature:
		return "signature"
	case TierStructural:
		return "structural"
	default:
		return "shape"
	}
}

// Input is one candidate string, before and after normalization.
type Input struct {
	Raw        string // exactly what the user supplied
	Normalized string // shadow prefix stripped, base58/base64 decoded to hex
}

// Evidence is the human-readable justification for a match, shown to the user
// and emitted in JSON, e.g. "32-char lowercase hex".
type Evidence string

// Prototype is one detection rule.
type Prototype struct {
	// Types are canonical Hashsmith -t names in the order crack must try them.
	// It is a slice because ordered groups are load-bearing: a "$krb5asrep$23$"
	// record yields {krb5asrep, krb5asrep-nt} and that order is a decision.
	Types []string

	// Display is the human name, e.g. "Kerberos 5 TGS-REP, etype 23".
	Display string

	Tier Tier

	// Exclusive marks a prototype that, on matching, suppresses every
	// lower-precedence prototype. This is how the cascade's early `return` is
	// expressed as data.
	Exclusive bool

	// Match reports whether this prototype recognizes the input.
	Match func(Input) (Evidence, bool)

	// Against is optional negative evidence: it reports a reason THIS input is
	// probably not this format even though the shape fits, e.g. "LM digests are
	// upper-case". It demotes confidence; it never suppresses a match.
	Against func(Input) (string, bool)

	// Prevalence is a curated 0-100 weight used only to order candidates that
	// carry equally strong evidence. It never promotes past "likely".
	Prevalence uint8

	// Rationale records WHY Prevalence is what it is. It may not be empty; a
	// test enforces this, because an unexplained weight is an unfalsifiable
	// claim about the world.
	Rationale string
}

// Match is one prototype's verdict on one input.
type Match struct {
	Proto      *Prototype
	Evidence   Evidence
	Suppressed bool // ruled out by a higher-precedence exclusive match
}
```

Create `internal/hashid/evaluate.go`:

```go
package hashid

// Evaluate runs every prototype in table order and applies the suppression
// rule. The returned slice is in table order and includes suppressed matches,
// marked as such, so identify can show a user what was ruled out.
//
// Suppression reproduces the cascade this engine replaces:
//
//   - If any Exclusive prototype matched, the EARLIEST one in table order wins
//     outright. Every other match — before or after it — is marked suppressed.
//     This is the cascade's early `return`.
//   - If none did, no match is suppressed. This is the cascade's trailing
//     length switch, which returns several candidates at once.
//
// A non-exclusive prototype never suppresses anything.
func Evaluate(table []Prototype, in Input) []Match {
	var matches []Match
	winner := -1
	for i := range table {
		p := &table[i]
		if p.Match == nil {
			continue
		}
		ev, ok := p.Match(in)
		if !ok {
			continue
		}
		if winner < 0 && p.Exclusive {
			winner = len(matches)
		}
		matches = append(matches, Match{Proto: p, Evidence: ev})
	}
	if winner >= 0 {
		for i := range matches {
			matches[i].Suppressed = i != winner
		}
	}
	return matches
}

// DetectTypes returns the canonical -t names crack should try, in order. It is
// exactly the unsuppressed matches' Types, de-duplicated.
func DetectTypes(table []Prototype, in Input) []string {
	matches := Evaluate(table, in)
	var out []string
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if m.Suppressed {
			continue
		}
		for _, t := range m.Proto.Types {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}
```

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./internal/hashid -count=1 -v
```

Expected: all five tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/hashid/
git commit -m "feat(hashid): add the detection engine, types and suppression rule"
```

---

## Task 3: The confidence model

**Files:**
- Create: `internal/hashid/confidence.go`
- Create: `internal/hashid/confidence_test.go`

**Interfaces:**
- Consumes: `Tier`, `Prototype`, `Match`, `Input`, `Evaluate` from Task 2
- Produces:
  - `type Confidence uint8` with `Certain`, `Likely`, `Possible`, `Unlikely`, and a `String()` returning `"certain"`, `"likely"`, `"possible"`, `"unlikely"`
  - `type Candidate struct { Type, Display string; Confidence Confidence; Tier Tier; Evidence Evidence; Reason string; Suppressed bool }`
  - `func Identify(table []Prototype, in Input) []Candidate`

`Reason` holds the demotion explanation: the `Against` string when negative
evidence fired, the `Rationale` when low prevalence demoted, otherwise empty.

- [ ] **Step 1: Write the failing tests**

Create `internal/hashid/confidence_test.go`:

```go
package hashid

import "testing"

func protoShape(name string, prev uint8, against func(Input) (string, bool)) Prototype {
	return Prototype{
		Types: []string{name}, Display: name, Tier: TierShape,
		Match:      func(Input) (Evidence, bool) { return "32 hex", true },
		Against:    against,
		Prevalence: prev, Rationale: name + " rationale",
	}
}

func find(cs []Candidate, typ string) *Candidate {
	for i := range cs {
		if cs[i].Type == typ {
			return &cs[i]
		}
	}
	return nil
}

func TestUnrivalledSignatureIsCertain(t *testing.T) {
	table := []Prototype{{
		Types: []string{"bcrypt"}, Display: "bcrypt", Tier: TierSignature, Exclusive: true,
		Match:      func(Input) (Evidence, bool) { return "$2y$ prefix", true },
		Prevalence: 90, Rationale: "r",
	}}
	cs := Identify(table, Input{Normalized: "$2y$10$x"})
	if len(cs) != 1 || cs[0].Confidence != Certain {
		t.Fatalf("got %+v, want one Certain candidate", cs)
	}
}

func TestDominantPrevalenceShapeIsLikely(t *testing.T) {
	table := []Prototype{
		protoShape("md5", 85, nil),
		protoShape("ntlm", 40, nil),
	}
	cs := Identify(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	if c := find(cs, "md5"); c == nil || c.Confidence != Likely {
		t.Fatalf("md5 = %+v, want Likely", c)
	}
	if c := find(cs, "ntlm"); c == nil || c.Confidence != Possible {
		t.Fatalf("ntlm = %+v, want Possible", c)
	}
}

func TestNegativeEvidenceDemotesAndExplains(t *testing.T) {
	table := []Prototype{
		protoShape("md5", 85, nil),
		protoShape("lm", 70, func(Input) (string, bool) {
			return "LM digests are upper-case", true
		}),
	}
	cs := Identify(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	c := find(cs, "lm")
	if c == nil || c.Confidence != Unlikely {
		t.Fatalf("lm = %+v, want Unlikely", c)
	}
	if c.Reason != "LM digests are upper-case" {
		t.Fatalf("lm reason = %q, want the Against string", c.Reason)
	}
}

func TestVeryLowPrevalenceDemotesAndCitesRationale(t *testing.T) {
	table := []Prototype{
		protoShape("md5", 85, nil),
		protoShape("md2", 5, nil),
	}
	cs := Identify(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	c := find(cs, "md2")
	if c == nil || c.Confidence != Unlikely {
		t.Fatalf("md2 = %+v, want Unlikely", c)
	}
	if c.Reason != "md2 rationale" {
		t.Fatalf("md2 reason = %q, want the Rationale", c.Reason)
	}
}

func TestCandidatesAreOrderedByConfidenceThenPrevalence(t *testing.T) {
	table := []Prototype{
		protoShape("md2", 5, nil),
		protoShape("ntlm", 40, nil),
		protoShape("md5", 85, nil),
	}
	cs := Identify(table, Input{Normalized: "x"})
	want := []string{"md5", "ntlm", "md2"}
	for i, w := range want {
		if cs[i].Type != w {
			t.Fatalf("position %d = %s, want %s (full: %+v)", i, cs[i].Type, w, cs)
		}
	}
}

func TestSuppressedCandidatesAreUnlikelyAndMarked(t *testing.T) {
	table := []Prototype{
		{Types: []string{"bcrypt"}, Display: "bcrypt", Tier: TierSignature, Exclusive: true,
			Match: func(Input) (Evidence, bool) { return "$2y$", true }, Prevalence: 90, Rationale: "r"},
		protoShape("base64", 30, nil),
	}
	cs := Identify(table, Input{Normalized: "$2y$10$x"})
	c := find(cs, "base64")
	if c == nil || !c.Suppressed || c.Confidence != Unlikely {
		t.Fatalf("base64 = %+v, want suppressed and Unlikely", c)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./internal/hashid -run 'TestUnrivalled|TestDominant|TestNegative|TestVeryLow|TestCandidatesAre|TestSuppressedCandidates' -count=1
```

Expected: FAIL — `undefined: Identify`.

- [ ] **Step 3: Write the implementation**

Create `internal/hashid/confidence.go`:

```go
package hashid

import "sort"

// Confidence is what the tool is willing to assert about a candidate. It is
// deliberately a small ordinal set rather than a percentage: the engine has no
// basis for computing a probability and should not imply that it does.
type Confidence uint8

const (
	Certain Confidence = iota
	Likely
	Possible
	Unlikely
)

func (c Confidence) String() string {
	switch c {
	case Certain:
		return "certain"
	case Likely:
		return "likely"
	case Possible:
		return "possible"
	default:
		return "unlikely"
	}
}

// Thresholds for shape-tier prevalence. Below dominantPrevalence a shape match
// stays "possible"; below extinctPrevalence it is demoted to "unlikely" and
// cites its rationale.
const (
	dominantPrevalence = 60
	extinctPrevalence  = 15
)

// Candidate is one identification result, ready to render.
type Candidate struct {
	Type       string // canonical -t name
	Display    string
	Confidence Confidence
	Tier       Tier
	Evidence   Evidence
	Reason     string // why it was demoted, when it was
	Suppressed bool
}

// Identify converts an evaluation into ranked candidates.
//
// Confidence comes from structural evidence first and curated prevalence only
// second: prevalence breaks ties and can demote, but never promotes a shape
// match past Likely.
func Identify(table []Prototype, in Input) []Candidate {
	matches := Evaluate(table, in)

	// A match is "rivalled" when another unsuppressed match survives alongside
	// it, which is what separates a definitive answer from a shortlist.
	live := 0
	for _, m := range matches {
		if !m.Suppressed {
			live++
		}
	}

	var out []Candidate
	for _, m := range matches {
		p := m.Proto
		for _, typ := range p.Types {
			c := Candidate{
				Type: typ, Display: p.Display, Tier: p.Tier,
				Evidence: m.Evidence, Suppressed: m.Suppressed,
			}
			switch {
			case m.Suppressed:
				c.Confidence = Unlikely
				c.Reason = "ruled out by a stronger match"
			default:
				c.Confidence = confidenceFor(p, in, live > 1)
				if c.Confidence == Unlikely {
					if p.Against != nil {
						if why, ok := p.Against(in); ok {
							c.Reason = why
						}
					}
					if c.Reason == "" {
						c.Reason = p.Rationale
					}
				}
			}
			out = append(out, c)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence < out[j].Confidence
		}
		return prevalenceOf(table, out[i].Type) > prevalenceOf(table, out[j].Type)
	})
	return out
}

func confidenceFor(p *Prototype, in Input, rivalled bool) Confidence {
	if p.Against != nil {
		if _, fired := p.Against(in); fired {
			return Unlikely
		}
	}
	switch p.Tier {
	case TierChecksum, TierSignature:
		if rivalled {
			return Likely
		}
		return Certain
	case TierStructural:
		if rivalled {
			return Possible
		}
		return Likely
	default: // TierShape
		if p.Prevalence < extinctPrevalence {
			return Unlikely
		}
		if !rivalled {
			return Possible
		}
		if p.Prevalence >= dominantPrevalence {
			return Likely
		}
		return Possible
	}
}

func prevalenceOf(table []Prototype, typ string) uint8 {
	for i := range table {
		for _, t := range table[i].Types {
			if t == typ {
				return table[i].Prevalence
			}
		}
	}
	return 0
}
```

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./internal/hashid -count=1 -v
```

Expected: all tests PASS. If `TestDominantPrevalenceShapeIsLikely` fails because
an unrivalled shape returns `Possible` while the test has two prototypes both
matching, re-read `confidenceFor`: with `live == 2` the branch taken must be the
`rivalled` one.

- [ ] **Step 5: Commit**

```bash
git add internal/hashid/confidence.go internal/hashid/confidence_test.go
git commit -m "feat(hashid): add the tier-and-prevalence confidence model"
```

---

## Task 4: The adapter and the first prototype batch

This task establishes the pattern every later porting task follows. The
adapter consults the prototype table first and falls through to the untouched
remainder of the cascade, so the golden test stays green at every commit and
each batch is independently reviewable.

**Files:**
- Create: `cmd/hashsmith/prototypes.go`
- Create: `cmd/hashsmith/prototypes_test.go`
- Modify: `cmd/hashsmith/identify.go:1444-1497` (rename the cascade, port branches at lines 1448-1497)

**Interfaces:**
- Consumes: `hashid.Prototype`, `hashid.Input`, `hashid.DetectTypes` (Task 2); the existing predicates `isNSEC3Record`, `detectBlake2HashcatTypes`, `isHMailServer`, `isPwsafe`, `isPKCS12`, `isEpiserver`, `isAzureSync`, `isSipHash`, `isHexPair`, `stripShadowUsername`
- Produces:
  - `func prototypeTable() []hashid.Prototype` — the whole table, built once
  - `func detectTypesFromTable(text string) ([]string, bool)` — table-only detection, used by coverage tests
  - `func legacyDetectHashTypes(text string) []string` — the not-yet-ported remainder

- [ ] **Step 1: Write the coverage test for this batch**

Create `cmd/hashsmith/prototypes_test.go`:

```go
package main

import (
	"reflect"
	"testing"
)

// tableCoverageCase asserts a branch is served by the PROTOTYPE TABLE, not by
// the legacy cascade fall-through. Without this, a broken port would silently
// fall through, the golden test would stay green, and the bug would ship.
type tableCoverageCase struct {
	name  string
	input string
	want  []string
}

func runTableCoverage(t *testing.T, cases []tableCoverageCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, served := detectTypesFromTable(tc.input)
			if !served {
				t.Fatalf("%q was not matched by the prototype table (it fell through to the legacy cascade)", tc.input)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("types = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTableCoverageBatchA(t *testing.T) {
	runTableCoverage(t, []tableCoverageCase{
		{"sha1crypt", "$sha1$64000$sfUsIAcX$k17MgwsyBQlYlr8bXCEuXkQmn5Rc", []string{"sha1crypt"}},
		{"md5crypt", "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/", []string{"md5crypt"}},
		{"apr1", "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", []string{"apr1"}},
		{"sha256crypt", "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", []string{"sha256crypt"}},
		{"sha512crypt", "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", []string{"sha512crypt"}},
		{"crc32 pair", "c762de4a:00000000", []string{"crc32-hashcat", "crc32c-hashcat", "murmurhash", "murmur3-seeded", "skip32"}},
		{"64-bit pair", "1234567890abcdef:fedcba0987654321", []string{"murmur64a", "crc64-jones"}},
	})
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd hashsmith/go_hashsmith
go test ./cmd/hashsmith -run TestTableCoverageBatchA -count=1
```

Expected: FAIL — `undefined: detectTypesFromTable`.

- [ ] **Step 3: Create the table, the adapter, and port this batch**

Create `cmd/hashsmith/prototypes.go`:

```go
package main

import (
	"hashsmith-go/internal/hashid"
	"strings"
	"sync"
)

// The prototype table is Hashsmith's single detection vocabulary. Both
// `identify` and `crack` read it, which is what makes it impossible for them
// to disagree about what a hash is.
//
// TABLE ORDER IS LOAD-BEARING. It reproduces the precedence of the cascade it
// replaces: the first Exclusive match wins outright and suppresses the rest.
// Reordering entries changes which type crack tries first. testdata/
// detect_golden.txt is the guard on that; do not regenerate it to make a
// reordering pass.
//
// Prototypes live here rather than in internal/hashid because their Match
// functions close over predicates like isPwsafe and isLDAP, which belong
// beside their own formats' cracking code in crack_pwsafe.go and crack_ldap.go.

var (
	prototypeTableOnce sync.Once
	prototypeTableVal  []hashid.Prototype
)

func prototypeTable() []hashid.Prototype {
	prototypeTableOnce.Do(func() {
		prototypeTableVal = append(prototypeTableVal, batchAPrototypes()...)
	})
	return prototypeTableVal
}

// hasPrefixProto builds the commonest prototype shape: an unambiguous record
// prefix that identifies exactly one format.
func hasPrefixProto(prefix, display string, prevalence uint8, rationale string, types ...string) hashid.Prototype {
	return hashid.Prototype{
		Types: types, Display: display, Tier: hashid.TierSignature, Exclusive: true,
		Match: func(in hashid.Input) (hashid.Evidence, bool) {
			if strings.HasPrefix(in.Normalized, prefix) {
				return hashid.Evidence("record prefix " + prefix), true
			}
			return "", false
		},
		Prevalence: prevalence, Rationale: rationale,
	}
}

// predicateProto wraps an existing boolean predicate as an exclusive signature.
func predicateProto(fn func(string) bool, display, evidence string, prevalence uint8, rationale string, types ...string) hashid.Prototype {
	return hashid.Prototype{
		Types: types, Display: display, Tier: hashid.TierSignature, Exclusive: true,
		Match: func(in hashid.Input) (hashid.Evidence, bool) {
			if fn(in.Normalized) {
				return hashid.Evidence(evidence), true
			}
			return "", false
		},
		Prevalence: prevalence, Rationale: rationale,
	}
}

func batchAPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// NSEC3 is checked against the RAW input, before shadow-line peeling,
		// because its colon-delimited domain can itself look like a 13-char
		// DES crypt token. This ordering is why hashid.Input carries both Raw
		// and Normalized.
		{
			Types: []string{"dnssec-nsec3"}, Display: "DNSSEC NSEC3",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isNSEC3Record(in.Raw) {
					return "complete NSEC3 record", true
				}
				return "", false
			},
			Prevalence: 20, Rationale: "narrow DNSSEC use; rare outside zone-walking work",
		},
		hasPrefixProto("$sha1$", "sha1crypt", 25, "NetBSD crypt(3); uncommon outside BSD systems", "sha1crypt"),
		hasPrefixProto("$1$", "md5crypt", 60, "the historic Unix crypt default; still widespread on legacy systems", "md5crypt"),
		hasPrefixProto("$apr1$", "Apache apr1", 45, "the Apache htpasswd default before bcrypt", "apr1"),
		hasPrefixProto("$5$", "sha256crypt", 55, "common on Linux distributions that predate the yescrypt default", "sha256crypt"),
		hasPrefixProto("$6$", "sha512crypt", 80, "the default /etc/shadow scheme on most Linux distributions", "sha512crypt"),
		predicateProto(isHMailServer, "hMailServer", 10, "single-product format; rare in the wild", "hmailserver"),
		predicateProto(isPwsafe, "Password Safe v3", 20, "desktop password manager; appears in forensic work", "pwsafe"),
		predicateProto(isPKCS12, "PKCS#12 keystore", 35, "common wherever TLS client certificates are issued", "pfx"),
		predicateProto(isEpiserver, "EPiServer", 10, "single-CMS format", "episerver"),
		predicateProto(isAzureSync, "Azure AD Connect sync", 15, "narrow to hybrid-AD deployments", "azuresync"),
		predicateProto(isSipHash, "SipHash", 15, "a MAC, not a password hash; seldom a cracking target", "siphash"),
		{
			Types: []string{"crc32-hashcat", "crc32c-hashcat", "murmurhash", "murmur3-seeded", "skip32"},
			Display: "32-bit checksum with seed", Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isHexPair(in.Normalized, 8, 8) {
					return "two 8-char hex fields", true
				}
				return "", false
			},
			Prevalence: 20, Rationale: "checksums, not password hashes; the group is inherently ambiguous",
		},
		{
			Types: []string{"murmur64a", "crc64-jones"},
			Display: "64-bit checksum with seed", Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isHexPair(in.Normalized, 16, 16) {
					return "two 16-char hex fields", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "checksums, not password hashes",
		},
	}
}
```

`detectBlake2HashcatTypes` returns a *variable-length list*, so it cannot be a
prototype: `Prototype.Types` is fixed at construction. Branches like this stay
functions, called from the adapter at the position their cascade order
requires. Add the adapter to the same file:

```go
// detectTypesFromTable runs the prototype table only. The bool reports whether
// the table served the input, which is what the per-batch coverage tests
// assert; without it a broken port would silently fall through to the legacy
// cascade and the golden test would still pass.
func detectTypesFromTable(text string) ([]string, bool) {
	in := hashid.Input{Raw: strings.TrimSpace(text)}
	in.Normalized = stripShadowUsername(in.Raw)

	// detectBlake2HashcatTypes returns a variable-length list, so it cannot be
	// expressed as a fixed-Types prototype. It keeps its cascade position by
	// running here, between the crypt prefixes and the vendor predicates.
	if blake := detectBlake2HashcatTypes(in.Normalized); len(blake) > 0 {
		return blake, true
	}
	types := hashid.DetectTypes(prototypeTable(), in)
	return types, len(types) > 0
}
```

Now modify `cmd/hashsmith/identify.go`. Rename the existing cascade and add the
adapter in its place:

```go
// detectHashTypes returns the candidate -t names for a target, in the order
// crack should try them. It consults the unified prototype table first and
// falls through to the not-yet-ported remainder of the original cascade.
func detectHashTypes(text string) []string {
	if types, served := detectTypesFromTable(text); served {
		return types
	}
	return legacyDetectHashTypes(text)
}

func legacyDetectHashTypes(text string) []string {
	// ... the original function body, unchanged ...
}
```

Then delete from `legacyDetectHashTypes` only the branches now covered by
`batchAPrototypes`: the `isNSEC3Record` branch, the four crypt-prefix branches,
the `detectBlake2HashcatTypes` branch, the six vendor predicate branches, and
the two `isHexPair` branches — original lines 1448-1497. Leave `stripShadowUsername`
in place at the top of `legacyDetectHashTypes`; both paths need it.

- [ ] **Step 4: Run the coverage test and the golden test**

```bash
cd hashsmith/go_hashsmith
go test ./cmd/hashsmith -run 'TestTableCoverageBatchA|TestDetectHashTypesGolden' -count=1 -v
```

Expected: both PASS. If the golden test fails, the port changed behaviour —
**fix the prototype, never regenerate the golden file**.

- [ ] **Step 5: Run the full suite and commit**

```bash
go test ./... -count=1
git add cmd/hashsmith/prototypes.go cmd/hashsmith/prototypes_test.go cmd/hashsmith/identify.go
git commit -m "refactor(identify): route detection through the prototype table, port batch A"
```

---

## Tasks 5-9: Port the remaining cascade branches

Each of these five tasks is structurally the same work on a different range of
`legacyDetectHashTypes`, and each is independently reviewable and revertible.
For every task:

**The mechanical transformation.** A cascade branch of the form

```go
if strings.HasPrefix(t, "$7z$") {
    return []string{"7z"}
}
```

becomes a table entry

```go
hasPrefixProto("$7z$", "7-Zip archive", 40, "<why this prevalence>", "7z"),
```

and a branch of the form

```go
if isShiro1(t) {
    return []string{"shiro1"}
}
```

becomes

```go
predicateProto(isShiro1, "Apache Shiro 1", 15, "<why this prevalence>", "shiro1"),
```

Branches with inline structure (a `strings.Split` with field-length checks, a
length-and-alphabet test, a nested `if` choosing between two types) get a
literal `hashid.Prototype` with a hand-written `Match`, following the
`isHexPair` entries in `batchAPrototypes` as the model. Branches whose types
depend on the input — a nested `if` that appends an extra candidate — become
**two prototypes**: the more specific one first, so table order reproduces the
nested precedence.

**Prevalence and rationale.** Every entry needs both, and the rationale must
say something falsifiable about how often the format is actually encountered.
"common" is not a rationale; "the Apache htpasswd default before bcrypt" is.
When you genuinely do not know, write `10` and the rationale
`"no basis for a better estimate; revisit with corpus data"` — an admitted
guess is fine, an unmarked one is not.

**The per-task steps are identical in form:**

- [ ] **Step 1:** Write `TestTableCoverageBatch<X>` in `cmd/hashsmith/prototypes_test.go`, using `runTableCoverage`, with one case per ported branch. Get the representative input for each branch from the branch's own literal prefix (append filler to satisfy any length check) or from the matching self-test vector:

```bash
cd hashsmith/go_hashsmith
grep -n 'target:' cmd/hashsmith/selftest_vectors*.go | grep '<format name>'
```

- [ ] **Step 2:** Run it and watch it fail with "was not matched by the prototype table".
- [ ] **Step 3:** Add `batch<X>Prototypes()` to the batch's file, append it in `prototypeTable()`, and delete the ported branches from `legacyDetectHashTypes`.
- [ ] **Step 4:** Run `go test ./cmd/hashsmith -run 'TestTableCoverage|TestDetectHashTypesGolden' -count=1`. Both must pass. A golden failure means the port is wrong; fix the prototype.
- [ ] **Step 5:** Run `go test ./... -count=1`, then commit.

The five tasks:

### Task 5: Archive and container records

**Files:** Create `cmd/hashsmith/prototypes_records.go`; modify `cmd/hashsmith/identify.go` (original lines 1499-1577)

Covers `$zipcrypto$`, `$zipaes128/192/256$`, `$7z$`, `$rar3$`/`$RAR3$`, `$rar5$`,
`isPDFR6`, `$pdf$`, `$ssh$`, `$sshng$`, `$pkcs8$`, `$PEM$1$`, `$PEM$2$`,
`$jksprivk$*`, `$vmx$`, `$ab$`, `$encfs$`, `$mozilla$*`, `$vbox$` (nested: the
`$16$` variant selects `virtualbox-aes256`, so emit two prototypes with the
`$16$` one first), `$metamask-short$`, `$metamask$`, `EXODUS:`, `$gpg$`,
`$office$2016$0$`.

Commit message: `refactor(identify): port archive and container prototypes`

### Task 6: Office, directory and vendor application records

**Files:** Modify `cmd/hashsmith/prototypes_records.go`, `cmd/hashsmith/identify.go` (original lines 1580-1717)

Covers `$oldoffice$0*`/`1*`, `$oldoffice$3*`/`4*`, `$office$`, `$mysqlna$`,
`$tacacs-plus$`, `$ASN$*`, `otm_sha256:`, `$xmpp-scram$`, `$postgres$`,
`$SNMPv3$`, `@m@`/`@m,`, `@s@`/`@s,`, `@S@`/`@S,`, `{x-issha, `,
`{x-isSHA256, `, `{x-isSHA384, `, `$stellar$`, `$telegram$0*`,
`$telegram$1*`/`2*`, `$signal$`, `$keychain$*`, `$vnc$*`, `$sm3$`,
`$chacha20$*`, the `{CRAM-MD5}` length-and-hex branch, `$sntp-ms$`, the second
`isNSEC3Record`, the `O$` `parseOracleH` branch, `$radmin3$`, the 137-char
`2`-prefixed hex branch, the 63-char `SH2` branch, `$vbk$*`,
`$MSONLINEACCOUNT$0$`, `S:"Config Passphrase"=02:`,
`$knx-ip-secure-device-authentication-code$*`, `$teamspeak$3$`,
`$bcrypt-sha256$`, the three-field `sha256:` branch, the 129-char `5`-prefixed
hex branch, `isUmbracoHMACSHA1`, `$AWS-Sig-v4$`, `isTOTPRecord`, `isHCCAPXHex`,
`$keepass$`.

Commit message: `refactor(identify): port office, directory and vendor prototypes`

### Task 7: Wallets, wireless and web frameworks

**Files:** Modify `cmd/hashsmith/prototypes_records.go`, `cmd/hashsmith/identify.go` (original lines 1720-1896)

Covers `WPA*01*`/`WPA*02*`/`isLegacyPMKID`, `$ethereum$` (nested `$ethereum$w*`
first), `$aescrypt$1*`, `$multibit$1*`, `isTerraWallet`, `$bitcoin$`, `$dmg$`,
`$monero$0*`, `$bitwarden$`, `$itunes_backup$`, `$ansible$`, `$blockchain$`,
`$rc4$`, `isShiro1`, `isSSPR`, `isNetIQPBKDF2`, `isAS400SSHA1`,
`isAuthMeSHA256`, `isPHPS`, the `pbkdf2(`/`,sha512)$` branch, `$wp$2`,
`$krb5db$17$`/`18$`, the three-field dot-split with a 27-char tail, the three
colon-split branches with 40-char hex heads, `isMySQL8`, `$axcrypt_sha1$`,
`$mongodb-scram$`, `$solarwinds$`, `$sip$*`, `isDjangoHash`, `truecrypt:`,
`veracrypt:`, `$truecrypt$`, `$veracrypt$`, the 47-char `AK1` branch,
`{x-isSHA512, `, the four-field colon-split with a 32-char head, `isChap`, the
three-field colon-split with a 32-char hex head, `$bitlocker$`, `$electrum$`,
`isPhpassHash` (nested: `$H$` selects one type, otherwise another — two
prototypes, `$H$` first), `isDrupal7Hash`, `$luks$`, the 61-char `$8$` and
`$9$` branches, `$4$` with `isCiscoType4`, `$ml$`, `{PKCS5S2}`, `isPBKDF1SHA1`,
`isJWT`.

Commit message: `refactor(identify): port wallet, wireless and framework prototypes`

### Task 8: KDF, directory and enterprise predicate families

**Files:** Modify `cmd/hashsmith/prototypes_records.go`, `cmd/hashsmith/identify.go` (original lines 1899-1977)

Covers `isGenericPBKDF2`, `isPasslibPBKDF2`, `isWerkzeug`, `isASPNetIdentity`,
`isGRUB2`, `isOnePassword`, `isIKE`, `isDCC2`, `SCRAM-SHA-256$`, `$cram_md5$`,
`isCitrix`, `isCiscoASA` (nested: appends `oracle-h` when `parseOracleH`
succeeds — emit the two-type prototype first, guarded on both predicates, then
the one-type prototype), `isIPMI`, `isIPMIMD5`, `isAIX`, `isRedHat389PBKDF2`,
`isLDAP`, `isSybaseASE`, `isSAPCodvnFGRFCReadTable`, `isSAPCodvnBRFCReadTable`,
`isSAPCodvnFG`, `isJuniper`, `isSAPCodvnB`, `isMediaWiki`, the bare
`parseOracleH` branch.

Commit message: `refactor(identify): port KDF and enterprise predicate prototypes`

### Task 9: Generic salted constructions, Kerberos and regex singles

This is the most delicate batch: the `detectCompatSaltedTypes` branch builds
its result by **prepending** more specific candidates to a generic list, and
that assembly order is precisely what the golden test protects.

**Files:** Modify `cmd/hashsmith/prototypes_records.go`, `cmd/hashsmith/identify.go` (original lines 1978-2054)

The `detectCompatSaltedTypes` branch cannot be a fixed-`Types` prototype
because its output is computed. Handle it the way `detectBlake2HashcatTypes`
was handled in Task 4 — in `detectTypesFromTable`, at the position matching its
cascade order, keeping its prepend logic verbatim:

```go
	// detectCompatSaltedTypes composes its result, prepending more specific
	// candidates to a generic list, so it stays a function rather than a
	// prototype. Its position here matches its position in the cascade.
	if generic := detectCompatSaltedTypes(in.Normalized); len(generic) > 0 {
		if isRedmine(in.Normalized) {
			generic = append([]string{"redmine"}, generic...)
		}
		// ... the remaining prepends, copied verbatim from the cascade ...
		return generic, true
	}
```

The rest of the batch is ordinary: `$krb5asrep$` (nested `$23$` first),
`$krb5tgs$` (nested `$23$` first), `$krb5pa$`, `isNetNTLMLine`, `reBcrypt`,
`reArgon2`, `reScrypt`, `rePostgres`, `reMySQL41`, `reMSSQLNew` (nested
`0x0200` first), `looksLikeDescrypt`, the 16-char `isPixToken` branch,
`isDahuaAuthToken`, and the 50-char `arubaos` branch.

Commit message: `refactor(identify): port salted, Kerberos and regex prototypes`

---

## Task 10: The shape fallback, and deleting the cascade

The trailing `switch len(t)` is the only **non-exclusive** group in the whole
cascade, and it is where the confidence model earns its keep.

**Files:**
- Create: `cmd/hashsmith/prototypes_shape.go`
- Modify: `cmd/hashsmith/identify.go` — delete `legacyDetectHashTypes` entirely
- Modify: `cmd/hashsmith/prototypes_test.go`

**Interfaces:**
- Consumes: `hashid.Prototype`, `isHex`, `hashid.TierShape`
- Produces: `func shapePrototypes() []hashid.Prototype`

- [ ] **Step 1: Write the failing tests**

Append to `cmd/hashsmith/prototypes_test.go`:

```go
func TestTableCoverageShapeFallback(t *testing.T) {
	runTableCoverage(t, []tableCoverageCase{
		{"16 hex", "0123456789abcdef", []string{"mysql323", "cisco-pix", "half-md5"}},
		{"32 hex", "5f4dcc3b5aa765d61d8327deb882cf99", []string{"md5", "md4", "md2", "ntlm", "lm"}},
		{"40 hex", "da39a3ee5e6b4b0d3255bfef95601890afd80709", []string{"sha1", "sha0", "ripemd160"}},
		{"56 hex", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", []string{"sha224", "sha512_224", "sha3_224", "keccak224"}},
	})
}

// The shape group must NOT suppress: it is the one place several candidates
// legitimately survive together.
func TestShapePrototypesAreNotExclusive(t *testing.T) {
	for _, p := range shapePrototypes() {
		if p.Exclusive {
			t.Errorf("shape prototype %q is Exclusive; the length fallback must not suppress", p.Display)
		}
		if p.Tier != hashid.TierShape {
			t.Errorf("shape prototype %q has tier %v, want TierShape", p.Display, p.Tier)
		}
	}
}

// LM is the motivating case for negative evidence: LM digests are upper-case,
// so a lower-case 32-hex input is evidence AGAINST LM, not neutral.
func TestLMIsDemotedOnLowercaseInput(t *testing.T) {
	cs := identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99")
	for _, c := range cs {
		if c.Type != "lm" {
			continue
		}
		if c.Confidence != hashid.Unlikely {
			t.Fatalf("lm confidence = %v, want unlikely", c.Confidence)
		}
		if c.Reason == "" {
			t.Fatal("lm was demoted without a stated reason")
		}
		return
	}
	t.Fatal("lm was not among the candidates at all")
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./cmd/hashsmith -run 'TestTableCoverageShapeFallback|TestShapePrototypesAreNotExclusive|TestLMIsDemoted' -count=1
```

Expected: FAIL — `undefined: shapePrototypes`, `undefined: identifyCandidates`.

- [ ] **Step 3: Write the implementation**

Create `cmd/hashsmith/prototypes_shape.go`:

```go
package main

import (
	"strconv"
	"strings"

	"hashsmith-go/internal/hashid"
)

// hexShapeProto builds a non-exclusive prototype matching hex of one exact
// length. These are the weakest rules in the table and the only ones that
// coexist: a bare 32-char hex string really could be any of five digests.
func hexShapeProto(length int, display string, prevalence uint8, rationale string,
	against func(hashid.Input) (string, bool), types ...string) hashid.Prototype {
	return hashid.Prototype{
		Types: types, Display: display, Tier: hashid.TierShape, Exclusive: false,
		Match: func(in hashid.Input) (hashid.Evidence, bool) {
			v := in.Normalized
			if len(v) != length || !isHex(v) {
				return "", false
			}
			casing := "lowercase"
			if v == strings.ToUpper(v) && v != strings.ToLower(v) {
				casing = "uppercase"
			}
			return hashid.Evidence(strconv.Itoa(length) + "-char " + casing + " hex"), true
		},
		Against: against, Prevalence: prevalence, Rationale: rationale,
	}
}

func lowercaseRulesOutLM(in hashid.Input) (string, bool) {
	v := in.Normalized
	if v != strings.ToUpper(v) {
		return "LM digests are upper-case", true
	}
	return "", false
}

func shapePrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		hexShapeProto(16, "MySQL 3.23 / Cisco-PIX / half-MD5", 25,
			"truncated and legacy digests; uncommon as a primary target", nil,
			"mysql323", "cisco-pix", "half-md5"),

		hexShapeProto(32, "MD5", 85,
			"the most common raw digest in leaked credential dumps by a wide margin", nil, "md5"),
		hexShapeProto(32, "MD4", 20,
			"rare standalone; almost always seen inside NTLM instead", nil, "md4"),
		hexShapeProto(32, "MD2", 5,
			"effectively extinct; no modern system emits it", nil, "md2"),
		hexShapeProto(32, "NTLM", 70,
			"ubiquitous in Windows domain compromise work", nil, "ntlm"),
		hexShapeProto(32, "LM (LAN Manager)", 30,
			"obsolete since Vista but still found in old NTDS dumps",
			lowercaseRulesOutLM, "lm"),

		hexShapeProto(40, "SHA-1", 80,
			"the second most common raw digest after MD5", nil, "sha1"),
		hexShapeProto(40, "SHA-0", 5,
			"withdrawn in 1995; effectively never encountered", nil, "sha0"),
		hexShapeProto(40, "RIPEMD-160", 20,
			"mainly seen via Bitcoin address derivation", nil, "ripemd160"),

		hexShapeProto(56, "SHA-224", 30, "uncommon; SHA-256 is chosen instead", nil, "sha224"),
		hexShapeProto(56, "SHA-512/224", 10, "rare truncated variant", nil, "sha512_224"),
		hexShapeProto(56, "SHA3-224", 10, "rare; SHA-3 adoption is thin", nil, "sha3_224"),
		hexShapeProto(56, "Keccak-224", 10, "rare outside Ethereum tooling", nil, "keccak224"),

		hexShapeProto(60, "Oracle 11g", 25, "legacy Oracle; still present in old databases", nil, "oracle11g"),
		hexShapeProto(160, "Oracle 12c", 25, "current Oracle password verifier", nil, "oracle12c"),

		hexShapeProto(64, "SHA-256", 85, "the default modern digest choice", nil, "sha256"),
		hexShapeProto(64, "SHA3-256", 15, "thin SHA-3 adoption", nil, "sha3_256"),
		hexShapeProto(64, "SM3", 10, "Chinese national standard; regionally concentrated", nil, "sm3"),
		hexShapeProto(64, "BLAKE2s", 10, "uncommon as a password digest", nil, "blake2s"),
		hexShapeProto(64, "Streebog-256", 10, "Russian national standard; regionally concentrated", nil, "streebog256"),
		hexShapeProto(64, "SHA-512/256", 10, "rare truncated variant", nil, "sha512_256"),
		hexShapeProto(64, "Keccak-256", 20, "common in Ethereum tooling", nil, "keccak256"),
		hexShapeProto(64, "SHAKE128-256", 5, "rare XOF output", nil, "shake128-256"),
		hexShapeProto(64, "BLAKE2b-256", 10, "uncommon truncated BLAKE2b", nil, "blake2b256"),

		hexShapeProto(96, "SHA-384", 40, "used where SHA-512 is considered oversized", nil, "sha384"),
		hexShapeProto(96, "SHA3-384", 10, "thin SHA-3 adoption", nil, "sha3_384"),
		hexShapeProto(96, "BLAKE2b-384", 5, "rare truncated BLAKE2b", nil, "blake2b384"),
		hexShapeProto(96, "Keccak-384", 5, "rare outside Ethereum tooling", nil, "keccak384"),

		hexShapeProto(128, "SHA-512", 80, "the common choice for a long digest", nil, "sha512"),
		hexShapeProto(128, "SHA3-512", 10, "thin SHA-3 adoption", nil, "sha3_512"),
		hexShapeProto(128, "BLAKE2b", 20, "the usual BLAKE2b output length", nil, "blake2b"),
		hexShapeProto(128, "Whirlpool", 15, "legacy; appears in older applications", nil, "whirlpool"),
		hexShapeProto(128, "Streebog-512", 10, "regionally concentrated", nil, "streebog512"),
		hexShapeProto(128, "Keccak-512", 10, "rare outside Ethereum tooling", nil, "keccak512"),
		hexShapeProto(128, "SHAKE256-512", 5, "rare XOF output", nil, "shake256-512"),
		hexShapeProto(128, "Cisco ISE", 10, "single-product format", nil, "cisco-ise"),
	}
}
```

**Ordering matters.** `hexShapeProto(32, ...)` entries must appear in the order
`md5, md4, md2, ntlm, lm` to reproduce the golden file, and likewise for every
other length group — copy each group's order from the original `switch len(t)`
verbatim. The 50-char `arubaos` branch was ported in Task 9 and is exclusive;
it must still be evaluated before this group, so append `shapePrototypes()`
**last** in `prototypeTable()`.

Add to `prototypeTable()`:

```go
		prototypeTableVal = append(prototypeTableVal, shapePrototypes()...)
```

Add `identifyCandidates` to `cmd/hashsmith/prototypes.go`:

```go
// identifyCandidates is identify's entry point: the same table and the same
// evaluation crack uses, presented with confidence instead of bare ordering.
func identifyCandidates(text string) []hashid.Candidate {
	in := hashid.Input{Raw: strings.TrimSpace(text)}
	in.Normalized = stripShadowUsername(in.Raw)
	return hashid.Identify(prototypeTable(), in)
}
```

Finally, delete `legacyDetectHashTypes` from `identify.go` and simplify the
adapter:

```go
func detectHashTypes(text string) []string {
	types, _ := detectTypesFromTable(text)
	return types
}
```

- [ ] **Step 4: Run everything**

```bash
go test ./... -count=1
```

Expected: PASS, including `TestDetectHashTypesGolden`. The golden file has not
changed since Task 1 and must not change now. If it fails on a length group,
the group's prototype order does not match the original `switch`.

- [ ] **Step 5: Confirm the cascade is actually gone**

```bash
grep -c 'legacyDetectHashTypes' cmd/hashsmith/*.go | grep -v ':0' || echo "cascade removed"
```

Expected: `cascade removed`.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/prototypes_shape.go cmd/hashsmith/prototypes.go cmd/hashsmith/prototypes_test.go cmd/hashsmith/identify.go
git commit -m "refactor(identify): port the shape fallback and delete the cascade"
```

---

## Task 11: Prototype integrity test

The property the rejected data-file approach could not provide. It runs over
the real table and fails the build on a malformed entry.

**Files:**
- Modify: `cmd/hashsmith/prototypes_test.go`

**Interfaces:**
- Consumes: `prototypeTable()`, `universalHashRegistry`, `canonicalHashType`

- [ ] **Step 1: Write the failing test**

```go
func TestPrototypeTableIntegrity(t *testing.T) {
	table := prototypeTable()
	if len(table) < 150 {
		t.Fatalf("table has %d prototypes; the cascade had ~185 branches — entries are missing", len(table))
	}

	seenDisplay := make(map[string]int)
	for i := range table {
		p := &table[i]
		label := p.Display
		if label == "" {
			t.Errorf("prototype %d has an empty Display", i)
			label = "<unnamed>"
		}
		if p.Match == nil {
			t.Errorf("prototype %q has a nil Match", label)
		}
		if strings.TrimSpace(p.Rationale) == "" {
			t.Errorf("prototype %q has an empty Rationale; an unexplained prevalence is an unfalsifiable claim", label)
		}
		if p.Prevalence > 100 {
			t.Errorf("prototype %q has Prevalence %d, want 0-100", label, p.Prevalence)
		}
		if len(p.Types) == 0 {
			t.Errorf("prototype %q declares no Types", label)
		}
		for _, typ := range p.Types {
			if typ != canonicalHashType(typ) {
				t.Errorf("prototype %q declares %q, which is an alias; use the canonical name %q",
					label, typ, canonicalHashType(typ))
			}
			if _, ok := universalHashRegistry.formats[typ]; !ok {
				t.Errorf("prototype %q declares unknown type %q", label, typ)
			}
		}
		if prev, dup := seenDisplay[p.Display]; dup {
			t.Errorf("Display %q is used by prototypes %d and %d; names must be unique so output is unambiguous",
				p.Display, prev, i)
		}
		seenDisplay[p.Display] = i
	}
}
```

Add `"strings"` to the test file's imports if it is not already there.

- [ ] **Step 2: Run it**

```bash
go test ./cmd/hashsmith -run TestPrototypeTableIntegrity -count=1 -v
```

Expected: FAIL on the first pass, listing every prototype with a missing
rationale, a duplicate display name, or a type that is an alias rather than a
canonical name. **This is the point of the task.**

- [ ] **Step 3: Fix every reported prototype**

Work through the failures in `prototypes.go`, `prototypes_records.go` and
`prototypes_shape.go`. For a type reported as an alias, replace it with the
canonical name the message gives. For a duplicate display, disambiguate both
(e.g. `"VirtualBox AES-128-XTS"` and `"VirtualBox AES-256-XTS"`). For a missing
rationale, write one — or `"no basis for a better estimate; revisit with corpus data"`
if you genuinely have none.

- [ ] **Step 4: Run until clean, then the whole suite**

```bash
go test ./cmd/hashsmith -run TestPrototypeTableIntegrity -count=1
go test ./... -count=1
```

Expected: both PASS, golden included.

- [ ] **Step 5: Commit**

```bash
git add cmd/hashsmith/prototypes*.go
git commit -m "test(identify): enforce prototype table integrity"
```

---

## Task 12: Recover Hashcat modes and John labels from the registry

Measured on the current tree: 395 of 457 formats carry a numeric Hashcat alias,
and **0 can report a John label** — John labels like `raw-md5` sit in the same
undifferentiated alias map as spelling variants like `md-5`, so there is no way
to ask which is which. This task adds the reverse lookups `identify` needs.

**Files:**
- Modify: `cmd/hashsmith/hash_registry.go`
- Create: `cmd/hashsmith/hash_john_labels.go`
- Create: `cmd/hashsmith/hash_registry_lookup_test.go`

**Interfaces:**
- Consumes: `universalHashRegistry`, `hashFormat.aliases`, `isDecimalIdentifier`
- Produces:
  - `func (r *hashRegistry) hashcatMode(name string) (int, bool)`
  - `func (r *hashRegistry) johnLabel(name string) (string, bool)`
  - `func johnLabelSeed() map[string]string` — canonical `-t` name → John `--format=` label

- [ ] **Step 1: Write the failing tests**

Create `cmd/hashsmith/hash_registry_lookup_test.go`:

```go
package main

import "testing"

func TestHashcatModeLookup(t *testing.T) {
	cases := []struct {
		typ  string
		want int
	}{
		{"md5", 0}, {"ntlm", 1000}, {"sha1", 100}, {"sha256", 1400},
		{"lm", 3000}, {"md4", 900}, {"sha512crypt", 1800},
	}
	for _, c := range cases {
		got, ok := universalHashRegistry.hashcatMode(c.typ)
		if !ok {
			t.Errorf("hashcatMode(%q): not found, want %d", c.typ, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("hashcatMode(%q) = %d, want %d", c.typ, got, c.want)
		}
	}
}

// A format with several Hashcat modes reports the lowest, deterministically.
func TestHashcatModeIsDeterministicForMultiModeFormats(t *testing.T) {
	first, ok := universalHashRegistry.hashcatMode("gpg")
	if !ok {
		t.Skip("gpg carries no numeric alias on this tree")
	}
	for i := 0; i < 20; i++ {
		again, _ := universalHashRegistry.hashcatMode("gpg")
		if again != first {
			t.Fatalf("hashcatMode(gpg) is unstable: %d then %d", first, again)
		}
	}
}

func TestJohnLabelLookup(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"md5", "raw-md5"}, {"ntlm", "NT"}, {"lm", "LM"},
		{"sha1", "raw-sha1"}, {"sha512crypt", "sha512crypt"},
		{"descrypt", "descrypt"}, {"bcrypt", "bcrypt"},
	}
	for _, c := range cases {
		got, ok := universalHashRegistry.johnLabel(c.typ)
		if !ok {
			t.Errorf("johnLabel(%q): not found, want %q", c.typ, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("johnLabel(%q) = %q, want %q", c.typ, got, c.want)
		}
	}
}

// Every John label declared must name a format that exists, or the column
// will print a label for a type Hashsmith cannot actually crack.
func TestJohnLabelSeedNamesRealFormats(t *testing.T) {
	for typ, label := range johnLabelSeed() {
		if _, ok := universalHashRegistry.formats[typ]; !ok {
			t.Errorf("johnLabelSeed declares label %q for unknown format %q", label, typ)
		}
	}
}

func TestUnknownFormatHasNoMetadata(t *testing.T) {
	if _, ok := universalHashRegistry.hashcatMode("no-such-format"); ok {
		t.Error("hashcatMode invented a mode for an unknown format")
	}
	if _, ok := universalHashRegistry.johnLabel("no-such-format"); ok {
		t.Error("johnLabel invented a label for an unknown format")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd hashsmith/go_hashsmith
go test ./cmd/hashsmith -run 'TestHashcatMode|TestJohnLabel|TestUnknownFormatHasNoMetadata' -count=1
```

Expected: FAIL — `hashcatMode` and `johnLabel` undefined.

- [ ] **Step 3: Write the implementation**

Append to `cmd/hashsmith/hash_registry.go`:

```go
// hashcatMode reports the Hashcat -m number for a format.
//
// A format may carry several numeric aliases — GPG spans 17010/17020/17030/
// 17040 — so the LOWEST is reported. That choice is arbitrary but it must be
// deterministic: a lookup that varies between runs would make identify's
// output unstable and its JSON undiffable.
func (r *hashRegistry) hashcatMode(name string) (int, bool) {
	format := r.formats[canonicalHashType(name)]
	if format == nil {
		return 0, false
	}
	best, found := 0, false
	for _, alias := range format.aliases {
		if !isDecimalIdentifier(alias) {
			continue
		}
		n, err := strconv.Atoi(alias)
		if err != nil {
			continue
		}
		if !found || n < best {
			best, found = n, true
		}
	}
	return best, found
}

// johnLabel reports the John the Ripper --format= label for a format.
//
// It cannot be derived from the alias map: John's labels live there
// undifferentiated from spelling variants, so "raw-md5" and "md-5" are
// indistinguishable to the registry. The mapping is therefore curated
// explicitly in johnLabelSeed, and a format with no entry reports none rather
// than guessing.
func (r *hashRegistry) johnLabel(name string) (string, bool) {
	canonical := canonicalHashType(name)
	if _, ok := r.formats[canonical]; !ok {
		return "", false
	}
	label, ok := johnLabels[canonical]
	return label, ok
}

var johnLabels = johnLabelSeed()
```

Add `"strconv"` to that file's imports.

Create `cmd/hashsmith/hash_john_labels.go`:

```go
package main

// johnLabelSeed maps a canonical Hashsmith format to the label John the Ripper
// accepts after --format=.
//
// This is deliberately a separate, hand-curated table rather than a filter over
// the alias map. Aliases are an INPUT vocabulary — every spelling anyone might
// type — and they carry no provenance, so "raw-md5" and "md-5" are the same
// kind of thing there. Reporting a John label is an OUTPUT claim about another
// tool's interface, and it has to be right or not made at all.
//
// Coverage is intentionally incremental: a format absent from this table prints
// "-" in identify's john column, and `identify --coverage` counts the gap.
func johnLabelSeed() map[string]string {
	return map[string]string{
		// Raw digests
		"md4": "raw-md4", "md5": "raw-md5", "sha1": "raw-sha1",
		"sha224": "raw-sha224", "sha256": "raw-sha256",
		"sha384": "raw-sha384", "sha512": "raw-sha512",
		"ripemd128": "ripemd-128", "ripemd160": "ripemd-160",
		"whirlpool": "whirlpool", "sm3": "sm3",

		// Windows
		"ntlm": "NT", "lm": "LM",
		"netntlmv1": "netntlmv1", "netntlmv2": "netntlmv2",
		"mscash": "mscash", "dcc2": "mscash2",

		// Unix crypt(3)
		"descrypt": "descrypt", "bsdicrypt": "bsdicrypt",
		"md5crypt": "md5crypt", "bcrypt": "bcrypt",
		"sha256crypt": "sha256crypt", "sha512crypt": "sha512crypt",
		"sha1crypt": "sha1crypt", "apr1": "md5crypt",

		// Databases
		"mysql323": "mysql", "mysql41": "mysql-sha1",
		"mssql2005": "mssql05", "mssql2012": "mssql12",
		"oracle11g": "oracle11", "oracle12c": "oracle12c",
		"postgres": "postgres", "sybase": "sybasease",

		// Kerberos
		"krb5tgs": "krb5tgs", "krb5asrep": "krb5asrep", "krb5pa": "krb5pa-sha1",

		// Containers and archives
		"7z": "7z", "rar4": "rar", "rar5": "rar5",
		"zipcrypto": "PKZIP", "zipaes256": "ZIP",
		"pdf": "PDF", "office": "office", "keepass": "KeePass",
		"ssh": "SSH", "pfx": "pfx", "gpg": "gpg",
		"luks": "LUKS", "truecrypt": "truecrypt", "veracrypt": "VeraCrypt",
		"pwsafe": "pwsafe", "dmg": "dmg",

		// Applications
		"phpass": "phpass", "drupal7": "Drupal7", "django": "django",
		"wordpress": "phpass", "mediawiki": "mediawiki",
		"vbulletin": "vbulletin", "ldap": "ssha",
		"racf": "racf", "sap-b": "sapb", "sap-fg": "sapg",
		"cisco-pix": "pix-md5", "cisco-asa": "asa-md5",
		"juniper": "md5crypt", "grub2": "grub",
		"bitcoin": "bitcoin", "ethereum": "ethereum-opencl",
		"wpa": "wpapsk", "vnc": "VNC", "sip": "SIP",
	}
}
```

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./cmd/hashsmith -run 'TestHashcatMode|TestJohnLabel|TestUnknownFormatHasNoMetadata' -count=1 -v
```

Expected: PASS. If `TestJohnLabelSeedNamesRealFormats` fails, a canonical name
above is wrong for this tree — check it with
`grep -n '"<name>"' cmd/hashsmith/types.go` and correct the seed. **Do not
delete the assertion to make it pass**; a wrong label is worse than none.

- [ ] **Step 5: Record the coverage number**

```bash
go run ./cmd/hashsmith -N types | wc -l
```

Then add a short note to the plan's Task 15 measurement section stating how
many of 457 formats now report a John label. This number is quoted in the
README in Task 19, so it must be measured, not estimated.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/hash_registry.go cmd/hashsmith/hash_john_labels.go cmd/hashsmith/hash_registry_lookup_test.go
git commit -m "feat(registry): report Hashcat modes and John labels for a format"
```

---

## Task 13: The new identify output

**Files:**
- Create: `cmd/hashsmith/identify_output.go`
- Create: `cmd/hashsmith/identify_output_test.go`
- Modify: `cmd/hashsmith/identify.go:132-190` — replace `identifyText`
- Delete from `cmd/hashsmith/identify.go`: `scoreCandidates`, `signatureMatch`, `scoreHashGroup`, `scoreEncodingGroup`, `scoreStructuralGroup`, `scoreCipherTextGroup`, `knownHashLen`, and the `candidate` type (lines 191-1030)

**Interfaces:**
- Consumes: `identifyCandidates` (Task 10), `hashcatMode`/`johnLabel` (Task 12), `hashid.Candidate`
- Produces: `func renderIdentifyHuman(input string, cs []hashid.Candidate) string`

> **Note on the deleted scorers.** `scoreEncodingGroup`, `scoreStructuralGroup`
> and `scoreCipherTextGroup` recognize things that are not hashes — Base64,
> Morse, ROT13, Bubble Babble, plain text. hashid and Name-That-Hash cannot do
> this at all, so the capability must survive the deletion, not be dropped with
> the scorer that happened to hold it.
>
> Port each check into the prototype table as a `TierStructural` or `TierShape`
> prototype. Each needs a real codec type name in `Types` — `Prototype.Types`
> may not be empty, and Task 11 enforces that — so use the name the codec
> registry already knows:
>
> ```bash
> go run ./cmd/hashsmith -N encodings | grep -w base64
> ```
>
> giving `Types: []string{"base64"}`. Task 11's integrity test will reject any
> name that does not resolve, so a mistake here fails the build rather than
> printing a type nothing can consume.

- [ ] **Step 1: Write the failing tests**

Create `cmd/hashsmith/identify_output_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestHumanOutputCarriesModeAndCommand(t *testing.T) {
	out := renderIdentifyHuman("5f4dcc3b5aa765d61d8327deb882cf99",
		identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99"))

	for _, want := range []string{"MD5", "likely", "-m 0", "raw-md5", "-t md5"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	if !strings.Contains(out, "hashsmith crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99") {
		t.Errorf("output missing the runnable crack command\n---\n%s", out)
	}
}

// A format Hashcat and John do not have must still be listed, with the gap
// shown rather than hidden. This is the coverage advantage made visible.
func TestFormatsWithoutForeignNamesPrintADash(t *testing.T) {
	out := renderIdentifyHuman("x", []hashid.Candidate{{
		Type: "hmailserver", Display: "hMailServer",
		Confidence: hashid.Certain, Tier: hashid.TierSignature,
		Evidence: "record prefix",
	}})
	if !strings.Contains(out, "-") {
		t.Errorf("expected a dash for the missing Hashcat mode\n---\n%s", out)
	}
	if strings.Contains(out, "-m 0") {
		t.Errorf("invented a Hashcat mode for a format that has none\n---\n%s", out)
	}
}

func TestBcryptIsASingleCertainAnswer(t *testing.T) {
	cs := identifyCandidates("$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS")
	if len(cs) == 0 || cs[0].Type != "bcrypt" || cs[0].Confidence != hashid.Certain {
		t.Fatalf("bcrypt = %+v, want a single certain bcrypt candidate", cs)
	}
}

func TestUnrecognizedInputSaysSo(t *testing.T) {
	out := renderIdentifyHuman("not a hash at all", identifyCandidates("not a hash at all"))
	if !strings.Contains(strings.ToLower(out), "no candidate") {
		t.Errorf("expected an explicit no-candidate message\n---\n%s", out)
	}
}
```

Add `"hashsmith-go/internal/hashid"` to the test imports.

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./cmd/hashsmith -run 'TestHumanOutput|TestFormatsWithout|TestBcryptIsA|TestUnrecognizedInput' -count=1
```

Expected: FAIL — `undefined: renderIdentifyHuman`.

- [ ] **Step 3: Write the implementation**

Create `cmd/hashsmith/identify_output.go`:

```go
package main

import (
	"fmt"
	"hashsmith-go/internal/hashid"
	"strconv"
	"strings"
)

// renderIdentifyHuman formats candidates for a terminal.
//
// Every row carries what the user needs to act: the confidence, the Hashcat
// mode, the John label, the Hashsmith type, and — for the leading candidate —
// a command that can be pasted. A format with no foreign equivalent prints "-",
// which is how Hashsmith's coverage advantage stays visible instead of being
// asserted in documentation.
func renderIdentifyHuman(input string, cs []hashid.Candidate) string {
	if len(cs) == 0 {
		return "  no candidate identified\n\n  " +
			"The input matched no known format. If it is a container file, try:\n" +
			"      hashsmith identify <file>"
	}

	type row struct{ name, conf, mode, john, typ, note string }
	rows := make([]row, 0, len(cs))
	for _, c := range cs {
		r := row{name: c.Display, conf: c.Confidence.String(), typ: "-t " + c.Type, note: c.Reason}
		if m, ok := universalHashRegistry.hashcatMode(c.Type); ok {
			r.mode = "-m " + strconv.Itoa(m)
		} else {
			r.mode = "-"
		}
		if l, ok := universalHashRegistry.johnLabel(c.Type); ok {
			r.john = l
		} else {
			r.john = "-"
		}
		rows = append(rows, r)
	}

	w := func(sel func(row) string) int {
		max := 0
		for _, r := range rows {
			if n := len(sel(r)); n > max {
				max = n
			}
		}
		return max
	}
	wName, wConf := w(func(r row) string { return r.name }), w(func(r row) string { return r.conf })
	wMode, wJohn := w(func(r row) string { return r.mode }), w(func(r row) string { return r.john })
	wType := w(func(r row) string { return r.typ })

	var sb strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&sb, "  %-*s  %-*s  %-*s  %-*s  %-*s",
			wName, r.name, wConf, r.conf, wMode, r.mode, wJohn, r.john, wType, r.typ)
		if r.note != "" {
			fmt.Fprintf(&sb, "  %s", r.note)
		}
		sb.WriteByte('\n')
	}

	if ev := cs[0].Evidence; ev != "" {
		fmt.Fprintf(&sb, "\n  %s\n", ev)
	}
	fmt.Fprintf(&sb, "  hashsmith crack -t %s %s\n", cs[0].Type, input)
	return sb.String()
}
```

Replace `identifyText`'s body in `identify.go` with:

```go
func identifyText(value string) string {
	return renderIdentifyHuman(strings.TrimSpace(value), identifyCandidates(value))
}
```

Then delete the old scoring engine: `scoreCandidates`, `signatureMatch`, the
four `score*Group` functions, `knownHashLen`, and the `candidate` type. Before
deleting each, port its non-hash recognitions into the table per the note above.
Compile after each deletion — the helpers below them (`shannonEntropy`,
`isMorseStr`, `isBase85Str`, …) are still used by the ported prototypes and
must stay.

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./cmd/hashsmith -run 'TestHumanOutput|TestFormatsWithout|TestBcryptIsA|TestUnrecognizedInput' -count=1 -v
go test ./... -count=1
```

Expected: PASS, golden included.

- [ ] **Step 5: Look at the real output**

```bash
go run ./cmd/hashsmith -N identify 5f4dcc3b5aa765d61d8327deb882cf99
go run ./cmd/hashsmith -N identify '$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS'
go run ./cmd/hashsmith -N identify 'aGVsbG8gd29ybGQ='
```

Columns must line up, the crack command must be runnable, and the Base64 case
must still be recognized. If Base64 is gone, a scorer was deleted without
porting it.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/identify_output.go cmd/hashsmith/identify_output_test.go cmd/hashsmith/identify.go cmd/hashsmith/prototypes*.go
git commit -m "feat(identify): report modes, labels and a runnable command"
```

---

## Task 14: JSON output and exit codes

**Files:**
- Modify: `cmd/hashsmith/identify_output.go`
- Modify: `cmd/hashsmith/identify.go:63-110` — `runIdentify` flags
- Modify: `cmd/hashsmith/main.go:86-89` — propagate the exit code
- Create: `cmd/hashsmith/identify_json_test.go`

**Interfaces:**
- Consumes: `hashid.Candidate`, `hashcatMode`, `johnLabel`
- Produces:
  - `type identifyReport struct` with JSON tags matching schema `hashsmith.identify/1`
  - `func buildIdentifyReport(input string, cs []hashid.Candidate) identifyReport`
  - `func identifyExitCode(cs []hashid.Candidate) int`

- [ ] **Step 1: Write the failing tests**

Create `cmd/hashsmith/identify_json_test.go`:

```go
package main

import (
	"encoding/json"
	"testing"

	"hashsmith-go/internal/hashid"
)

func TestJSONReportShape(t *testing.T) {
	rep := buildIdentifyReport("5f4dcc3b5aa765d61d8327deb882cf99",
		identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99"))
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back["schema"] != "hashsmith.identify/1" {
		t.Errorf("schema = %v, want hashsmith.identify/1", back["schema"])
	}
	cands, ok := back["candidates"].([]any)
	if !ok || len(cands) == 0 {
		t.Fatalf("candidates = %v, want a non-empty array", back["candidates"])
	}
	first := cands[0].(map[string]any)
	for _, k := range []string{"name", "type", "confidence", "tier", "hashcat", "john", "evidence", "rationale", "command"} {
		if _, present := first[k]; !present {
			t.Errorf("candidate is missing key %q", k)
		}
	}
	if first["hashcat"] != float64(0) {
		t.Errorf("md5 hashcat = %v, want 0", first["hashcat"])
	}
}

// A missing mode must be null, never 0 — 0 is a real Hashcat mode (MD5).
func TestMissingHashcatModeIsNull(t *testing.T) {
	rep := buildIdentifyReport("x", []hashid.Candidate{{
		Type: "hmailserver", Display: "hMailServer", Confidence: hashid.Certain,
	}})
	blob, _ := json.Marshal(rep)
	var back map[string]any
	_ = json.Unmarshal(blob, &back)
	first := back["candidates"].([]any)[0].(map[string]any)
	if first["hashcat"] != nil {
		t.Errorf("hashcat = %v, want null; 0 is MD5's real mode and must not double as 'absent'", first["hashcat"])
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name  string
		cs    []hashid.Candidate
		want  int
	}{
		{"certain", []hashid.Candidate{{Confidence: hashid.Certain}}, 0},
		{"likely", []hashid.Candidate{{Confidence: hashid.Likely}}, 0},
		{"possible only", []hashid.Candidate{{Confidence: hashid.Possible}}, 1},
		{"unlikely only", []hashid.Candidate{{Confidence: hashid.Unlikely}}, 1},
		{"none", nil, 1},
	}
	for _, c := range cases {
		if got := identifyExitCode(c.cs); got != c.want {
			t.Errorf("%s: exit = %d, want %d", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./cmd/hashsmith -run 'TestJSONReportShape|TestMissingHashcatModeIsNull|TestExitCodes' -count=1
```

Expected: FAIL — `undefined: buildIdentifyReport`.

- [ ] **Step 3: Write the implementation**

Append to `cmd/hashsmith/identify_output.go`:

```go
// identifyCandidateJSON is one candidate in the machine-readable report.
//
// Hashcat is *int, not int, because 0 is MD5's real mode number: a plain int
// could not distinguish "mode 0" from "no mode", and a consumer would read
// every unknown format as MD5.
type identifyCandidateJSON struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Confidence string  `json:"confidence"`
	Tier       string  `json:"tier"`
	Hashcat    *int    `json:"hashcat"`
	John       *string `json:"john"`
	Evidence   string  `json:"evidence"`
	Rationale  string  `json:"rationale"`
	Command    string  `json:"command"`
	Suppressed bool    `json:"suppressed,omitempty"`
}

type identifyReport struct {
	Schema     string                  `json:"schema"`
	Input      string                  `json:"input"`
	Normalized string                  `json:"normalized"`
	Candidates []identifyCandidateJSON `json:"candidates"`
}

// identifySchemaVersion is versioned from the first release so fields can be
// added later without breaking anything parsing this output.
const identifySchemaVersion = "hashsmith.identify/1"

func buildIdentifyReport(input string, cs []hashid.Candidate) identifyReport {
	rep := identifyReport{
		Schema:     identifySchemaVersion,
		Input:      input,
		Normalized: stripShadowUsername(strings.TrimSpace(input)),
		Candidates: make([]identifyCandidateJSON, 0, len(cs)),
	}
	for _, c := range cs {
		item := identifyCandidateJSON{
			Name: c.Display, Type: c.Type,
			Confidence: c.Confidence.String(), Tier: c.Tier.String(),
			Evidence: string(c.Evidence), Rationale: c.Reason,
			Command:    "hashsmith crack -t " + c.Type + " " + input,
			Suppressed: c.Suppressed,
		}
		if m, ok := universalHashRegistry.hashcatMode(c.Type); ok {
			mode := m
			item.Hashcat = &mode
		}
		if l, ok := universalHashRegistry.johnLabel(c.Type); ok {
			label := l
			item.John = &label
		}
		rep.Candidates = append(rep.Candidates, item)
	}
	return rep
}

// identifyExitCode lets identify participate in shell chains: 0 means the tool
// is willing to commit to an answer, 1 means it is not. It deliberately mirrors
// crack's 0/1/2 contract, where 2 is reserved for usage and I/O errors and is
// returned by the caller, not here.
func identifyExitCode(cs []hashid.Candidate) int {
	for _, c := range cs {
		if c.Suppressed {
			continue
		}
		if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
			return 0
		}
	}
	return 1
}
```

In `runIdentify` (`identify.go`), add the flags and wire the exit code:

```go
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
```

and after `inputs` is resolved, branch on `*asJSON` to marshal
`buildIdentifyReport` per input with `json.MarshalIndent(rep, "", "  ")`,
otherwise use the existing human path. Have `runIdentify` return a sentinel
error carrying the exit code, and in `main.go`'s `case "identify":` translate
it. Follow the pattern `runCrack` already uses at `main.go:82-85` for its own
exit code rather than inventing a second mechanism.

Add `"encoding/json"` to `identify.go`'s imports.

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./cmd/hashsmith -run 'TestJSONReportShape|TestMissingHashcatModeIsNull|TestExitCodes' -count=1 -v
go test ./... -count=1
```

- [ ] **Step 5: Verify the exit codes end to end**

```bash
go build -o /tmp/hs ./cmd/hashsmith
/tmp/hs -N identify --json 5f4dcc3b5aa765d61d8327deb882cf99 | head -20
/tmp/hs -N identify '$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS' >/dev/null; echo "bcrypt exit=$?"
/tmp/hs -N identify 'zzzz' >/dev/null; echo "garbage exit=$?"
```

Expected: valid JSON; `bcrypt exit=0`; `garbage exit=1`.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/identify_output.go cmd/hashsmith/identify_json_test.go cmd/hashsmith/identify.go cmd/hashsmith/main.go
git commit -m "feat(identify): add JSON output and script-friendly exit codes"
```

---

## Task 15: Measure recognition accuracy honestly

Nothing currently proves detection is correct — only that hashing is. This task
measures the truth and writes it down, whatever it is.

**Files:**
- Create: `cmd/hashsmith/recognition_test.go`
- Create: `docs/superpowers/notes/2026-09-04-recognition-baseline.md`

**Interfaces:**
- Consumes: `universalHashRegistry.vectors`, `identifyCandidates`, `detectHashTypes`

- [ ] **Step 1: Write the measurement test**

Create `cmd/hashsmith/recognition_test.go`:

```go
package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

// recognitionFloor is a ratchet, not a target. Raise it as coverage improves;
// never lower it to make a change pass.
const recognitionFloor = 0.0 // set from the first measured run, see Step 3

func TestRecognitionAccuracy(t *testing.T) {
	var total, recognized int
	missed := map[string]string{}

	for _, v := range universalHashRegistry.vectors {
		if v.target == "" {
			continue
		}
		total++
		ok := false
		for _, c := range identifyCandidates(v.target) {
			if c.Suppressed || c.Type != v.typ {
				continue
			}
			if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
				ok = true
			}
			break
		}
		if ok {
			recognized++
		} else if _, dup := missed[v.typ]; !dup {
			missed[v.typ] = v.target
		}
	}

	rate := float64(recognized) / float64(total)
	names := make([]string, 0, len(missed))
	for k := range missed {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("recognition: %d/%d = %.1f%%", recognized, total, rate*100)
	t.Logf("formats not recognized at certain/likely (%d): %s",
		len(names), strings.Join(names, " "))

	if rate < recognitionFloor {
		t.Fatalf("recognition rate %.3f fell below the ratchet %.3f", rate, recognitionFloor)
	}
}

// Every vector must at least be CRACKABLE by auto-detection, which is a weaker
// and more important property than being confidently named.
func TestEveryVectorIsDetectableForCracking(t *testing.T) {
	var missing []string
	for _, v := range universalHashRegistry.vectors {
		if v.target == "" {
			continue
		}
		found := false
		for _, typ := range detectHashTypes(v.target) {
			if typ == v.typ {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, fmt.Sprintf("%s (%.40s)", v.typ, v.target))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Logf("%d vectors whose own type is not among detectHashTypes' candidates:", len(missing))
		for _, m := range missing {
			t.Log("  " + m)
		}
	}
}

func TestFalsePositives(t *testing.T) {
	notHashes := []string{
		"the quick brown fox jumps over the lazy dog",
		"hello world",
		"550e8400-e29b-41d4-a716-446655440000",
		"/usr/local/bin/hashsmith",
		"1234",
		"{}",
	}
	for _, in := range notHashes {
		for _, c := range identifyCandidates(in) {
			if !c.Suppressed && c.Confidence == hashid.Certain {
				t.Errorf("%q was identified as %s with certainty", in, c.Display)
			}
		}
	}
}
```

- [ ] **Step 2: Run it and read the numbers**

```bash
cd hashsmith/go_hashsmith
go test ./cmd/hashsmith -run 'TestRecognition|TestEveryVectorIsDetectable|TestFalsePositives' -count=1 -v 2>&1 | tee /tmp/recognition.txt
```

`TestRecognitionAccuracy` cannot fail at this point (`recognitionFloor` is 0).
`TestFalsePositives` may fail — if it does, that is a real defect: fix the
prototype that over-claims, usually by lowering its `Tier` from
`TierSignature` to `TierStructural`.

- [ ] **Step 3: Write the baseline down**

Create `docs/superpowers/notes/2026-09-04-recognition-baseline.md` recording,
from `/tmp/recognition.txt` verbatim: the recognition rate, the count and list
of formats not recognized at certain/likely, the count of vectors whose own
type is not a detection candidate, and the John-label coverage measured in
Task 12. State the date and the commit. **Do not round the numbers up and do
not editorialize them.**

Then set `recognitionFloor` to the measured rate minus 0.01 so it becomes a
ratchet against regression.

- [ ] **Step 4: Fix the cheapest misses**

Take the formats listed as unrecognized and fix those whose cause is a missing
or mis-tiered prototype. Re-run after each fix. Stop when the remaining misses
need real new detection logic rather than a table correction; leave those
listed in the baseline note as known gaps.

- [ ] **Step 5: Run everything and commit**

```bash
go test ./... -count=1
git add cmd/hashsmith/recognition_test.go docs/superpowers/notes/2026-09-04-recognition-baseline.md cmd/hashsmith/prototypes*.go
git commit -m "test(identify): measure recognition accuracy and record the baseline"
```

---

## Task 16: Identify container files and route them to their extractor

No other identification tool accepts a container file. `hashid`, `haiti` and
`Name-That-Hash` take text only; Hashcat and John recognize the file but send
you to an out-of-tree converter. Hashsmith has all 47 extractors in the same
binary, so this closes the loop.

**Files:**
- Create: `cmd/hashsmith/sniff.go`
- Create: `cmd/hashsmith/sniff_test.go`
- Modify: `cmd/hashsmith/extractor_registry.go:12-19` — add the `sniff` field
- Modify: `cmd/hashsmith/identify.go` — file-path branch in `runIdentify`

**Interfaces:**
- Consumes: `universalExtractorRegistry`, `hashid.Evidence`
- Produces:
  - `sniff func(head []byte) (hashid.Evidence, bool)` field on `extractorDefinition`
  - `func sniffContainer(path string) (*extractorDefinition, hashid.Evidence, bool)`
  - `func renderContainerIdentification(path string, d *extractorDefinition, ev hashid.Evidence) string`
  - `func sniffCoverage() (withSniff, total int)`

- [ ] **Step 1: Write the failing tests**

Create `cmd/hashsmith/sniff_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSniffKeePassKDBX4(t *testing.T) {
	// KDBX signature: 0x9AA2D903 0xB54BFB67, then minor/major version words.
	head := []byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x00, 0x00, 0x04, 0x00}
	head = append(head, make([]byte, 64)...)
	p := writeTemp(t, "Database.kdbx", head)

	d, ev, ok := sniffContainer(p)
	if !ok {
		t.Fatal("KDBX file was not recognized")
	}
	if d.name != "keepass2smith" {
		t.Errorf("routed to %s, want keepass2smith", d.name)
	}
	if !strings.Contains(string(ev), "KDBX") {
		t.Errorf("evidence = %q, want it to mention KDBX", ev)
	}
}

func TestSniffZip(t *testing.T) {
	p := writeTemp(t, "archive.zip", append([]byte("PK\x03\x04"), make([]byte, 64)...))
	d, _, ok := sniffContainer(p)
	if !ok || d.name != "zip2smith" {
		t.Fatalf("zip routed to %v (ok=%v), want zip2smith", d, ok)
	}
}

func TestSniffPDF(t *testing.T) {
	p := writeTemp(t, "doc.pdf", append([]byte("%PDF-1.7\n"), make([]byte, 64)...))
	d, _, ok := sniffContainer(p)
	if !ok || d.name != "pdf2smith" {
		t.Fatalf("pdf routed to %v (ok=%v), want pdf2smith", d, ok)
	}
}

func TestSniffRejectsPlainText(t *testing.T) {
	p := writeTemp(t, "hashes.txt", []byte("5f4dcc3b5aa765d61d8327deb882cf99\n"))
	if _, _, ok := sniffContainer(p); ok {
		t.Error("a text file of hashes must not be treated as a container")
	}
}

func TestContainerOutputNamesTheExtractorCommand(t *testing.T) {
	d, _ := findExtractor("keepass2smith")
	out := renderContainerIdentification("Database.kdbx", d, "KDBX 4.0, KDF Argon2d")
	if !strings.Contains(out, "hashsmith keepass2smith -f Database.kdbx") {
		t.Errorf("output missing the runnable extractor command\n---\n%s", out)
	}
}

func TestSniffCoverageIsReported(t *testing.T) {
	with, total := sniffCoverage()
	if total != len(universalExtractorRegistry) {
		t.Errorf("total = %d, want %d", total, len(universalExtractorRegistry))
	}
	if with == 0 {
		t.Error("no extractor implements sniff")
	}
	t.Logf("sniff coverage: %d/%d extractors", with, total)
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./cmd/hashsmith -run TestSniff -count=1
```

Expected: FAIL — `undefined: sniffContainer`.

- [ ] **Step 3: Write the implementation**

Add the field to `extractorDefinition` in `extractor_registry.go`:

```go
	// sniff recognizes this extractor's container from the file's first bytes.
	// It is optional: an extractor without one is simply never auto-routed, and
	// sniffCoverage reports the gap rather than hiding it.
	sniff func(head []byte) (hashid.Evidence, bool)
```

Add `"hashsmith-go/internal/hashid"` to that file's imports.

Create `cmd/hashsmith/sniff.go`:

```go
package main

import (
	"encoding/binary"
	"fmt"
	"hashsmith-go/internal/hashid"
	"io"
	"os"
	"strings"
)

// sniffHeadBytes is how much of a file the magic-byte checks see. 4 KiB covers
// every signature below with room for the ones with offset headers.
const sniffHeadBytes = 4096

// magicSniff builds the common case: a fixed byte prefix identifies the format.
func magicSniff(magic []byte, evidence string) func([]byte) (hashid.Evidence, bool) {
	return func(head []byte) (hashid.Evidence, bool) {
		if len(head) >= len(magic) && string(head[:len(magic)]) == string(magic) {
			return hashid.Evidence(evidence), true
		}
		return "", false
	}
}

// sniffKeePass reads the KDBX version words after the two signature words, so
// the answer names KDBX 3 or 4 — which decides whether the KDF is AES or Argon2
// and therefore how expensive the crack will be.
func sniffKeePass(head []byte) (hashid.Evidence, bool) {
	if len(head) < 12 {
		return "", false
	}
	if binary.LittleEndian.Uint32(head[0:4]) != 0x9AA2D903 {
		return "", false
	}
	sig2 := binary.LittleEndian.Uint32(head[4:8])
	if sig2 != 0xB54BFB67 && sig2 != 0xB54BFB66 && sig2 != 0xB54BFB65 {
		return "", false
	}
	major := binary.LittleEndian.Uint16(head[10:12])
	return hashid.Evidence(fmt.Sprintf(
		"signature 0x9AA2D903 0x%08X, KDBX %d.x", sig2, major)), true
}

// installSniffers attaches the magic-byte recognizers to the extractor
// registry. It lives here rather than in the registry literal so the registry
// stays a readable one-line-per-extractor table.
func installSniffers() {
	set := func(name string, fn func([]byte) (hashid.Evidence, bool)) {
		d, ok := findExtractor(name)
		if !ok {
			panic("sniffer for unknown extractor " + name)
		}
		d.sniff = fn
	}
	set("keepass2smith", sniffKeePass)
	set("zip2smith", magicSniff([]byte("PK\x03\x04"), "ZIP local file header"))
	set("7z2smith", magicSniff([]byte("7z\xBC\xAF\x27\x1C"), "7-Zip signature"))
	set("rar2smith", magicSniff([]byte("Rar!\x1A\x07"), "RAR signature"))
	set("pdf2smith", magicSniff([]byte("%PDF-"), "PDF header"))
	set("pfx2smith", magicSniff([]byte{0x30, 0x82}, "DER SEQUENCE, PKCS#12 candidate"))
	set("gpg2smith", magicSniff([]byte("-----BEGIN PGP"), "ASCII-armoured OpenPGP block"))
	set("ssh2smith", magicSniff([]byte("-----BEGIN OPENSSH PRIVATE KEY"), "OpenSSH private key"))
	set("luks2smith", magicSniff([]byte("LUKS\xBA\xBE"), "LUKS1 header"))
	set("pwsafe2smith", magicSniff([]byte("PWS3"), "Password Safe v3 header"))
	set("truecrypt2smith", magicSniff([]byte("TRUE"), "TrueCrypt volume header"))
	set("office2smith", magicSniff([]byte{0xD0, 0xCF, 0x11, 0xE0}, "OLE2 compound document"))
	set("bitcoin2smith", magicSniff([]byte("SQLite format 3\x00"), "SQLite database, Bitcoin Core wallet candidate"))
	set("hccapx2smith", magicSniff([]byte("HCPX"), "hccapx capture"))
}

func init() { installSniffers() }

// sniffContainer reports which extractor handles a file, if any.
func sniffContainer(path string) (*extractorDefinition, hashid.Evidence, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", false
	}
	defer f.Close()

	head := make([]byte, sniffHeadBytes)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, "", false
	}
	head = head[:n]

	for i := range universalExtractorRegistry {
		d := &universalExtractorRegistry[i]
		if d.sniff == nil {
			continue
		}
		if ev, ok := d.sniff(head); ok {
			return d, ev, true
		}
	}
	return nil, "", false
}

// renderContainerIdentification tells the user this is a container and what to
// run on it. Extraction is NOT performed automatically: it writes files and can
// be slow, and identify is a read-only question.
func renderContainerIdentification(path string, d *extractorDefinition, ev hashid.Evidence) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %s        certain\n", d.input)
	if ev != "" {
		fmt.Fprintf(&sb, "  %s\n", ev)
	}
	fmt.Fprintf(&sb, "\n  This is a container, not a hash. Extract the record first:\n")
	fmt.Fprintf(&sb, "      hashsmith %s -f %s\n", d.name, path)
	return sb.String()
}

// sniffCoverage reports how many extractors can be auto-routed. The gap is
// published by `identify --coverage` rather than left as an unstated limit.
func sniffCoverage() (withSniff, total int) {
	total = len(universalExtractorRegistry)
	for i := range universalExtractorRegistry {
		if universalExtractorRegistry[i].sniff != nil {
			withSniff++
		}
	}
	return withSniff, total
}
```

In `runIdentify`, before treating a path as a list of hashes, try the sniffer:

```go
	// A readable file that a sniffer recognizes is a container, not a hash list.
	for _, arg := range fs.Args() {
		if d, ev, ok := sniffContainer(arg); ok {
			color.New(themeAttr).Fprintln(os.Stdout, renderContainerIdentification(arg, d, ev))
			return nil
		}
	}
```

Add a `--coverage` flag that prints both coverage numbers and returns:

```go
	if *coverage {
		withSniff, totalExtractors := sniffCoverage()
		withJohn := 0
		for name := range universalHashRegistry.formats {
			if _, ok := universalHashRegistry.johnLabel(name); ok {
				withJohn++
			}
		}
		fmt.Printf("container sniffers: %d/%d extractors\n", withSniff, totalExtractors)
		fmt.Printf("John labels:        %d/%d formats\n", withJohn, len(universalHashRegistry.formats))
		return nil
	}
```

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./cmd/hashsmith -run TestSniff -count=1 -v
go test ./... -count=1
```

- [ ] **Step 5: Check it end to end**

```bash
go build -o /tmp/hs ./cmd/hashsmith
printf 'PK\x03\x04' > /tmp/probe.zip && head -c 200 /dev/zero >> /tmp/probe.zip
/tmp/hs -N identify /tmp/probe.zip
/tmp/hs -N identify --coverage
printf '5f4dcc3b5aa765d61d8327deb882cf99\n' > /tmp/probe.txt
/tmp/hs -N identify /tmp/probe.txt
```

Expected: the zip routes to `zip2smith`; `--coverage` prints both ratios; the
text file is still read as a hash list, **not** as a container.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/sniff.go cmd/hashsmith/sniff_test.go cmd/hashsmith/extractor_registry.go cmd/hashsmith/identify.go
git commit -m "feat(identify): recognize container files and route them to their extractor"
```

---

## Task 17: Batch mode

**Files:**
- Create: `cmd/hashsmith/identify_batch.go`
- Create: `cmd/hashsmith/identify_batch_test.go`
- Modify: `cmd/hashsmith/identify.go` — `--summary`, `--split-by-type`, `--unmatched` flags

**Interfaces:**
- Consumes: `identifyCandidates`, `stripShadowUsername`
- Produces:
  - `type batchStats struct { Total, Identified int; ByType map[string]int; Unmatched []string }`
  - `func scanBatch(r io.Reader) batchStats`
  - `func renderBatchSummary(s batchStats) string`
  - `func splitByType(s batchStats, dir string) error` — `batchStats.Lines` already carries the per-type lines, so it is not passed separately

- [ ] **Step 1: Write the failing tests**

Create `cmd/hashsmith/identify_batch_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

const sampleDump = `5f4dcc3b5aa765d61d8327deb882cf99
$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS
5f4dcc3b5aa765d61d8327deb882cf99

# a comment line
not a hash at all
root:$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/
`

func TestScanBatchCountsAndClassifies(t *testing.T) {
	s := scanBatch(strings.NewReader(sampleDump))
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5 (blank and comment lines are skipped)", s.Total)
	}
	if s.ByType["md5"] != 2 {
		t.Errorf("md5 count = %d, want 2", s.ByType["md5"])
	}
	if s.ByType["bcrypt"] != 1 {
		t.Errorf("bcrypt count = %d, want 1", s.ByType["bcrypt"])
	}
	if s.ByType["sha512crypt"] != 1 {
		t.Errorf("sha512crypt count = %d, want 1 (a shadow line must be peeled)", s.ByType["sha512crypt"])
	}
	if len(s.Unmatched) != 1 || s.Unmatched[0] != "not a hash at all" {
		t.Errorf("Unmatched = %v, want exactly the non-hash line", s.Unmatched)
	}
}

// The percentages here are counts over lines — measured quantities, unlike the
// normalized scores the old identify printed.
func TestBatchSummaryPercentagesAreLineCounts(t *testing.T) {
	s := scanBatch(strings.NewReader(sampleDump))
	out := renderBatchSummary(s)
	if !strings.Contains(out, "5 lines scanned") {
		t.Errorf("summary missing the scanned count\n---\n%s", out)
	}
	if !strings.Contains(out, "40.0%") {
		t.Errorf("summary missing md5's 2/5 = 40.0%%\n---\n%s", out)
	}
}

func TestEmptyInputDoesNotDivideByZero(t *testing.T) {
	out := renderBatchSummary(scanBatch(strings.NewReader("")))
	if !strings.Contains(out, "0 lines scanned") {
		t.Errorf("empty input summary = %q", out)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./cmd/hashsmith -run 'TestScanBatch|TestBatchSummary|TestEmptyInput' -count=1
```

Expected: FAIL — `undefined: scanBatch`.

- [ ] **Step 3: Write the implementation**

Create `cmd/hashsmith/identify_batch.go`:

```go
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"hashsmith-go/internal/hashid"
)

// batchStats is the tally over a dump. ByType counts LINES, so the percentages
// rendered from it are measured proportions rather than heuristic scores.
type batchStats struct {
	Total      int
	Identified int
	ByType     map[string]int
	Confidence map[string]string
	Lines      map[string][]string
	Unmatched  []string
}

// batchLineScanBuffer matches scan2smith's, so a dump one command can read is
// readable by the other.
const batchLineScanBuffer = 4 * 1024 * 1024

func scanBatch(r io.Reader) batchStats {
	s := batchStats{
		ByType:     map[string]int{},
		Confidence: map[string]string{},
		Lines:      map[string][]string{},
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), batchLineScanBuffer)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.Total++

		var best *hashid.Candidate
		for _, c := range identifyCandidates(line) {
			if c.Suppressed {
				continue
			}
			if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
				candidate := c
				best = &candidate
				break
			}
		}
		if best == nil {
			s.Unmatched = append(s.Unmatched, line)
			continue
		}
		s.Identified++
		s.ByType[best.Type]++
		s.Confidence[best.Type] = best.Confidence.String()
		s.Lines[best.Type] = append(s.Lines[best.Type], line)
	}
	return s
}

func renderBatchSummary(s batchStats) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %d lines scanned · %d identified · %d unidentified\n\n",
		s.Total, s.Identified, len(s.Unmatched))

	types := make([]string, 0, len(s.ByType))
	for t := range s.ByType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		if s.ByType[types[i]] != s.ByType[types[j]] {
			return s.ByType[types[i]] > s.ByType[types[j]]
		}
		return types[i] < types[j]
	})

	for _, t := range types {
		pct := 0.0
		if s.Total > 0 {
			pct = float64(s.ByType[t]) / float64(s.Total) * 100
		}
		mode := "-"
		if m, ok := universalHashRegistry.hashcatMode(t); ok {
			mode = fmt.Sprintf("-m %d", m)
		}
		fmt.Fprintf(&sb, "  %-16s %6d  %5.1f%%   %-9s %s\n",
			t, s.ByType[t], pct, s.Confidence[t], mode)
	}
	if len(s.Unmatched) > 0 {
		fmt.Fprintf(&sb, "\n  Unidentified lines: --unmatched <file>\n")
	}
	if len(types) > 1 {
		fmt.Fprintf(&sb, "  Split by type:      --split-by-type <dir>\n")
	}
	return sb.String()
}

// splitByType writes one file per detected type, named for the type, so each
// can be fed straight back to `crack -t <type>`.
func splitByType(s batchStats, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for typ, lines := range s.Lines {
		path := filepath.Join(dir, typ+".txt")
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}
```

Wire three flags into `runIdentify`: `--summary` (bool), `--split-by-type`
(string dir) and `--unmatched` (string file). When `--summary` is set and the
input is a file, call `scanBatch` on it and print `renderBatchSummary`;
`--split-by-type` then calls `splitByType`, and `--unmatched` writes
`s.Unmatched` one per line.

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./cmd/hashsmith -run 'TestScanBatch|TestBatchSummary|TestEmptyInput' -count=1 -v
go test ./... -count=1
```

- [ ] **Step 5: Check it on a real dump**

```bash
go build -o /tmp/hs ./cmd/hashsmith
for i in $(seq 1 500); do echo 5f4dcc3b5aa765d61d8327deb882cf99; done > /tmp/dump.txt
for i in $(seq 1 200); do echo '$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS'; done >> /tmp/dump.txt
time /tmp/hs -N identify --summary /tmp/dump.txt
/tmp/hs -N identify --summary --split-by-type /tmp/split /tmp/dump.txt && ls -la /tmp/split
```

Expected: 700 lines scanned, roughly 71.4% md5 and 28.6% bcrypt, two files in
`/tmp/split`, and a runtime well under a second.

- [ ] **Step 6: Confirm scan2smith still agrees with identify**

Spec §4.5 requires the two scanners to stay consistent. `scan2smith`
(`extract_compat.go:735,746`) calls `detectHashTypes`, which now resolves
through the prototype table, so consistency should be automatic — verify it
rather than assume it:

```bash
/tmp/hs -N scan2smith -f /tmp/dump.txt | wc -l
```

Expected: 700, matching the identified count from `--summary`. If the two
disagree, `scan2smith`'s token splitting is finding hashes inside lines that
batch mode reads whole; note the difference in the baseline document rather
than changing either scanner.

- [ ] **Step 7: Commit**

```bash
git add cmd/hashsmith/identify_batch.go cmd/hashsmith/identify_batch_test.go cmd/hashsmith/identify.go
git commit -m "feat(identify): add batch summary, split-by-type and unmatched output"
```

---

## Task 18: `--explain` record decoding

**Files:**
- Create: `cmd/hashsmith/identify_explain.go`
- Create: `cmd/hashsmith/identify_explain_test.go`
- Modify: `cmd/hashsmith/identify.go` — `--explain` flag

**Interfaces:**
- Consumes: `hashid.Candidate`
- Produces:
  - `type explainField struct { Label, Value, Note string }`
  - `func explainRecord(input string, c hashid.Candidate) []explainField`

- [ ] **Step 1: Write the failing tests**

Create `cmd/hashsmith/identify_explain_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

func fieldValue(fs []explainField, label string) string {
	for _, f := range fs {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func TestExplainKerberosTGS(t *testing.T) {
	rec := "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local:1433*$" +
		strings.Repeat("a", 32) + "$" + strings.Repeat("b", 64)
	fs := explainRecord(rec, hashid.Candidate{Type: "krb5tgs", Display: "Kerberos 5 TGS-REP"})

	if got := fieldValue(fs, "etype"); !strings.HasPrefix(got, "23") {
		t.Errorf("etype = %q, want it to start with 23", got)
	}
	if got := fieldValue(fs, "user"); got != "svc_sql" {
		t.Errorf("user = %q, want svc_sql", got)
	}
	if got := fieldValue(fs, "realm"); got != "CORP.LOCAL" {
		t.Errorf("realm = %q, want CORP.LOCAL", got)
	}
}

func TestExplainJWTSurfacesAlg(t *testing.T) {
	// {"alg":"HS256","typ":"JWT"} . {"sub":"1"} . sig
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln"
	fs := explainRecord(jwt, hashid.Candidate{Type: "jwt", Display: "JSON Web Token"})
	if got := fieldValue(fs, "alg"); got != "HS256" {
		t.Errorf("alg = %q, want HS256", got)
	}
}

// An unsigned JWT is a finding, not a detail, and must be called out.
func TestExplainJWTFlagsAlgNone(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
	fs := explainRecord(jwt, hashid.Candidate{Type: "jwt", Display: "JSON Web Token"})
	for _, f := range fs {
		if f.Label == "alg" && f.Note != "" {
			return
		}
	}
	t.Error(`alg "none" was reported without a note flagging it`)
}

func TestExplainUnknownFormatReturnsNothing(t *testing.T) {
	if fs := explainRecord("5f4dcc3b5aa765d61d8327deb882cf99",
		hashid.Candidate{Type: "md5", Display: "MD5"}); len(fs) != 0 {
		t.Errorf("a raw digest has no internal fields, got %v", fs)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./cmd/hashsmith -run TestExplain -count=1
```

Expected: FAIL — `undefined: explainRecord`.

- [ ] **Step 3: Write the implementation**

Create `cmd/hashsmith/identify_explain.go`:

```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"hashsmith-go/internal/hashid"
)

// explainField is one decoded field of a record. Note carries an observation
// worth acting on, e.g. that an etype is the weak one or a JWT is unsigned.
type explainField struct {
	Label string
	Value string
	Note  string
}

// krbEtypes names the encryption types that appear in Kerberos records. 23 is
// called out because RC4-HMAC is the etype most exposed to offline cracking.
var krbEtypes = map[string]struct{ name, note string }{
	"17": {"AES128-CTS-HMAC-SHA1-96", ""},
	"18": {"AES256-CTS-HMAC-SHA1-96", ""},
	"23": {"RC4-HMAC", "the etype most exposed to offline cracking"},
}

// explainRecord decodes a record's internal structure. It returns nothing for
// formats that have no structure to show — a raw digest is just bytes.
func explainRecord(input string, c hashid.Candidate) []explainField {
	switch {
	case strings.HasPrefix(input, "$krb5tgs$"), strings.HasPrefix(input, "$krb5asrep$"):
		return explainKerberos(input)
	case c.Type == "jwt" || strings.HasPrefix(input, "eyJ"):
		return explainJWT(input)
	case strings.HasPrefix(input, "-----BEGIN "):
		return explainPEM(input)
	}
	return nil
}

func explainKerberos(rec string) []explainField {
	parts := strings.Split(rec, "$")
	if len(parts) < 4 {
		return nil
	}
	var out []explainField
	etype := parts[2]
	if info, ok := krbEtypes[etype]; ok {
		out = append(out, explainField{"etype", etype + " (" + info.name + ")", info.note})
	} else {
		out = append(out, explainField{"etype", etype, ""})
	}

	// The body is "*user$realm$spn*" — split it on '$' after trimming the
	// surrounding asterisks.
	body := strings.Trim(parts[3], "*")
	fields := strings.Split(body, "$")
	if len(fields) > 0 && fields[0] != "" {
		out = append(out, explainField{"user", fields[0], ""})
	}
	if len(fields) > 1 && fields[1] != "" {
		out = append(out, explainField{"realm", fields[1], ""})
	}
	if len(fields) > 2 && fields[2] != "" {
		out = append(out, explainField{"SPN", strings.Trim(fields[2], "*"), ""})
	}
	return out
}

func explainJWT(tok string) []explainField {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil
	}
	var out []explainField
	if alg, ok := header["alg"].(string); ok {
		note := ""
		switch strings.ToLower(alg) {
		case "none":
			note = "unsigned — the signature is not verified at all"
		case "hs256", "hs384", "hs512":
			note = "HMAC: the signing key is a secret and is crackable offline"
		}
		out = append(out, explainField{"alg", alg, note})
	}
	if typ, ok := header["typ"].(string); ok {
		out = append(out, explainField{"typ", typ, ""})
	}
	if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		var claims map[string]any
		if json.Unmarshal(payload, &claims) == nil {
			for _, k := range []string{"sub", "iss", "aud"} {
				if v, ok := claims[k].(string); ok {
					out = append(out, explainField{k, v, ""})
				}
			}
		}
	}
	if parts[2] == "" {
		out = append(out, explainField{"signature", "(empty)", "no signature present"})
	}
	return out
}

func explainPEM(pem string) []explainField {
	line, _, _ := strings.Cut(pem, "\n")
	label := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "-----BEGIN "), "-----")
	out := []explainField{{"block", label, ""}}
	if strings.Contains(pem, "Proc-Type: 4,ENCRYPTED") || strings.Contains(pem, "DEK-Info:") {
		out = append(out, explainField{"encrypted", "yes", "legacy PEM encryption; crackable"})
	} else if strings.Contains(label, "ENCRYPTED") {
		out = append(out, explainField{"encrypted", "yes", "PKCS#8 encrypted private key"})
	} else {
		out = append(out, explainField{"encrypted", "no", "no passphrase to recover"})
	}
	return out
}
```

Wire `--explain` into `runIdentify`: when set, after the candidate rows, print
`explainRecord(input, cs[0])` indented four spaces, `Label` left-aligned, with
` — <Note>` appended when a note is present.

- [ ] **Step 4: Run to verify they pass**

```bash
go test ./cmd/hashsmith -run TestExplain -count=1 -v
go test ./... -count=1
```

- [ ] **Step 5: Check it end to end**

```bash
go build -o /tmp/hs ./cmd/hashsmith
/tmp/hs -N identify --explain 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.'
```

Expected: `alg none` shown with the unsigned note.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/identify_explain.go cmd/hashsmith/identify_explain_test.go cmd/hashsmith/identify.go
git commit -m "feat(identify): decode record internals behind --explain"
```

---

## Task 19: Benchmarks, help text and documentation

**Files:**
- Create: `cmd/hashsmith/identify_bench_test.go`
- Modify: `cmd/hashsmith/main.go:160-190` — help text
- Modify: `README.md:930-1010`
- Modify: `docs/superpowers/notes/2026-09-04-recognition-baseline.md`

- [ ] **Step 1: Write the benchmarks**

Create `cmd/hashsmith/identify_bench_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func BenchmarkIdentifySingle(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99")
	}
}

func BenchmarkIdentifySignature(b *testing.B) {
	b.ReportAllocs()
	const h = "$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS"
	for i := 0; i < b.N; i++ {
		_ = identifyCandidates(h)
	}
}

func BenchmarkDetectHashTypes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = detectHashTypes("5f4dcc3b5aa765d61d8327deb882cf99")
	}
}

func BenchmarkScanBatch100k(b *testing.B) {
	dump := strings.Repeat("5f4dcc3b5aa765d61d8327deb882cf99\n", 100000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = scanBatch(strings.NewReader(dump))
	}
}
```

- [ ] **Step 2: Run and record them**

```bash
cd hashsmith/go_hashsmith
go test ./cmd/hashsmith -run '^$' -bench 'BenchmarkIdentify|BenchmarkDetect|BenchmarkScanBatch' -benchtime 200x -count=1 | tee /tmp/identify_bench.txt
```

Record the numbers in the baseline note under a "Performance" heading, with the
machine and Go version, the way
`docs/superpowers/notes/2026-08-31-phase1-measurements.md` does. If
`BenchmarkScanBatch100k` exceeds two seconds per iteration, profile before
proceeding:

```bash
go test ./cmd/hashsmith -run '^$' -bench BenchmarkScanBatch100k -benchtime 5x -cpuprofile /tmp/cpu.out
go tool pprof -top -nodecount=15 /tmp/cpu.out
```

- [ ] **Step 3: Update the help text**

In `main.go`, replace the `identify` usage line with the new flags:

```go
	fmt.Println("  identify      [--json] [--explain] [--summary] [--coverage]")
	fmt.Println("                [--split-by-type <dir>] [--unmatched <file>] [-o out] [-c]  INPUT...")
	fmt.Println("                INPUT may also be a container file (.kdbx, .zip, .pdf, …)")
```

And add to the exit-code line at the bottom:

```go
	fmt.Println("Exit codes (identify):  0 = confident answer   1 = ambiguous or none   2 = error")
```

- [ ] **Step 4: Update the README**

In the comparison table at `README.md:961`, replace the auto-detection row with
one stating that Hashsmith's `identify` and `crack` share a single engine, and
add rows for JSON output, container-file identification, and record decoding.
Correct the "Hash-type auto-detection" row to say `identify` reports the
Hashcat mode and John label per candidate.

Every number in the README must come from a measurement made in Tasks 12, 15
or 19 — the John-label coverage ratio, the sniffer coverage ratio, and the
recognition rate. **Do not write a number this plan did not measure.**

Also update the identify examples near `README.md:56` and `README.md:71` to
show the new output, pasting real output from `/tmp/hs`, not hand-written
approximations.

- [ ] **Step 5: Verify everything one final time**

```bash
cd hashsmith/go_hashsmith
go build ./... && go vet ./...
go test ./... -count=1
go run ./cmd/hashsmith -N selftest | tail -5
go run ./cmd/hashsmith -N identify --coverage
```

Expected: build clean, vet clean, all tests pass including
`TestDetectHashTypesGolden`, and selftest still reports its full vector count.

- [ ] **Step 6: Commit**

```bash
git add cmd/hashsmith/identify_bench_test.go cmd/hashsmith/main.go README.md docs/superpowers/notes/2026-09-04-recognition-baseline.md
git commit -m "docs: document the unified identification engine and record its measurements"
```

---

## Definition of done

Every item is checkable by running a command, not by reading the diff.

1. `go test ./... -count=1` passes, `TestDetectHashTypesGolden` included, with `testdata/detect_golden.txt` unchanged since Task 1.
2. `grep -c legacyDetectHashTypes cmd/hashsmith/*.go` finds nothing — the cascade is gone.
3. `grep -c 'func scoreCandidates' cmd/hashsmith/*.go` finds nothing — the old scorer is gone.
4. `hashsmith identify <md5>` prints a Hashcat mode, a John label, a `-t` name and a runnable command.
5. `hashsmith identify --json <md5> | jq .schema` prints `"hashsmith.identify/1"`.
6. `hashsmith identify <container>` routes to the right `*2smith` command.
7. `hashsmith identify --summary <dump>` reports per-type line counts.
8. `hashsmith identify --explain <jwt>` surfaces the `alg`.
9. `hashsmith identify --coverage` reports both coverage ratios.
10. `docs/superpowers/notes/2026-09-04-recognition-baseline.md` records the measured recognition rate, the remaining gaps by name, and the benchmark numbers.
