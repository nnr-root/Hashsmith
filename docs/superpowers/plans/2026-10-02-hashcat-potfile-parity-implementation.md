# Hashcat Potfile Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Hashsmith read an existing hashcat `.pot` file (and optionally write new entries in hashcat's own format) without breaking any existing native-potfile behavior.

**Architecture:** `internal/smith/pot.go`'s scanner auto-detects, per line, whether it is Hashsmith's native `hash<TAB>plaintext` or hashcat's `hash[:...]:plaintext` (with `$HEX[...]` escaping), decoding either into the same in-memory `seen` map. A new `writeFormat` field on `potfile`, set from a new `--potfile-format` flag, controls which format `add()` appends in. `verifiedPlain` gets one extra fallback lookup (`target+":"+salt`) so hashcat's salt-folded-into-the-key convention is reachable from Hashsmith's separate `-s` flag.

**Tech Stack:** Go stdlib only (`encoding/hex`, already used elsewhere in the project — no new dependency).

**Spec:** `docs/superpowers/specs/2026-10-02-hashcat-potfile-parity-design.md` — read this first. It documents the exact hashcat `$HEX[]` trigger condition (`:` or any byte `< 0x20`), measured directly against the real hashcat 7.1.2 binary, not assumed.

## Global Constraints

- Every performance or behavior claim must be backed by a real test run (`go test`), per the user's own execution guidelines — no invented numbers.
- Do not change `compat.go`'s flag-translation logic in this plan (out of scope; `--pot`/`--potfile-format` are Hashsmith-native flags, not part of the hashcat/John compat layer).
- `loadPotfile(path string)`'s existing one-argument signature must NOT change — `pot_test.go:TestPotfileRoundTrip` and others call it directly; format detection happens automatically per-line inside it, it does not need to be told which format to expect.
- `newCrackCtx`'s signature DOES gain one new trailing parameter (`potFormat string`) — every call site must be updated in the same task that changes the signature, never left to a later task. The full call-site list, confirmed by grep on 2026-10-02, is:
  - `internal/smith/auto.go:109`
  - `internal/smith/crack.go:797`
  - `internal/smith/crack.go:1858`
  - `internal/smith/distribution_test.go:112`
  - `internal/smith/exitcode_test.go:13`
  - `internal/smith/lanes_test.go:328`
  - `internal/smith/prince_test.go:683` and `:699`
  - `internal/smith/saltedvector_test.go:616`
  - `internal/smith/session_fastpath_test.go:358`, `:379`, `:418`, `:512`, `:543`

---

### Task 1: `$HEX[]` encode/decode helpers + hashcat-format read support

**Files:**
- Modify: `internal/smith/pot.go`
- Test: `internal/smith/pot_test.go`

**Interfaces:**
- Produces: `decodeHashcatHexPlain(s string) string`, `encodeHashcatHexPlain(plain string) string`, `needsHashcatHexEncode(plain string) bool` — Task 2 and Task 3 call these.
- Produces: `loadPotfile` now also populates `seen` from colon-format lines (no signature change).

- [ ] **Step 1: Write the failing tests**

Add to `internal/smith/pot_test.go`:

```go
func TestDecodeHashcatHexPlain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"café", "café"},
		{"$HEX[61623a6364]", "ab:cd"},
		{"$HEX[610962]", "a\tb"},
		{"$HEX[zz]", "$HEX[zz]"}, // invalid hex inside — hashcat's own ambiguity, left raw
	}
	for _, c := range cases {
		if got := decodeHashcatHexPlain(c.in); got != c.want {
			t.Errorf("decodeHashcatHexPlain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoadPotfileHashcatFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashcat.pot")
	// Written by hand in hashcat's own on-disk shape, exactly as produced by
	// a real `hashcat --potfile-path` run (verified empirically 2026-10-02):
	// plain ascii unescaped, a colon-containing plaintext hex-escaped, and a
	// salted-mode entry whose key has the salt folded in via hashcat's own
	// colon join.
	content := "5d41402abc4b2a76b9719d911017c592:hello\n" +
		"7421742cb38488304149bb5332975204:$HEX[61623a6364]\n" +
		"8e8327204e54d58ce328098b38200580:abc123:secretpw\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := p.lookup("5d41402abc4b2a76b9719d911017c592"); !ok || got != "hello" {
		t.Errorf("plain ascii: got %q ok=%v", got, ok)
	}
	if got, ok := p.lookup("7421742cb38488304149bb5332975204"); !ok || got != "ab:cd" {
		t.Errorf("hex-escaped: got %q ok=%v", got, ok)
	}
	if got, ok := p.lookup("8e8327204e54d58ce328098b38200580:abc123"); !ok || got != "secretpw" {
		t.Errorf("salt-folded key: got %q ok=%v", got, ok)
	}
}
```

`pot_test.go`'s current imports are only `"path/filepath"` and `"testing"` — add `"os"` alongside them (needed for `os.WriteFile` in the new test above).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/smith/ -run 'TestDecodeHashcatHexPlain|TestLoadPotfileHashcatFormat' -v`
Expected: FAIL — `decodeHashcatHexPlain` undefined, and the hashcat-format lines are silently dropped by the current tab-only scanner (no `:` detection), so the third assertion set fails too.

- [ ] **Step 3: Implement**

In `internal/smith/pot.go`, add the import and the two new helpers (near the top, after the existing imports):

```go
import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// decodeHashcatHexPlain reverses hashcat's own potfile escaping: a plaintext
// that was written as $HEX[<lowercase hex>] decodes back to its raw bytes.
// Anything else — including a plaintext that merely LOOKS like $HEX[...]
// but isn't valid hex inside the brackets — is returned unchanged. This is
// hashcat's own real, inherited ambiguity (a literal password "$HEX[zz]" is
// genuinely indistinguishable from an escaped one), reproduced here rather
// than "fixed", because the goal is reading a real hashcat potfile exactly
// as hashcat itself would, not inventing a stricter format of our own.
func decodeHashcatHexPlain(s string) string {
	if len(s) >= len("$HEX[]") && strings.HasPrefix(s, "$HEX[") && strings.HasSuffix(s, "]") {
		if b, err := hex.DecodeString(s[5 : len(s)-1]); err == nil {
			return string(b)
		}
	}
	return s
}
```

Now change the scan loop inside `loadPotfile` from:

```go
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '\t'); i > 0 {
			p.seen[line[:i]] = line[i+1:]
		}
	}
```

to:

```go
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '\t'); i > 0 {
			// Hashsmith's own native format.
			p.seen[line[:i]] = line[i+1:]
			continue
		}
		// A hashcat-format line has no TAB: hash[:field...]:plaintext, split
		// on the LAST colon so a key that itself contains colons (a salted
		// mode's hash:salt, NetNTLMv2, Kerberos) is preserved whole rather
		// than mis-split.
		if i := strings.LastIndexByte(line, ':'); i > 0 {
			p.seen[line[:i]] = decodeHashcatHexPlain(line[i+1:])
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run 'TestDecodeHashcatHexPlain|TestLoadPotfileHashcatFormat|TestPotfileRoundTrip' -v`
Expected: PASS (all three, including the pre-existing round-trip test — it uses TAB-containing lines exclusively, so the new `:`-splitting branch never fires for it).

- [ ] **Step 5: Commit**

```bash
git add internal/smith/pot.go internal/smith/pot_test.go
git commit -m "feat(pot): read hashcat-format potfile lines alongside native format"
```

---

### Task 2: Salt-folded composite lookup fallback

**Files:**
- Modify: `internal/smith/pot.go`
- Test: `internal/smith/pot_verify_test.go`

**Interfaces:**
- Consumes: `decodeHashcatHexPlain` (Task 1).
- Produces: `verifiedPlain`'s new fallback behavior — no signature change (it already takes `salt`).

- [ ] **Step 1: Write the failing test**

First read `internal/smith/pot_verify_test.go` in full to match its existing helper style (it almost certainly already builds a `potfile` by hand and calls `verifiedPlain` with a real type/salt — follow that exact pattern rather than inventing a new one). Add:

```go
func TestVerifiedPlainSaltFoldedFallback(t *testing.T) {
	// Simulates an imported hashcat -m 10 (md5($pass.$salt)) entry, whose
	// potfile key has the salt folded in via hashcat's own colon join —
	// Hashsmith's own -s flag passes salt separately, so the plain target
	// alone won't find it without the fallback this test pins.
	p := &potfile{seen: map[string]string{
		"8e8327204e54d58ce328098b38200580:abc123": "secretpw",
	}}
	plain, status := p.verifiedPlain("8e8327204e54d58ce328098b38200580", "md5", "abc123", "suffix")
	if status != potVerified || plain != "secretpw" {
		t.Fatalf("got plain=%q status=%v, want potVerified/secretpw", plain, status)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/smith/ -run TestVerifiedPlainSaltFoldedFallback -v`
Expected: FAIL with `potMiss` (or similar) — the direct `p.lookup(target)` call misses since the real key has `:abc123` appended, and there is currently no fallback.

- [ ] **Step 3: Implement**

In `internal/smith/pot.go`, change `verifiedPlain`'s opening lines from:

```go
func (p *potfile) verifiedPlain(target, explicitType, salt, saltMode string) (string, potHitStatus) {
	plain, found := p.lookup(target)
	if !found {
		return "", potMiss
	}
```

to:

```go
func (p *potfile) verifiedPlain(target, explicitType, salt, saltMode string) (string, potHitStatus) {
	plain, found := p.lookup(target)
	if !found && salt != "" {
		// hashcat's own salted-mode potfile convention folds the salt into
		// the key via a colon join (e.g. "hash:salt"); Hashsmith's -s/-S
		// flags pass salt separately instead, so an imported hashcat entry
		// for a salted mode is only reachable through this composite key.
		plain, found = p.lookup(target + ":" + salt)
	}
	if !found {
		return "", potMiss
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run 'TestVerifiedPlainSaltFoldedFallback|TestPotfile' -v`
Expected: PASS, including every pre-existing `TestPotfile*`/potfile-related test in the package (confirms the `salt != ""` guard means unsalted lookups are byte-for-byte unchanged).

- [ ] **Step 5: Run the full package test suite**

Run: `go test ./internal/smith/...`
Expected: `ok` — this fallback sits on a hot path (every potfile lookup now does one extra conditional and, on a miss with a salt, one extra map read), so confirm nothing else in the package regressed before moving on.

- [ ] **Step 6: Commit**

```bash
git add internal/smith/pot.go internal/smith/pot_verify_test.go
git commit -m "feat(pot): fall back to a salt-folded key for imported hashcat potfiles"
```

---

### Task 3: Hashcat-format write support

**Files:**
- Modify: `internal/smith/pot.go`
- Test: `internal/smith/pot_test.go`

**Interfaces:**
- Consumes: `encodeHashcatHexPlain`/`needsHashcatHexEncode` (defined in this task, alongside `decodeHashcatHexPlain` from Task 1 for symmetry).
- Produces: `potfile.writeFormat` field — Task 4 sets it from the new CLI flag.

- [ ] **Step 1: Write the failing test**

Add to `internal/smith/pot_test.go`:

```go
func TestPotfileAddHashcatFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pot")
	p, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	p.writeFormat = "hashcat"
	p.add("5d41402abc4b2a76b9719d911017c592", "hello")   // plain — no escaping
	p.add("7421742cb38488304149bb5332975204", "ab:cd")   // colon — must hex-escape
	p.add("deadbeefdeadbeefdeadbeefdeadbeef", "café")    // unicode — not escaped, matches real hashcat

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "5d41402abc4b2a76b9719d911017c592:hello\n" +
		"7421742cb38488304149bb5332975204:$HEX[61623a6364]\n" +
		"deadbeefdeadbeefdeadbeefdeadbeef:café\n"
	if string(raw) != want {
		t.Fatalf("got:\n%q\nwant:\n%q", raw, want)
	}

	// Round-trips back through loadPotfile (Task 1's colon-format reader).
	reloaded, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reloaded.lookup("7421742cb38488304149bb5332975204"); !ok || got != "ab:cd" {
		t.Fatalf("round-trip: got %q ok=%v", got, ok)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/smith/ -run TestPotfileAddHashcatFormat -v`
Expected: FAIL — `p.writeFormat` field doesn't exist yet (compile error).

- [ ] **Step 3: Implement**

Add the `writeFormat` field to the struct:

```go
type potfile struct {
	path string
	mu   sync.Mutex
	seen map[string]string // targetHash -> plaintext
	// writeFormat controls how add() appends NEW entries to disk: "" (the
	// zero value) or "native" writes Hashsmith's own TAB format; "hashcat"
	// writes hashcat's colon format with $HEX[] escaping. Reading (see
	// loadPotfile) always accepts both regardless of this field — it only
	// ever affects what this run writes next.
	writeFormat string
}
```

Add the encode helpers next to `decodeHashcatHexPlain`:

```go
// needsHashcatHexEncode reports whether plain must be $HEX[]-escaped to
// round-trip through hashcat's colon-delimited potfile format — true for
// any byte that would otherwise break the line's field boundaries. Measured
// directly against the real hashcat 7.1.2 binary (2026-10-02): a colon or
// any control byte (<0x20) triggers it; unicode and spaces do not.
func needsHashcatHexEncode(plain string) bool {
	for i := 0; i < len(plain); i++ {
		if c := plain[i]; c == ':' || c < 0x20 {
			return true
		}
	}
	return false
}

func encodeHashcatHexPlain(plain string) string {
	if !needsHashcatHexEncode(plain) {
		return plain
	}
	return "$HEX[" + hex.EncodeToString([]byte(plain)) + "]"
}
```

Change `add`'s on-disk line construction from:

```go
	fmt.Fprintf(f, "%s\t%s\n", hash, plain)
```

to:

```go
	if p.writeFormat == "hashcat" {
		fmt.Fprintf(f, "%s:%s\n", hash, encodeHashcatHexPlain(plain))
	} else {
		fmt.Fprintf(f, "%s\t%s\n", hash, plain)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run 'TestPotfileAddHashcatFormat|TestPotfileRoundTrip' -v`
Expected: PASS for both — the default (`writeFormat` unset) path used by `TestPotfileRoundTrip` is untouched, since the `if` falls through to the original `%s\t%s\n` branch.

- [ ] **Step 5: Commit**

```bash
git add internal/smith/pot.go internal/smith/pot_test.go
git commit -m "feat(pot): support writing new entries in hashcat's potfile format"
```

---

### Task 4: CLI wiring — `--potfile-format` flag

**Files:**
- Modify: `internal/smith/auto.go`
- Modify: `internal/smith/crack.go`
- Modify: `internal/smith/distribution_test.go`, `internal/smith/exitcode_test.go`, `internal/smith/lanes_test.go`, `internal/smith/prince_test.go`, `internal/smith/saltedvector_test.go`, `internal/smith/session_fastpath_test.go` (mechanical trailing-argument addition only — see Global Constraints for the full call-site list)
- Test: `internal/smith/pot_cmd_test.go` (new file)

**Interfaces:**
- Consumes: `potfile.writeFormat` (Task 3).
- Produces: `newCrackCtx(potPath string, noPot bool, sessName string, showOnly bool, wordlist2 string, useGPU bool, skip, limit int64, hcstat2 string, markovThreshold int, potFormat string) (*crackCtx, error)` — the new trailing parameter. No other task depends on this signature, so no further ripple beyond the call sites listed.

- [ ] **Step 1: Write the failing test**

Create `internal/smith/pot_cmd_test.go`. The real CLI entry point used by this package's own end-to-end tests is `runCrack([]string{...flags..., target})` (confirmed 2026-10-02 against `internal/smith/association_test.go:73`), with helpers `mustWrite`/`mustRead` (`internal/smith/pipeline_test.go`) and `md5hex` (`internal/smith/mask_test.go`) already available package-wide:

```go
package smith

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRunCrackPotfileFormatHashcat exercises the real CLI flag end-to-end:
// cracking a target with --potfile-format hashcat must append a
// hashcat-shaped (colon, $HEX[]-escaped where needed) line, not Hashsmith's
// native TAB line.
func TestRunCrackPotfileFormatHashcat(t *testing.T) {
	dir := t.TempDir()
	potPath := filepath.Join(dir, "out.pot")
	wordlistPath := filepath.Join(dir, "words.txt")
	mustWrite(t, wordlistPath, "ab:cd\n")
	target := md5hex("ab:cd")

	if err := runCrack([]string{"-t", "md5", "-w", wordlistPath,
		"--pot", potPath, "--potfile-format", "hashcat", target}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}

	raw, err := os.ReadFile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	want := target + ":$HEX[61623a6364]\n"
	if string(raw) != want {
		t.Fatalf("potfile content = %q, want %q", raw, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/smith/ -run TestRunCrackPotfileFormatHashcat -v`
Expected: FAIL — `--potfile-format` is an unrecognized flag.

- [ ] **Step 3: Implement — add the flag and thread it through**

In `internal/smith/auto.go`, right after the existing `noPot` line:

```go
	potPath := fs.String("pot", "", "potfile path (default ~/.hashsmith/hashsmith.pot)")
	noPot := fs.Bool("no-pot", false, "disable the potfile")
	potFormat := fs.String("potfile-format", "native", "format for NEW potfile entries this run writes: native (Hashsmith's own TAB format) or hashcat (hash:plaintext, with $HEX[] escaping); reading always accepts both regardless of this flag")
```

and change the `newCrackCtx` call:

```go
	cc, err := newCrackCtx(*potPath, *noPot, sn, *showOnly, wl2, *useGPU, 0, 0, "", 0, *potFormat)
```

In `internal/smith/crack.go`, right after its own `noPot` line (note its help text differs slightly from auto.go's — match crack.go's own wording style):

```go
	potPath := fs.String("pot", "", "potfile path (default ~/.hashsmith/hashsmith.pot)")
	noPot := fs.Bool("no-pot", false, "disable the potfile (do not read or record cracked hashes)")
	potFormat := fs.String("potfile-format", "native", "format for NEW potfile entries this run writes: native (Hashsmith's own TAB format) or hashcat (hash:plaintext, with $HEX[] escaping); reading always accepts both regardless of this flag")
```

and change its `newCrackCtx` call (line 797):

```go
	cc, err := newCrackCtx(*potPath, *noPot, sn, *showOnly, wl2, *useGPU, *skip, *limit, *hcstat2Flag, *markovThreshold, *potFormat)
```

Also add a validation guard right after `checkBruteCharset`'s error check in BOTH files. In `internal/smith/auto.go`, that is immediately after:

```go
	if err := checkBruteCharset(*mode, *charset); err != nil {
		return err
	}
```

In `internal/smith/crack.go` (line 652-654), the identical check appears; insert after its closing brace too. In both places, insert:

```go
	if *potFormat != "native" && *potFormat != "hashcat" {
		return fmt.Errorf("--potfile-format must be \"native\" or \"hashcat\", got %q", *potFormat)
	}
```

`fmt` is already imported in `crack.go` (used a few lines below at `fmt.Fprintf`/`fmt.Fprintln` sites in the same function). `internal/smith/auto.go`'s current import block (confirmed 2026-10-02) is `"flag"`, `"io"`, `"os"`, `"runtime"`, `"strings"` — no `"fmt"` yet, so add it:

```go
import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)
```

Now update `newCrackCtx` itself in `internal/smith/crack.go`:

```go
func newCrackCtx(potPath string, noPot bool, sessName string, showOnly bool, wordlist2 string, useGPU bool, skip, limit int64, hcstat2 string, markovThreshold int, potFormat string) (*crackCtx, error) {
	cc := &crackCtx{sessName: sessName, showOnly: showOnly, wordlist2: wordlist2, useGPU: useGPU, skip: skip, limit: limit, hcstat2: hcstat2, markovThreshold: markovThreshold}
	if !noPot {
		p, err := loadPotfile(potPath)
		if err != nil {
			return nil, err
		}
		p.writeFormat = potFormat
		cc.pot = p
		cc.potPlains = p.allPlains()
	}
```

(the rest of the function body — session loading — is unchanged, keep it exactly as it is).

Also update the internal convenience call at `crack.go:1858` — this one has no flag to read from, pass `"native"` literally:

```go
	cc, _ := newCrackCtx("", false, "", false, "", false, 0, 0, "", 0, "native")
```

- [ ] **Step 4: Mechanical trailing-argument update across every test call site**

For each of the following, add `, "native"` immediately before the closing `)` of the `newCrackCtx(...)` call — no other change on the line:

- `internal/smith/distribution_test.go:112`
- `internal/smith/exitcode_test.go:13`
- `internal/smith/lanes_test.go:328`
- `internal/smith/prince_test.go:683`
- `internal/smith/prince_test.go:699`
- `internal/smith/saltedvector_test.go:616`
- `internal/smith/session_fastpath_test.go:358`
- `internal/smith/session_fastpath_test.go:379`
- `internal/smith/session_fastpath_test.go:418`
- `internal/smith/session_fastpath_test.go:512`
- `internal/smith/session_fastpath_test.go:543`

Before editing, re-run `grep -rn "newCrackCtx(" internal/smith/*.go` yourself and diff it against this list — if the package has grown a new call site since this plan was written (2026-10-02), add it to this task rather than leaving it broken; this is exactly the mistake the hcstat2/Markov project's own retrospective flagged (a plan's confidence about "the" call sites is not evidence, grep it yourself).

- [ ] **Step 5: Build and run the full package test suite**

Run: `go build ./... && go vet ./... && go test ./internal/smith/...`
Expected: clean build, clean vet, `ok` — every call site compiles with the new parameter and no existing test's behavior changed (`"native"` reproduces the pre-change default in every case, since the pre-change code always wrote TAB format).

- [ ] **Step 6: Run the new end-to-end test**

Run: `go test ./internal/smith/ -run TestRunCrackPotfileFormatHashcat -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/smith/auto.go internal/smith/crack.go internal/smith/pot_cmd_test.go \
        internal/smith/distribution_test.go internal/smith/exitcode_test.go internal/smith/lanes_test.go \
        internal/smith/prince_test.go internal/smith/saltedvector_test.go internal/smith/session_fastpath_test.go
git commit -m "feat(cli): add --potfile-format flag, wire through newCrackCtx"
```

---

### Task 5: Real-hashcat-oracle end-to-end test

**Files:**
- Test: `internal/smith/pot_hashcat_oracle_test.go` (new file)

**Interfaces:**
- Consumes: everything from Tasks 1–4. No new production code.

This task validates the whole feature against a REAL hashcat-produced potfile, not a hand-written fixture — the same "real oracle, not assumed" standard the rules-engine tests and the PBKDF2 project's own vectors already hold to. It must SKIP cleanly (not fail) when hashcat isn't installed, matching `scripts/rules-oracle.sh`'s own "skip if missing" convention, since CI machines may not have it.

- [ ] **Step 1: Write the test**

```go
package smith

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestImportRealHashcatPotfile runs the real hashcat binary to produce a
// genuine potfile (colon format, $HEX[]-escaped where hashcat itself
// decides to), then confirms Hashsmith's --show reads it correctly. Skips
// if hashcat is not installed rather than failing, matching
// scripts/rules-oracle.sh's convention.
func TestImportRealHashcatPotfile(t *testing.T) {
	hashcatBin, err := exec.LookPath("hashcat")
	if err != nil {
		t.Skip("hashcat not installed, skipping real-oracle potfile test")
	}

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "hash.txt")
	wordFile := filepath.Join(dir, "words.txt")
	potFile := filepath.Join(dir, "hashcat.pot")

	// md5("ab:cd") — deliberately chosen to force hashcat's own $HEX[]
	// escaping (see the spec: a plaintext containing ':' always triggers it).
	target := "7421742cb38488304149bb5332975204"
	if err := os.WriteFile(hashFile, []byte(target+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wordFile, []byte("ab:cd\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(hashcatBin, "-m", "0", "-a", "0",
		"--potfile-path", potFile, "--force", hashFile, wordFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hashcat run failed: %v\n%s", err, out)
	}

	p, err := loadPotfile(potFile)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := p.lookup(target)
	if !ok {
		t.Fatalf("Hashsmith failed to read the real hashcat potfile entry for %s", target)
	}
	if got != "ab:cd" {
		t.Fatalf("got plaintext %q, want %q", got, "ab:cd")
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/smith/ -run TestImportRealHashcatPotfile -v`
Expected: PASS (hashcat 7.1.2 confirmed installed at `/opt/homebrew/bin/hashcat` on this machine, per the empirical checks already run while writing this plan's spec — on a machine without hashcat, expect a clean SKIP, not a failure).

- [ ] **Step 3: Run the full suite one more time**

Run: `go test ./internal/smith/...`
Expected: `ok` — final confirmation nothing in the whole package regressed across all five tasks.

- [ ] **Step 4: Commit**

```bash
git add internal/smith/pot_hashcat_oracle_test.go
git commit -m "test(pot): validate hashcat-potfile import against the real hashcat binary"
```
