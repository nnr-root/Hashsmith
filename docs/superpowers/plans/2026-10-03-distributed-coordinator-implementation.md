# WP4.2 Distributed Coordinator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Hashsmith crack job split its keyspace across multiple `hashsmith worker` processes reachable over HTTP, coordinated by a new `hashsmith coordinate` subcommand.

**Architecture:** Two new CLI subcommands (`worker`, `coordinate`) on the existing binary. A worker is a tiny HTTP server with one endpoint (`POST /chunk`) that runs the existing, untouched `runCrack([]string) error` against a `--skip`/`--limit` slice and reports back via the existing `-o`-file mechanism — no changes to any existing crack code. The coordinator computes the total keyspace via the existing `bruteLayout`/`maskLayout`/`exactWordlistCount` helpers, splits it into a pull-based chunk queue, and runs one goroutine per worker pulling chunks until one reports found or the queue drains.

**Tech Stack:** Go stdlib only (`net/http`, `encoding/json`) — no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-03-distributed-coordinator-design.md` — read this first. It documents the decisions already made (HTTP-only, dynamic pull-based chunking, shared-path wordlist assumption, shared-secret token auth) and the explicit non-goals (no mid-chunk cancellation, no SSH, no wordlist shipping, no real multi-machine validation this session).

## Global Constraints

- `runCrack(args []string) error` must NEVER be modified by this plan — it is proven, heavily-tested code (confirmed this session to never call `os.Exit` itself). Every task that calls it does so exactly as an existing CLI invocation would, via a `[]string` argument slice.
- `--chunk-size` has **no default** and is a required flag on `coordinate` — there is no single candidate-count default that is sane across hash types differing in speed by 5+ orders of magnitude (measured this session: ~23.6 MH/s raw MD5 vs. ~60 H/s bcrypt on the same machine). Its help text must say so and point at `hashsmith benchmark -t <type>`.
- A worker process handles exactly one chunk at a time (a package-level mutex serializes `runCrack` calls on a worker), because `runCrack`'s existing implementation shares a package-level `exitCode` variable across calls — this is a documented existing constraint, not a new one introduced here.
- Every new file lives in `internal/smith/`, following the existing flat-package convention (confirmed: the package has no subdirectories for CLI-subcommand-shaped features — `gpu.go`, `benchmark.go`, `interactive.go` are siblings of `crack.go`, not nested).

---

### Task 1: Chunk queue — pure splitting and pull logic

**Files:**
- Create: `internal/smith/coordinator_chunks.go`
- Test: `internal/smith/coordinator_chunks_test.go`

**Interfaces:**
- Produces: `type chunkRange struct { skip, limit int64 }`, `func splitKeyspace(total, chunkSize int64) []chunkRange`, `type chunkQueue struct{...}`, `func newChunkQueue(items []chunkRange) *chunkQueue`, `func (q *chunkQueue) next() (chunkRange, bool)`, `func (q *chunkQueue) requeue(c chunkRange)`. Tasks 5 and 6 consume all of these exactly as named.

- [ ] **Step 1: Write the failing tests**

```go
package smith

import "testing"

func TestSplitKeyspaceEvenDivision(t *testing.T) {
	got := splitKeyspace(100, 25)
	want := []chunkRange{{0, 25}, {25, 25}, {50, 25}, {75, 25}}
	if len(got) != len(want) {
		t.Fatalf("got %d chunks, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSplitKeyspacePartialFinalChunk(t *testing.T) {
	got := splitKeyspace(105, 25)
	want := []chunkRange{{0, 25}, {25, 25}, {50, 25}, {75, 25}, {100, 5}}
	if len(got) != len(want) {
		t.Fatalf("got %d chunks, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSplitKeyspaceSmallerThanOneChunk(t *testing.T) {
	got := splitKeyspace(10, 25)
	want := []chunkRange{{0, 10}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSplitKeyspaceZeroTotal(t *testing.T) {
	if got := splitKeyspace(0, 25); len(got) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}

func TestChunkQueuePullOrderAndExhaustion(t *testing.T) {
	q := newChunkQueue([]chunkRange{{0, 10}, {10, 10}, {20, 10}})
	c, ok := q.next()
	if !ok || c != (chunkRange{0, 10}) {
		t.Fatalf("first pull: got %+v ok=%v, want {0 10} true", c, ok)
	}
	c, ok = q.next()
	if !ok || c != (chunkRange{10, 10}) {
		t.Fatalf("second pull: got %+v ok=%v, want {10 10} true", c, ok)
	}
	c, ok = q.next()
	if !ok || c != (chunkRange{20, 10}) {
		t.Fatalf("third pull: got %+v ok=%v, want {20 10} true", c, ok)
	}
	if _, ok := q.next(); ok {
		t.Fatal("fourth pull should be empty, got ok=true")
	}
}

func TestChunkQueueRequeueGoesToFront(t *testing.T) {
	q := newChunkQueue([]chunkRange{{0, 10}, {10, 10}})
	first, _ := q.next() // {0 10}
	q.requeue(first)
	c, ok := q.next()
	if !ok || c != first {
		t.Fatalf("requeued chunk should come back first: got %+v ok=%v", c, ok)
	}
	c, ok = q.next()
	if !ok || c != (chunkRange{10, 10}) {
		t.Fatalf("got %+v ok=%v, want {10 10} true", c, ok)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hashsmith/go_hashsmith && go test ./internal/smith/ -run TestSplitKeyspace -v` and `go test ./internal/smith/ -run TestChunkQueue -v`
Expected: FAIL — `splitKeyspace`, `chunkRange`, `chunkQueue`, `newChunkQueue` undefined.

- [ ] **Step 3: Implement**

```go
package smith

import "sync"

// chunkRange is one (skip, limit) slice of a keyspace, in the same units
// --skip/--limit already use (word index in dict mode, whole-layout index
// in brute/mask mode).
type chunkRange struct {
	skip, limit int64
}

// splitKeyspace divides [0, total) into chunkSize-sized pieces, the last
// one shorter if total is not an exact multiple. Returns nil for total<=0.
// chunkSize must be > 0 (the coordinate command's flag parsing enforces
// this before ever calling here).
func splitKeyspace(total, chunkSize int64) []chunkRange {
	if total <= 0 {
		return nil
	}
	var out []chunkRange
	for skip := int64(0); skip < total; skip += chunkSize {
		limit := chunkSize
		if skip+limit > total {
			limit = total - skip
		}
		out = append(out, chunkRange{skip: skip, limit: limit})
	}
	return out
}

// chunkQueue is a mutex-guarded FIFO of chunkRanges, safe for concurrent
// pull-based access from multiple worker-dispatch goroutines (Task 5).
type chunkQueue struct {
	mu    sync.Mutex
	items []chunkRange
}

func newChunkQueue(items []chunkRange) *chunkQueue {
	return &chunkQueue{items: items}
}

// next pops the next chunk, or returns ok=false if the queue is empty.
func (q *chunkQueue) next() (chunkRange, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return chunkRange{}, false
	}
	c := q.items[0]
	q.items = q.items[1:]
	return c, true
}

// requeue pushes a chunk back onto the FRONT of the queue, so a chunk that
// just failed is retried soon rather than after every other chunk.
func (q *chunkQueue) requeue(c chunkRange) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append([]chunkRange{c}, q.items...)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run 'TestSplitKeyspace|TestChunkQueue' -v`
Expected: PASS, all 6 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/smith/coordinator_chunks.go internal/smith/coordinator_chunks_test.go
git commit -m "feat(coordinator): chunk queue — pure keyspace splitting and pull logic"
```

---

### Task 2: Chunk request/response types and the crack-args builder

**Files:**
- Create: `internal/smith/coordinator_protocol.go`
- Test: `internal/smith/coordinator_protocol_test.go`

**Interfaces:**
- Consumes: `chunkRange` (Task 1) only by field shape (`.skip`, `.limit`), not by importing the type directly — `chunkRequest.Skip`/`.Limit` are plain `int64` fields a caller fills in from a `chunkRange`.
- Produces: `type chunkRequest struct{...}` (JSON tags as below), `type chunkResponse struct{...}`, `func buildCrackArgs(req chunkRequest, outFile string) ([]string, error)`. Task 3 consumes all three exactly as named.

- [ ] **Step 1: Write the failing tests**

```go
package smith

import (
	"reflect"
	"testing"
)

func TestBuildCrackArgsMask(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "5f4dcc3b5aa765d61d8327deb882cf99",
		Mode: "mask", Mask: "?l?l?l?l?l?l",
		Skip: 1000, Limit: 500,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5",
		"--skip", "1000", "--limit", "500",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "mask", "--mask", "?l?l?l?l?l?l",
		"5f4dcc3b5aa765d61d8327deb882cf99",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsMaskWithCustomCharsetsAndSalt(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "deadbeef", Salt: "abcd", SaltMode: "suffix",
		Mode: "mask", Mask: "?1?1?1", Charset1: "xyz",
		Skip: 0, Limit: 27,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5", "-s", "abcd", "-S", "suffix",
		"--skip", "0", "--limit", "27",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "mask", "--mask", "?1?1?1", "-1", "xyz",
		"deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsBrute(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "deadbeef",
		Mode: "brute", Charset: "abc", MinLen: 1, MaxLen: 3,
		Skip: 0, Limit: 39,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5",
		"--skip", "0", "--limit", "39",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "brute", "-C", "abc", "-n", "1", "-x", "3",
		"deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsDict(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "deadbeef",
		Mode: "dict", Wordlist: "/shared/words.txt",
		Skip: 0, Limit: 100,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5",
		"--skip", "0", "--limit", "100",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "dict", "-w", "/shared/words.txt",
		"deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsRejectsMissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		req  chunkRequest
	}{
		{"missing type", chunkRequest{Target: "x", Mode: "mask", Mask: "?l", Limit: 1}},
		{"missing target", chunkRequest{Type: "md5", Mode: "mask", Mask: "?l", Limit: 1}},
		{"negative skip", chunkRequest{Type: "md5", Target: "x", Mode: "mask", Mask: "?l", Skip: -1, Limit: 1}},
		{"zero limit", chunkRequest{Type: "md5", Target: "x", Mode: "mask", Mask: "?l", Limit: 0}},
		{"mask mode missing mask", chunkRequest{Type: "md5", Target: "x", Mode: "mask", Limit: 1}},
		{"brute mode missing charset", chunkRequest{Type: "md5", Target: "x", Mode: "brute", MinLen: 1, MaxLen: 2, Limit: 1}},
		{"dict mode missing wordlist", chunkRequest{Type: "md5", Target: "x", Mode: "dict", Limit: 1}},
		{"unknown mode", chunkRequest{Type: "md5", Target: "x", Mode: "nonsense", Limit: 1}},
	}
	for _, c := range cases {
		if _, err := buildCrackArgs(c.req, "/tmp/out.txt"); err == nil {
			t.Errorf("%s: expected an error, got none", c.name)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/smith/ -run TestBuildCrackArgs -v`
Expected: FAIL — `chunkRequest`, `buildCrackArgs` undefined.

- [ ] **Step 3: Implement**

```go
package smith

import (
	"errors"
	"fmt"
	"strconv"
)

// chunkRequest is the JSON body of a worker's POST /chunk — see
// docs/superpowers/specs/2026-10-03-distributed-coordinator-design.md.
type chunkRequest struct {
	Type     string `json:"type"`
	Target   string `json:"target"`
	Salt     string `json:"salt,omitempty"`
	SaltMode string `json:"saltMode,omitempty"`
	Mode     string `json:"mode"` // "mask" | "brute" | "dict"
	// mode == "mask"
	Mask     string `json:"mask,omitempty"`
	Charset1 string `json:"charset1,omitempty"`
	Charset2 string `json:"charset2,omitempty"`
	Charset3 string `json:"charset3,omitempty"`
	Charset4 string `json:"charset4,omitempty"`
	// mode == "brute"
	Charset string `json:"charset,omitempty"`
	MinLen  int    `json:"minLen,omitempty"`
	MaxLen  int    `json:"maxLen,omitempty"`
	// mode == "dict" — must already exist at this same path on the worker.
	Wordlist string `json:"wordlist,omitempty"`
	Skip     int64  `json:"skip"`
	Limit    int64  `json:"limit"`
}

// chunkResponse is the JSON body of a successful (200) /chunk response.
type chunkResponse struct {
	Found    bool   `json:"found"`
	Password string `json:"password,omitempty"`
}

// buildCrackArgs turns a validated chunkRequest into the exact []string a
// human would type for an equivalent local `hashsmith crack` invocation,
// writing its result to outFile via the existing -o mechanism. Returns an
// error for anything a caller should treat as a malformed request (HTTP
// 400), never for a "not found" outcome, which this function cannot see —
// that is determined later by whether outFile exists after runCrack runs.
func buildCrackArgs(req chunkRequest, outFile string) ([]string, error) {
	if req.Type == "" {
		return nil, errors.New("missing type")
	}
	if req.Target == "" {
		return nil, errors.New("missing target")
	}
	if req.Skip < 0 {
		return nil, errors.New("skip must be >= 0")
	}
	if req.Limit <= 0 {
		return nil, errors.New("limit must be > 0")
	}
	args := []string{"-t", req.Type}
	if req.Salt != "" {
		args = append(args, "-s", req.Salt)
	}
	if req.SaltMode != "" {
		args = append(args, "-S", req.SaltMode)
	}
	args = append(args,
		"--skip", strconv.FormatInt(req.Skip, 10),
		"--limit", strconv.FormatInt(req.Limit, 10),
		"--no-pot", "-o", outFile,
	)
	switch req.Mode {
	case "mask":
		if req.Mask == "" {
			return nil, errors.New("mode mask requires mask")
		}
		args = append(args, "-M", "mask", "--mask", req.Mask)
		if req.Charset1 != "" {
			args = append(args, "-1", req.Charset1)
		}
		if req.Charset2 != "" {
			args = append(args, "-2", req.Charset2)
		}
		if req.Charset3 != "" {
			args = append(args, "-3", req.Charset3)
		}
		if req.Charset4 != "" {
			args = append(args, "-4", req.Charset4)
		}
	case "brute":
		if req.Charset == "" || req.MinLen <= 0 || req.MaxLen <= 0 {
			return nil, errors.New("mode brute requires charset, minLen, and maxLen")
		}
		args = append(args, "-M", "brute", "-C", req.Charset,
			"-n", strconv.Itoa(req.MinLen), "-x", strconv.Itoa(req.MaxLen))
	case "dict":
		if req.Wordlist == "" {
			return nil, errors.New("mode dict requires wordlist")
		}
		args = append(args, "-M", "dict", "-w", req.Wordlist)
	default:
		return nil, fmt.Errorf("unknown mode %q: use mask, brute, or dict", req.Mode)
	}
	args = append(args, req.Target)
	return args, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run TestBuildCrackArgs -v`
Expected: PASS, all 5 tests (the table-driven rejection test counts as one).

- [ ] **Step 5: Commit**

```bash
git add internal/smith/coordinator_protocol.go internal/smith/coordinator_protocol_test.go
git commit -m "feat(coordinator): chunk request/response types and the crack-args builder"
```

---

### Task 3: Worker HTTP server

**Files:**
- Create: `internal/smith/coordinator_worker.go`
- Test: `internal/smith/coordinator_worker_test.go`
- Modify: `internal/smith/main.go` (add the `worker` subcommand)

**Interfaces:**
- Consumes: `chunkRequest`, `chunkResponse`, `buildCrackArgs` (Task 2); `runCrack(args []string) error` (existing, untouched).
- Produces: `func executeCrack(args []string, outFile string) (chunkResponse, error)`, `func chunkHandler(token string) http.HandlerFunc`, `func runWorker(args []string) error`. No later task consumes these directly (the end-to-end test in Task 7 talks to the worker only over real HTTP), but `runWorker`'s name and signature must match the `case "worker":` dispatch added to `main.go` in this same task.

- [ ] **Step 1: Write the failing tests**

First, read `internal/smith/main.go`'s existing dispatch switch (`case "benchmark", "bench":` etc., confirmed at line ~133-140 this session) to match its exact style before adding `case "worker":`.

```go
package smith

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestExecuteCrackFound(t *testing.T) {
	outFile := t.TempDir() + "/out.txt"
	target := md5hex("ab") // "ab" is within a 2-char lowercase mask
	args, err := buildCrackArgs(chunkRequest{
		Type: "md5", Target: target, Mode: "mask", Mask: "?l?l", Skip: 0, Limit: 676,
	}, outFile)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executeCrack(args, outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Found || resp.Password != "ab" {
		t.Fatalf("got %+v, want found=true password=ab", resp)
	}
}

func TestExecuteCrackNotFound(t *testing.T) {
	outFile := t.TempDir() + "/out.txt"
	args, err := buildCrackArgs(chunkRequest{
		Type: "md5", Target: "0000000000000000000000000000000000", Mode: "mask", Mask: "?l?l", Skip: 0, Limit: 676,
	}, outFile)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executeCrack(args, outFile)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Found {
		t.Fatalf("got %+v, want found=false", resp)
	}
}

func TestChunkHandlerRejectsWrongToken(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("right-token"))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{}`))
	req.Header.Set("X-Hashsmith-Token", "wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestChunkHandlerRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("t"))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`not json`))
	req.Header.Set("X-Hashsmith-Token", "t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestChunkHandlerRejectsInvalidMode(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("t"))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(
		`{"type":"md5","target":"x","mode":"nonsense","limit":1}`))
	req.Header.Set("X-Hashsmith-Token", "t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestChunkHandlerFindsRealTarget(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("t"))
	defer srv.Close()
	target := md5hex("zz")
	body := `{"type":"md5","target":"` + target + `","mode":"mask","mask":"?l?l","skip":0,"limit":676}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	req.Header.Set("X-Hashsmith-Token", "t")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := os.ReadFile("/dev/stdin") // placeholder never reached; real failure path below
		t.Fatalf("got status %d body=%v", resp.StatusCode, b)
	}
	var out chunkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Found || out.Password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz", out)
	}
}
```

Fix the placeholder in `TestChunkHandlerFindsRealTarget` before running it — it was left in to show you where a real failure message belongs, which the "No Placeholders" rule forbids shipping. Replace the `if resp.StatusCode != http.StatusOK` block with:

```go
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("got status %d, body: %s", resp.StatusCode, b)
	}
```

and add `"encoding/json"` and `"io"` to the import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/smith/ -run 'TestExecuteCrack|TestChunkHandler' -v`
Expected: FAIL — `executeCrack`, `chunkHandler` undefined.

- [ ] **Step 3: Implement**

```go
package smith

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// workerMu serializes every runCrack call on this worker process.
// runCrack's existing implementation shares the package-level exitCode
// variable across calls (see internal/smith/main.go), so only one chunk
// may run at a time per worker — a documented existing constraint, not a
// new one introduced here. Run more workers (more OS processes on
// different ports/machines) for more parallelism, not more concurrency
// within one worker.
var workerMu sync.Mutex

// executeCrack runs one chunk's args synchronously and reads back the
// result from outFile via the existing -o mechanism: the file is written
// only on a found result (confirmed this session by reading crack.go's
// own result-reporting code), so its absence after a nil-error run means
// not found. Returns a non-nil error only for a genuine runCrack failure
// (the HTTP handler turns that into a 500) — "not found" is a normal,
// successful chunkResponse with Found: false.
func executeCrack(args []string, outFile string) (chunkResponse, error) {
	workerMu.Lock()
	defer workerMu.Unlock()

	os.Remove(outFile) // start from "does not exist"; runCrack creates it fresh if found
	defer os.Remove(outFile)

	if err := runCrack(args); err != nil {
		return chunkResponse{}, err
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		if os.IsNotExist(err) {
			return chunkResponse{Found: false}, nil
		}
		return chunkResponse{}, err
	}
	return chunkResponse{Found: true, Password: strings.TrimRight(string(data), "\n")}, nil
}

// chunkHandler builds the POST /chunk handler, closing over the
// shared-secret token every request must carry in X-Hashsmith-Token.
func chunkHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hashsmith-Token") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req chunkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		tmp, err := os.CreateTemp("", "hashsmith-chunk-*.txt")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		outPath := tmp.Name()
		tmp.Close()
		defer os.Remove(outPath)

		args, err := buildCrackArgs(req, outPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := executeCrack(args, outPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// runWorker is the `hashsmith worker` subcommand entry point.
func runWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	listen := fs.String("listen", ":8745", "address to listen on")
	token := fs.String("token", "", "shared-secret token required on every request (must match the coordinator's --token)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return errors.New("--token is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/chunk", chunkHandler(*token))
	fmt.Fprintf(os.Stderr, "hashsmith worker listening on %s\n", *listen)
	return http.ListenAndServe(*listen, mux)
}
```

Now modify `internal/smith/main.go`: find the existing dispatch switch's `case "gpu":` arm (confirmed this session at line 137) and add a sibling arm immediately after it, matching its exact shape:

```go
	case "worker":
		if err := runWorker(rest); err != nil {
			fail(err.Error())
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go build ./... && go test ./internal/smith/ -run 'TestExecuteCrack|TestChunkHandler' -v`
Expected: clean build, PASS on all 6 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/smith/coordinator_worker.go internal/smith/coordinator_worker_test.go internal/smith/main.go
git commit -m "feat(coordinator): worker HTTP server and the \`hashsmith worker\` subcommand"
```

---

### Task 4: Coordinator keyspace computation and request template

**Files:**
- Create: `internal/smith/coordinator_keyspace.go`
- Test: `internal/smith/coordinator_keyspace_test.go`

**Interfaces:**
- Consumes: `bruteLayout(charset string, minLen, maxLen int) *keyspaceLayout` (existing, `keyspace.go:63`), `maskLayout(cfg *maskConfig) (*keyspaceLayout, error)` (existing, `keyspace.go:78`), `buildMaskConfig(mask, c1, c2, c3, c4 string, increment bool, incMin int, maskFirst bool) *maskConfig` (existing, `mask.go:285`), `exactWordlistCount(path string) (int64, error)` (existing, `crack.go:2516`), `keyspaceLayout.total` field (existing `int64`).
- Produces: `func coordinatorKeyspace(mode, mask, cs1, cs2, cs3, cs4, charset string, minLen, maxLen int, wordlist string) (int64, error)`. Task 6 consumes this exactly.

- [ ] **Step 1: Write the failing tests**

```go
package smith

import (
	"os"
	"testing"
)

func TestCoordinatorKeyspaceMask(t *testing.T) {
	// ?l?l is 26*26 = 676.
	got, err := coordinatorKeyspace("mask", "?l?l", "", "", "", "", "", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 676 {
		t.Fatalf("got %d, want 676", got)
	}
}

func TestCoordinatorKeyspaceBrute(t *testing.T) {
	// charset "ab", minLen 1, maxLen 2: "a","b" (2) + "aa".."bb" (4) = 6.
	got, err := coordinatorKeyspace("brute", "", "", "", "", "", "ab", 1, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 6 {
		t.Fatalf("got %d, want 6", got)
	}
}

func TestCoordinatorKeyspaceDict(t *testing.T) {
	path := t.TempDir() + "/words.txt"
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := coordinatorKeyspace("dict", "", "", "", "", "", "", 0, 0, path)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("got %d, want 3", got)
	}
}

func TestCoordinatorKeyspaceUnknownMode(t *testing.T) {
	if _, err := coordinatorKeyspace("nonsense", "", "", "", "", "", "", 0, 0, ""); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/smith/ -run TestCoordinatorKeyspace -v`
Expected: FAIL — `coordinatorKeyspace` undefined.

- [ ] **Step 3: Implement**

```go
package smith

import "fmt"

// coordinatorKeyspace computes the total candidate count for the
// coordinate command's chosen mode, reusing the exact same layout
// construction the normal (single-machine) crack path already uses
// internally — see keyspace.go's maskLayout/bruteLayout and crack.go's
// exactWordlistCount. This guarantees the coordinator's chunking is
// counting in the same units --skip/--limit already use everywhere else
// in this project.
func coordinatorKeyspace(mode, mask, cs1, cs2, cs3, cs4, charset string, minLen, maxLen int, wordlist string) (int64, error) {
	switch mode {
	case "mask":
		mc := buildMaskConfig(mask, cs1, cs2, cs3, cs4, false, 0, false)
		layout, err := maskLayout(mc)
		if err != nil {
			return 0, err
		}
		return layout.total, nil
	case "brute":
		layout := bruteLayout(charset, minLen, maxLen)
		return layout.total, nil
	case "dict":
		return exactWordlistCount(wordlist)
	default:
		return 0, fmt.Errorf("unknown mode %q: use mask, brute, or dict", mode)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run TestCoordinatorKeyspace -v`
Expected: PASS, all 4 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/smith/coordinator_keyspace.go internal/smith/coordinator_keyspace_test.go
git commit -m "feat(coordinator): keyspace computation reusing the existing layout builders"
```

---

### Task 5: Coordinator HTTP client — the per-worker pull loop

**Files:**
- Create: `internal/smith/coordinator_client.go`
- Test: `internal/smith/coordinator_client_test.go`

**Interfaces:**
- Consumes: `chunkRange`, `chunkQueue`, `newChunkQueue` (Task 1); `chunkRequest`, `chunkResponse` (Task 2); `chunkHandler` (Task 3, test-only — the test spins up a real `httptest.Server` wrapping it to exercise the client against a real handler).
- Produces: `type coordResult struct { found bool; password string; incomplete bool }`, `func postChunk(client *http.Client, url, token string, req chunkRequest) (chunkResponse, error)`, `func runCoordinatorLoop(workerURLs []string, token string, base chunkRequest, queue *chunkQueue) coordResult`, `const maxWorkerFailures = 3`. Task 6 consumes `coordResult` and `runCoordinatorLoop` exactly.

- [ ] **Step 1: Write the failing tests**

```go
package smith

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostChunkSuccess(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("t"))
	defer srv.Close()
	target := md5hex("zz")
	req := chunkRequest{Type: "md5", Target: target, Mode: "mask", Mask: "?l?l", Skip: 0, Limit: 676}
	resp, err := postChunk(http.DefaultClient, srv.URL, "t", req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Found || resp.Password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz", resp)
	}
}

func TestPostChunkWrongTokenIsAnError(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("right"))
	defer srv.Close()
	req := chunkRequest{Type: "md5", Target: "x", Mode: "mask", Mask: "?l", Skip: 0, Limit: 1}
	if _, err := postChunk(http.DefaultClient, srv.URL, "wrong", req); err == nil {
		t.Fatal("expected an error for a wrong token")
	}
}

func TestRunCoordinatorLoopFindsAcrossTwoWorkers(t *testing.T) {
	srv1 := httptest.NewServer(chunkHandler("t"))
	defer srv1.Close()
	srv2 := httptest.NewServer(chunkHandler("t"))
	defer srv2.Close()

	// "zz" -> index 675 of ?l?l's 676-candidate keyspace (a=0..z=25, so
	// "zz" is the very last one, in the final chunk: [600,676) with
	// chunk-size 100). Which of the two workers actually pulls that last
	// chunk is a race, not deterministic -- the point is that finding it
	// at all requires BOTH workers pulling chunks until the queue (all 7
	// of them) is fully drained, not just one worker getting lucky on an
	// early guess.
	target := md5hex("zz")
	base := chunkRequest{Type: "md5", Target: target, Mode: "mask", Mask: "?l?l"}
	queue := newChunkQueue(splitKeyspace(676, 100)) // 7 chunks of <=100

	result := runCoordinatorLoop([]string{srv1.URL, srv2.URL}, "t", base, queue)
	if !result.found || result.password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz", result)
	}
}

func TestRunCoordinatorLoopNotFound(t *testing.T) {
	srv := httptest.NewServer(chunkHandler("t"))
	defer srv.Close()
	base := chunkRequest{Type: "md5", Target: "0000000000000000000000000000000000", Mode: "mask", Mask: "?l?l"}
	queue := newChunkQueue(splitKeyspace(676, 100))

	result := runCoordinatorLoop([]string{srv.URL}, "t", base, queue)
	if result.found || result.incomplete {
		t.Fatalf("got %+v, want found=false incomplete=false", result)
	}
}

func TestRunCoordinatorLoopDeadWorkerChunksGoToOthers(t *testing.T) {
	srvGood := httptest.NewServer(chunkHandler("t"))
	defer srvGood.Close()
	// A URL nothing is listening on -- every request to it fails immediately.
	deadURL := "http://127.0.0.1:1" // port 1 is reserved, nothing binds it

	target := md5hex("zz")
	base := chunkRequest{Type: "md5", Target: target, Mode: "mask", Mask: "?l?l"}
	queue := newChunkQueue(splitKeyspace(676, 100))

	result := runCoordinatorLoop([]string{deadURL, srvGood.URL}, "t", base, queue)
	if !result.found || result.password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz (the live worker should pick up every chunk)", result)
	}
}

func TestRunCoordinatorLoopAllWorkersDeadIsIncomplete(t *testing.T) {
	queue := newChunkQueue(splitKeyspace(676, 100))
	base := chunkRequest{Type: "md5", Target: "x", Mode: "mask", Mask: "?l?l"}
	result := runCoordinatorLoop([]string{"http://127.0.0.1:1"}, "t", base, queue)
	if !result.incomplete {
		t.Fatalf("got %+v, want incomplete=true", result)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/smith/ -run 'TestPostChunk|TestRunCoordinatorLoop' -v -timeout 30s`
Expected: FAIL — `postChunk`, `runCoordinatorLoop`, `coordResult` undefined.

- [ ] **Step 3: Implement**

```go
package smith

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// coordResult is the final outcome of one coordinate run.
type coordResult struct {
	found      bool
	password   string
	incomplete bool // true: the queue never fully drained because every worker assigned to its remaining chunks failed
}

// maxWorkerFailures: after this many CONSECUTIVE failures (timeouts,
// connection errors, non-2xx other than a wrong-token 401) a worker is
// dropped from the run — its goroutine exits rather than retrying forever.
// A 401 is NOT a transient failure (retrying the same wrong token will
// never succeed) and drops the worker on the first occurrence instead.
const maxWorkerFailures = 3

var errUnauthorized = errors.New("worker rejected token (401)")

// postChunk sends one chunk to one worker and returns its result, or an
// error for anything that is not a clean 200 (including the 401 case,
// returned as the exact errUnauthorized sentinel so callers can tell it
// apart from a transient failure without string-matching).
func postChunk(client *http.Client, url, token string, req chunkRequest) (chunkResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return chunkResponse{}, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(url, "/")+"/chunk", bytes.NewReader(body))
	if err != nil {
		return chunkResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Hashsmith-Token", token)
	resp, err := client.Do(httpReq)
	if err != nil {
		return chunkResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return chunkResponse{}, errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return chunkResponse{}, fmt.Errorf("worker returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out chunkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return chunkResponse{}, err
	}
	return out, nil
}

// runCoordinatorLoop runs one goroutine per worker URL, each pulling
// chunks from queue until one of: the queue is empty, this worker is
// dropped for repeated failures, or any worker (including a different
// one) has reported found. base is the shared chunkRequest template
// (type/target/mode/mask or charset/wordlist); only Skip/Limit vary per
// chunk.
func runCoordinatorLoop(workerURLs []string, token string, base chunkRequest, queue *chunkQueue) coordResult {
	var (
		mu     sync.Mutex
		result coordResult
		found  bool
		wg     sync.WaitGroup
	)
	doneOnce := sync.Once{}
	done := make(chan struct{})
	client := &http.Client{Timeout: 5 * time.Minute}

	for _, url := range workerURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			failures := 0
			for {
				select {
				case <-done:
					return
				default:
				}
				chunk, ok := queue.next()
				if !ok {
					return
				}
				req := base
				req.Skip, req.Limit = chunk.skip, chunk.limit
				resp, err := postChunk(client, url, token, req)
				if err != nil {
					queue.requeue(chunk)
					if errors.Is(err, errUnauthorized) {
						fmt.Fprintf(os.Stderr, "worker %s: rejected token, dropping this worker\n", url)
						return
					}
					failures++
					if failures >= maxWorkerFailures {
						fmt.Fprintf(os.Stderr, "worker %s: giving up after %d failures (%v)\n", url, failures, err)
						return
					}
					continue
				}
				failures = 0
				if resp.Found {
					mu.Lock()
					if !found {
						found = true
						result = coordResult{found: true, password: resp.Password}
					}
					mu.Unlock()
					doneOnce.Do(func() { close(done) })
					return
				}
			}
		}(url)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if found {
		return result
	}
	if _, stillQueued := queue.next(); stillQueued {
		// Every goroutine exited yet the queue isn't empty: every worker
		// that could have taken the remaining chunks was dropped.
		return coordResult{incomplete: true}
	}
	return coordResult{found: false}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/smith/ -run 'TestPostChunk|TestRunCoordinatorLoop' -v -timeout 30s`
Expected: PASS, all 6 tests. (`TestRunCoordinatorLoopDeadWorkerChunksGoToOthers` and `TestRunCoordinatorLoopAllWorkersDeadIsIncomplete` connect to a reserved, never-listening port — they should fail fast on connection refused, not hang; if either takes anywhere near the 5-minute client timeout, something is wrong and needs investigating before moving on, not waiting out.)

- [ ] **Step 5: Commit**

```bash
git add internal/smith/coordinator_client.go internal/smith/coordinator_client_test.go
git commit -m "feat(coordinator): HTTP client pull loop across workers, with failure handling"
```

---

### Task 6: `coordinate` CLI subcommand

**Files:**
- Create: `internal/smith/coordinator_cmd.go`
- Test: `internal/smith/coordinator_cmd_test.go`
- Modify: `internal/smith/main.go` (add the `coordinate` subcommand, alongside `worker` from Task 3)

**Interfaces:**
- Consumes: `coordinatorKeyspace` (Task 4); `splitKeyspace`, `newChunkQueue` (Task 1); `runCoordinatorLoop`, `coordResult` (Task 5); `chunkRequest` (Task 2); the package-level `exitCode` variable (existing, `main.go:12`).
- Produces: `func runCoordinate(args []string) error`. Must match the `case "coordinate":` dispatch added to `main.go` in this task.

- [ ] **Step 1: Write the failing tests**

This command's own flag-parsing and end-to-end behavior is better exercised as a real end-to-end test in Task 7 (against real worker HTTP servers) than mocked here. This task's own test instead pins the one piece of pure logic specific to this file: the required-flag validation, which has no network dependency and should fail fast with a clear message rather than attempt a keyspace computation or any HTTP call.

```go
package smith

import "testing"

func TestRunCoordinateRequiresType(t *testing.T) {
	err := runCoordinate([]string{"--workers", "http://x", "--token", "t", "--chunk-size", "100", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when -t is missing")
	}
}

func TestRunCoordinateRequiresWorkers(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--token", "t", "--chunk-size", "100", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when --workers is missing")
	}
}

func TestRunCoordinateRequiresToken(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--workers", "http://x", "--chunk-size", "100", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when --token is missing")
	}
}

func TestRunCoordinateRequiresChunkSize(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--workers", "http://x", "--token", "t", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when --chunk-size is missing (there is no safe default)")
	}
}

func TestRunCoordinateRequiresExactlyOneTarget(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--workers", "http://x", "--token", "t", "--chunk-size", "100", "--mask", "?l"})
	if err == nil {
		t.Fatal("expected an error when no target is given")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/smith/ -run TestRunCoordinate -v`
Expected: FAIL — `runCoordinate` undefined.

- [ ] **Step 3: Implement**

```go
package smith

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// runCoordinate is the `hashsmith coordinate` subcommand entry point.
func runCoordinate(args []string) error {
	fs := flag.NewFlagSet("coordinate", flag.ContinueOnError)
	typ := fs.String("t", "", "hash type")
	mode := fs.String("M", "mask", "attack mode: mask|brute|dict")
	mask := fs.String("mask", "", "mask (mode mask)")
	cs1 := fs.String("1", "", "custom charset 1 (mode mask)")
	cs2 := fs.String("2", "", "custom charset 2 (mode mask)")
	cs3 := fs.String("3", "", "custom charset 3 (mode mask)")
	cs4 := fs.String("4", "", "custom charset 4 (mode mask)")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (mode brute)")
	minLen := fs.Int("n", 1, "min length (mode brute)")
	maxLen := fs.Int("x", 4, "max length (mode brute)")
	wordlist := fs.String("w", "", "wordlist path (mode dict; must exist at this exact path on every worker)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workersFlag := fs.String("workers", "", "comma-separated worker URLs, e.g. http://host1:8745,http://host2:8745")
	token := fs.String("token", "", "shared-secret token (must match every worker's --token)")
	chunkSize := fs.Int64("chunk-size", 0, "candidates per chunk; required, no default -- there is no safe universal size across hash types whose speed differs by many orders of magnitude. Run `hashsmith benchmark -t <type>` first and pick roughly (seconds per chunk you want) x (that rate)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *typ == "" {
		return errors.New("-t is required")
	}
	if *workersFlag == "" {
		return errors.New("--workers is required")
	}
	if *token == "" {
		return errors.New("--token is required")
	}
	if *chunkSize <= 0 {
		return fmt.Errorf("--chunk-size is required and must be > 0 -- run `hashsmith benchmark -t %s` first and pick a size that takes roughly 5-30 seconds per chunk", *typ)
	}
	targets := fs.Args()
	if len(targets) != 1 {
		return fmt.Errorf("coordinate takes exactly one target hash, got %d", len(targets))
	}
	target := targets[0]
	workerURLs := strings.Split(*workersFlag, ",")

	total, err := coordinatorKeyspace(*mode, *mask, *cs1, *cs2, *cs3, *cs4, *charset, *minLen, *maxLen, *wordlist)
	if err != nil {
		return err
	}

	base := chunkRequest{
		Type: *typ, Target: target, Salt: *salt, SaltMode: *saltMode, Mode: *mode,
		Mask: *mask, Charset1: *cs1, Charset2: *cs2, Charset3: *cs3, Charset4: *cs4,
		Charset: *charset, MinLen: *minLen, MaxLen: *maxLen, Wordlist: *wordlist,
	}

	chunks := splitKeyspace(total, *chunkSize)
	if len(chunks) == 0 {
		fmt.Println("Not found")
		exitCode = 1
		return nil
	}
	queue := newChunkQueue(chunks)
	result := runCoordinatorLoop(workerURLs, *token, base, queue)
	switch {
	case result.found:
		fmt.Printf("Found: %s\n", result.password)
		exitCode = 0
	case result.incomplete:
		fmt.Fprintln(os.Stderr, "Error: every worker failed before the keyspace was fully covered -- this is NOT a confirmed \"not found\"")
		exitCode = 2
	default:
		fmt.Println("Not found")
		exitCode = 1
	}
	return nil
}
```

Now modify `internal/smith/main.go`: add a sibling arm immediately after the `case "worker":` arm added in Task 3:

```go
	case "coordinate":
		if err := runCoordinate(rest); err != nil {
			fail(err.Error())
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go build ./... && go test ./internal/smith/ -run TestRunCoordinate -v`
Expected: clean build, PASS on all 5 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/smith/coordinator_cmd.go internal/smith/coordinator_cmd_test.go internal/smith/main.go
git commit -m "feat(coordinator): the \`hashsmith coordinate\` subcommand"
```

---

### Task 7: End-to-end test against real local worker processes

**Files:**
- Test: `internal/smith/coordinator_e2e_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-6. No new production code — this task is pure test, proving the pieces work together over a REAL `net/http` listener (not an in-process shortcut), matching the spec's stated validation scope (loopback, multiple local processes — here, multiple real `httptest.Server`-backed listeners on distinct ephemeral ports, which is a real TCP/HTTP stack round-trip, just not a separate OS process; the plan's Step 1 note explains why that distinction doesn't matter for what this test proves).

- [ ] **Step 1: Write the test**

`httptest.NewServer` already binds a real OS-assigned TCP port on `127.0.0.1` and serves real HTTP — the distinction from a separately-`exec.Command`-spawned `hashsmith worker` process is only which Go runtime's goroutines handle the request, not the network path, which is the thing this test exists to exercise end-to-end (real JSON marshaling over a real socket, real concurrent `executeCrack` calls guarded by `workerMu`, a real pull-based chunk race across workers). A full subprocess-based test would exercise CLI flag parsing too, which Task 3's and Task 6's own tests already cover directly — this task's job is the protocol, not reproving flag parsing.

```go
package smith

import (
	"net/http/httptest"
	"testing"
)

// TestCoordinatorEndToEndFindsAcrossThreeWorkers exercises the whole
// pipeline: real keyspace computation, real chunk splitting, three real
// HTTP servers each running real executeCrack calls, a real pull-based
// race to find the one chunk containing the password.
func TestCoordinatorEndToEndFindsAcrossThreeWorkers(t *testing.T) {
	const token = "e2e-test-token"
	var servers []*httptest.Server
	var urls []string
	for i := 0; i < 3; i++ {
		srv := httptest.NewServer(chunkHandler(token))
		defer srv.Close()
		servers = append(servers, srv)
		urls = append(urls, srv.URL)
	}

	// "zz" is the very last candidate of mask ?l?l's 676-candidate
	// keyspace (a=0..z=25 per position), so only a worker that actually
	// reaches the final chunk can find it -- this fails if the pull
	// distribution logic is broken, not just if any one worker happens
	// to get lucky.
	target := md5hex("zz")
	total, err := coordinatorKeyspace("mask", "?l?l", "", "", "", "", "", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if total != 676 {
		t.Fatalf("got total %d, want 676", total)
	}
	queue := newChunkQueue(splitKeyspace(total, 50)) // 14 chunks across 3 workers
	base := chunkRequest{Type: "md5", Target: target, Mode: "mask", Mask: "?l?l"}

	result := runCoordinatorLoop(urls, token, base, queue)
	if !result.found || result.password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz", result)
	}
}

// TestCoordinatorEndToEndWrongTokenWorkerIsSkippedButOthersSucceed proves
// the spec's own stated behavior: a worker with a mismatched token is
// dropped immediately (not retried), and the run still succeeds using the
// remaining, correctly-configured workers.
func TestCoordinatorEndToEndWrongTokenWorkerIsSkippedButOthersSucceed(t *testing.T) {
	srvRight := httptest.NewServer(chunkHandler("right-token"))
	defer srvRight.Close()
	srvWrong := httptest.NewServer(chunkHandler("different-token-on-this-one"))
	defer srvWrong.Close()

	target := md5hex("zz")
	total, err := coordinatorKeyspace("mask", "?l?l", "", "", "", "", "", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	queue := newChunkQueue(splitKeyspace(total, 50))
	base := chunkRequest{Type: "md5", Target: target, Mode: "mask", Mask: "?l?l"}

	// The coordinator sends "right-token" to both; srvWrong will reject
	// every request with 401 since its own handler was built with a
	// different token.
	result := runCoordinatorLoop([]string{srvRight.URL, srvWrong.URL}, "right-token", base, queue)
	if !result.found || result.password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz (via the correctly-tokened worker)", result)
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/smith/ -run TestCoordinatorEndToEnd -v -timeout 30s`
Expected: PASS, both tests.

- [ ] **Step 3: Run the full package suite**

Run: `go test -timeout 1200s ./internal/smith/... 2>&1 | tail -5` — but per this project's own repeated lesson this session, do not trust a piped exit code; read the actual "ok"/"FAIL" text in the output, and separately confirm no background `go test` process is left running afterward (`ps aux | grep "go test"` should show nothing).
Expected: `ok hashsmith-go/internal/smith <duration>`.

- [ ] **Step 4: Commit**

```bash
git add internal/smith/coordinator_e2e_test.go
git commit -m "test(coordinator): end-to-end test against real local worker HTTP servers"
```

---

## Plan self-review (performed before handing this plan off)

- **Spec coverage:** worker HTTP server + `/chunk` endpoint (Tasks 2-3), coordinator keyspace computation + chunking (Tasks 1, 4), pull-based distribution with failure handling (Task 5), both CLI subcommands (Tasks 3, 6), token auth (Tasks 2-3, 5, tested in Task 7), shared-path wordlist assumption (documented in Task 6's `-w` help text and `coordinatorKeyspace`'s dict case, never contradicted by shipping wordlist content), no mid-chunk cancellation (Task 5's `runCoordinatorLoop` never cancels an in-flight `postChunk` call — matches the spec's explicit non-goal), end-to-end loopback validation (Task 7). No spec section lacks a task.
- **Placeholder scan:** one found and fixed inline during authoring — `TestChunkHandlerFindsRealTarget`'s draft failure-message line (`os.ReadFile("/dev/stdin")`) was replaced with a real `io.ReadAll(resp.Body)` before this plan was finalized; Task 3's Step 1 keeps the fix instruction visible since an implementer typing the test by hand would otherwise reproduce the mistake.
- **Type consistency:** `chunkRange{skip, limit int64}` (Task 1) is read field-by-field into `chunkRequest.Skip`/`.Limit` (Task 2, both `int64`) everywhere it's used (Tasks 5, 6, 7) — no mismatched field name or type anywhere. `coordResult{found bool, password string, incomplete bool}` (Task 5) is read with exactly those three field names in Task 6's `switch` and Task 7's assertions.
