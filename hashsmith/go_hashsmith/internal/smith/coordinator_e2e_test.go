package smith

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestCoordinatorEndToEndFindsAcrossThreeWorkers exercises the whole
// pipeline: real keyspace computation, real chunk splitting, three real
// HTTP servers each running real executeCrack calls, a real pull-based
// race to find the one chunk containing the password. Concurrency is
// exercised in chunk-pulling and HTTP dispatch across worker goroutines,
// not in parallel crack execution (workerMu serializes per-worker execution).
func TestCoordinatorEndToEndFindsAcrossThreeWorkers(t *testing.T) {
	const token = "e2e-test-token"
	counts := make([]int64, 3)
	var urls []string
	for i := 0; i < 3; i++ {
		idx := i // avoid loop-variable capture
		wrapped := func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&counts[idx], 1)
				h.ServeHTTP(w, r)
			})
		}(chunkHandler(token))
		srv := httptest.NewServer(wrapped)
		defer srv.Close()
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

	participating := 0
	for i := range counts {
		if atomic.LoadInt64(&counts[i]) > 0 {
			participating++
		}
	}
	if participating < 2 {
		t.Fatalf("got %d workers contacted (%v), want at least 2 -- distribution did not actually spread across workers", participating, counts)
	}
}

// TestCoordinatorEndToEndWrongTokenWorkerIsSkippedButOthersSucceed proves
// the spec's own stated behavior: a worker with a mismatched token is
// dropped immediately (not retried), and the run still succeeds using the
// remaining, correctly-configured workers.
func TestCoordinatorEndToEndWrongTokenWorkerIsSkippedButOthersSucceed(t *testing.T) {
	srvRight := httptest.NewServer(chunkHandler("right-token"))
	defer srvRight.Close()

	var wrongCount int64
	wrongHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&wrongCount, 1)
		chunkHandler("different-token-on-this-one").ServeHTTP(w, r)
	})
	srvWrong := httptest.NewServer(wrongHandler)
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

	if got := atomic.LoadInt64(&wrongCount); got != 1 {
		t.Fatalf("got %d requests to the wrong-token worker, want exactly 1 -- it must be contacted once (proving it wasn't silently skipped) and never retried after its 401 (proving immediate-drop-on-401, not the N-retry path used for transient failures)", got)
	}
}
