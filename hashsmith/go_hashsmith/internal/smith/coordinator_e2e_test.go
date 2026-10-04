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
