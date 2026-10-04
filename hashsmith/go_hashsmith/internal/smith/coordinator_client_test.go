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
