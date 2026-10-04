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
