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
// result from outFile via the existing -o mechanism. Contrary to this
// function's original draft comment, runCrack's own newOutWriter (see
// crack.go) opens outFile with O_CREATE|O_TRUNC up front regardless of
// outcome, so the file always exists after a nil-error run — it is only
// ever non-empty when a result line was appended on success. So emptiness,
// not existence, is the real "not found" signal; verified directly by
// TestExecuteCrackNotFound failing against the existence-only check during
// implementation. Returns a non-nil error only for a genuine runCrack
// failure (the HTTP handler turns that into a 500) — "not found" is a
// normal, successful chunkResponse with Found: false.
func executeCrack(args []string, outFile string) (chunkResponse, error) {
	workerMu.Lock()
	defer workerMu.Unlock()

	os.Remove(outFile) // start from "does not exist"; runCrack recreates it either way
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
	password := strings.TrimRight(string(data), "\n")
	if password == "" {
		return chunkResponse{Found: false}, nil
	}
	return chunkResponse{Found: true, Password: password}, nil
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
