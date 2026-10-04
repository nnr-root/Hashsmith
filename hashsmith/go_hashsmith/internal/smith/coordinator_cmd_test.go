package smith

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

// fakeChunkServer is a minimal stand-in for a real worker's POST /chunk
// handler: it checks the token and always answers with resp, regardless of
// the chunk requested. Unlike the real chunkHandler (coordinator_worker.go),
// it never runs an actual crack -- which matters here because these tests
// run the "worker" in-process via httptest.Server, sharing this test
// process's single os.Stdout with whatever runCoordinate itself writes. A
// real chunkHandler's own runCrack call writes its own `hash:plaintext` line
// to that same stdout, which would double up with the line under test. In a
// real deployment the worker is a separate OS process with its own stdout,
// so that duplication is purely a test-harness artifact to avoid here, not a
// product behavior -- genuine end-to-end coverage of the real worker belongs
// in Task 7.
func fakeChunkServer(t *testing.T, token string, resp chunkResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hashsmith-Token") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRunCoordinateEmitsStdoutOnFound confirms a found password is written to
// STDOUT as a machine-readable `hash:plaintext` line (the same convention
// results_stdout.go documents for `crack`), not as human-facing text.
func TestRunCoordinateEmitsStdoutOnFound(t *testing.T) {
	preserveExitCode(t)
	srv := fakeChunkServer(t, "t", chunkResponse{Found: true, Password: "zz"})

	target := md5hex("zz")
	args := []string{
		"-t", "md5", "-M", "mask", "--mask", "?l?l",
		"--workers", srv.URL, "--token", "t", "--chunk-size", "1000",
		target,
	}
	out := captureStdout(t, func() error { return runCoordinate(args) })
	want := target + ":zz\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
}

// TestRunCoordinateEmitsNothingOnStdoutWhenNotFound confirms a miss writes
// nothing to STDOUT at all -- the whole point of the stdout/stderr split is
// that `coordinate ... > found.txt` produces an empty file on a miss, not a
// file containing the literal text "Not found".
func TestRunCoordinateEmitsNothingOnStdoutWhenNotFound(t *testing.T) {
	preserveExitCode(t)
	srv := fakeChunkServer(t, "t", chunkResponse{Found: false})

	args := []string{
		"-t", "md5", "-M", "mask", "--mask", "?l?l",
		"--workers", srv.URL, "--token", "t", "--chunk-size", "1000",
		"0000000000000000000000000000000000",
	}
	out := captureStdout(t, func() error { return runCoordinate(args) })
	if out != "" {
		t.Fatalf("stdout = %q, want empty", out)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
}

// TestRunCoordinateTargetFirstArgOrdering confirms coordinate parses via
// parseArgsFlexible: putting the positional target first (as crack itself
// supports) must not be misread as part of an over-long positional list.
func TestRunCoordinateTargetFirstArgOrdering(t *testing.T) {
	preserveExitCode(t)
	srv := fakeChunkServer(t, "t", chunkResponse{Found: true, Password: "zz"})

	target := md5hex("zz")
	args := []string{
		target,
		"-t", "md5", "-M", "mask", "--mask", "?l?l",
		"--workers", srv.URL, "--token", "t", "--chunk-size", "1000",
	}
	out := captureStdout(t, func() error { return runCoordinate(args) })
	want := target + ":zz\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q (target-first ordering must still parse and find it)", out, want)
	}
}
