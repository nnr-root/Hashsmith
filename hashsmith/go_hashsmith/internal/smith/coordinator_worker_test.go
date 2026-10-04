package smith

import (
	"encoding/json"
	"io"
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

// TestExecuteCrackFoundEmptyPassword guards against the regression caught in
// code review: a chunk can legitimately be "found" with an empty-string
// password (dict mode's streamWordlistBatches, crack.go:2074, explicitly
// keeps blank wordlist lines as candidates), and the write path
// (outWriter.writeLine's fmt.Fprintln(w.f, "") or the os.WriteFile
// fallback) still writes at least the newline byte for that case. A
// found/not-found check based on the trimmed string being empty cannot
// distinguish that 1-byte file from the 0-byte not-found file, so it must
// be based on raw byte length instead. md5("") = d41d8cd98f00b204e9800998ecf8427e.
func TestExecuteCrackFoundEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	wordlist := dir + "/words.txt"
	if err := os.WriteFile(wordlist, []byte("\n"), 0644); err != nil {
		t.Fatal(err)
	}
	outFile := dir + "/out.txt"
	args, err := buildCrackArgs(chunkRequest{
		Type: "md5", Target: "d41d8cd98f00b204e9800998ecf8427e",
		Mode: "dict", Wordlist: wordlist, Skip: 0, Limit: 1,
	}, outFile)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executeCrack(args, outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Found || resp.Password != "" {
		t.Fatalf("got %+v, want found=true password=\"\"", resp)
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
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("got status %d, body: %s", resp.StatusCode, b)
	}
	var out chunkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Found || out.Password != "zz" {
		t.Fatalf("got %+v, want found=true password=zz", out)
	}
}
