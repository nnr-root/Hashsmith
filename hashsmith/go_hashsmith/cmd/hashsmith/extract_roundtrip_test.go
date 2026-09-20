package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ── Extractor round trips ─────────────────────────────────────────────────────
//
// No test anywhere took a REAL container file, ran the extractor over it, and
// then cracked the record it produced with the password the file was built
// with. Every extractor test used a hand-written fixture, which checks that
// the parser reads what the test author believed the format to be — not what
// the format is.
//
// Each case here does the whole loop:
//
//	build a container with a known password
//	  -> extract a record from it
//	    -> crack that record with the password   (must be FOUND)
//	    -> crack it with a different password    (must NOT be found)
//
// The second check matters as much as the first. A verifier that accepts a
// short prefix, or that drops the authentication tag, reports a wrong password
// as correct — and a round trip that only tested the right password would pass
// happily while the extractor was useless.

// requireTool skips the test when a container-building tool is absent, which
// is the normal case in CI. A skip says so; it does not pass quietly.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed here, so this container cannot be built", name)
	}
	return p
}

// extractRecords runs an extractor over a file and returns the records.
func extractRecords(t *testing.T, bin, extractor, path string) []string {
	t.Helper()
	cmd := exec.Command(bin, "-N", extractor, "-f", path)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s -f %s failed: %v\n%s", extractor, filepath.Base(path), err, out)
	}
	var recs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// A record is the line that carries the format tag; the rest is banner
		// and commentary.
		if strings.HasPrefix(line, "$") || strings.Contains(line, "$") && len(line) > 20 {
			recs = append(recs, line)
		}
	}
	if len(recs) == 0 {
		t.Fatalf("%s produced no record for %s:\n%s", extractor, filepath.Base(path), out)
	}
	return recs
}

// crackRecord reports whether the record cracks with candidate.
func crackRecord(t *testing.T, bin, record, candidate string) bool {
	t.Helper()
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte(candidate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(dir, "rec.txt")
	if err := os.WriteFile(rec, []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-N", "crack", rec, "-w", wl, "--no-pot")
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+dir)
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "Found:") ||
		strings.Contains(string(out), ":"+candidate)
}

// assertRoundTrip runs the whole loop for one container.
func assertRoundTrip(t *testing.T, bin, extractor, path, password string) {
	t.Helper()
	records := extractRecords(t, bin, extractor, path)
	t.Logf("%s produced %d record(s); first is %.70s", extractor, len(records), records[0])

	var cracked bool
	for _, r := range records {
		if crackRecord(t, bin, r, password) {
			cracked = true
			break
		}
	}
	if !cracked {
		t.Errorf("%s: no record cracked with the password the container was built with (%q)",
			extractor, password)
	}

	// A wrong password must be rejected by EVERY record. One that accepts it
	// is worse than one that fails outright: it reports a wrong answer.
	const wrong = "definitely-not-the-password-9137"
	for _, r := range records {
		if crackRecord(t, bin, r, wrong) {
			t.Errorf("%s: a record accepted a wrong password — this extractor reports false positives\n  %.90s",
				extractor, r)
		}
	}
}

func TestZipCryptoRoundTrip(t *testing.T) {
	zipBin := requireTool(t, "zip")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("round trip payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "legacy.zip")
	const password = "correct horse"
	cmd := exec.Command(zipBin, "-j", "-P", password, archive, payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("zip could not build a ZipCrypto archive: %v\n%s", err, out)
	}
	assertRoundTrip(t, bin, "zip2smith", archive, password)
}

func TestZipAESRoundTrip(t *testing.T) {
	sevenZip := requireTool(t, "7z")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("aes payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "aes.zip")
	const password = "correct horse"
	cmd := exec.Command(sevenZip, "a", "-tzip", "-mem=AES256", "-p"+password, archive, payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("7z could not build a WinZip AES archive: %v\n%s", err, out)
	}
	assertRoundTrip(t, bin, "zip2smith", archive, password)
}

// 7z is a KNOWN GAP, asserted as one rather than left to look like a pass.
//
// The extractor reads the AES parameters correctly but cannot reach the CRC
// and unpacked size that verification needs — those live inside the nested,
// VINT-encoded next-header it does not parse. It used to emit a record anyway,
// which could never crack: a user ran a long attack against something that
// could not match and concluded their wordlist was wrong.
//
// This test pins the refusal AND the reason. When the header parser is
// written, this test starts failing, which is the signal to replace it with
// the round trip the other extractors get.
func Test7zRefusesRatherThanEmittingAnUncrackableRecord(t *testing.T) {
	sevenZip := requireTool(t, "7z")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	payload := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("seven zip payload. ", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	const password = "correct horse"

	// Both shapes: header-encrypted and data-only.
	for _, args := range [][]string{
		{"a", "-t7z", "-p" + password},
		{"a", "-t7z", "-mhe=on", "-p" + password},
	} {
		archive := filepath.Join(dir, "a"+strings.Join(args, "")+".7z")
		cmd := exec.Command(sevenZip, append(append([]string{}, args...), archive, payload)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("7z could not build an archive: %v\n%s", err, out)
		}

		run := exec.Command(bin, "-N", "7z2smith", "-f", archive)
		run.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+dir)
		out, err := run.CombinedOutput()
		if err == nil {
			t.Errorf("7z2smith produced a record for %s; if the next-header parser now exists, "+
				"replace this test with a real round trip\n%s", filepath.Base(archive), out)
			continue
		}
		msg := string(out)
		for _, want := range []string{"CRC", "next-header", "11600"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the refusal does not mention %q, so it does not tell the user what to do:\n%s", want, msg)
			}
		}
	}
}

func TestSSHKeyRoundTrip(t *testing.T) {
	keygen := requireTool(t, "ssh-keygen")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	key := filepath.Join(dir, "id_rsa")
	const password = "correct horse"
	cmd := exec.Command(keygen, "-t", "rsa", "-b", "2048", "-N", password, "-f", key, "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen could not build a key: %v\n%s", err, out)
	}
	assertRoundTrip(t, bin, "ssh2smith", key, password)
}

func TestPKCS12RoundTrip(t *testing.T) {
	ossl := requireTool(t, "openssl")
	bin := buildTestBinary(t)
	dir := t.TempDir()

	key := filepath.Join(dir, "k.pem")
	crt := filepath.Join(dir, "c.pem")
	p12 := filepath.Join(dir, "bundle.p12")
	const password = "correct horse"

	gen := exec.Command(ossl, "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
		"-out", crt, "-days", "1", "-nodes", "-subj", "/CN=hashsmith-test")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("openssl could not build a certificate: %v\n%s", err, out)
	}
	pack := exec.Command(ossl, "pkcs12", "-export", "-out", p12, "-inkey", key,
		"-in", crt, "-passout", "pass:"+password)
	if out, err := pack.CombinedOutput(); err != nil {
		t.Skipf("openssl could not build a PKCS#12 bundle: %v\n%s", err, out)
	}
	assertRoundTrip(t, bin, "pfx2smith", p12, password)
}
