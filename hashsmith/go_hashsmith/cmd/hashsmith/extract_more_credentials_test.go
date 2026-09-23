package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// ── IBM i ────────────────────────────────────────────────────────────────────

// The record John ships for this format carries the user name TWICE: once as
// the label and once as the salt. A reader that drops either copy produces a
// file that looks right.
func TestExtractIBMiScanner(t *testing.T) {
	record, password := johnVector(t, "as400-ssha1 $as400ssha1$")
	f := strings.Split(strings.TrimPrefix(record, "$as400ssha1$"), "$")
	digest, user := f[0], f[1]

	file := "# a comment\n" + user + ":" + digest + "\n" + "malformed line\n"
	got, err := extractIBMiScannerRecords(writeFixture(t, "scan.txt", []byte(file)))
	if err != nil {
		t.Fatalf("extractIBMiScannerRecords: %v", err)
	}
	want := user + ":" + record
	if len(got) != 1 || got[0] != want {
		t.Fatalf("\n got: %v\nwant: %s", got, want)
	}
	_, bare, _ := strings.Cut(got[0], ":")
	mustCrack(t, "as400-ssha1", bare, password)
}

// ── Mosquitto ────────────────────────────────────────────────────────────────

// The leading digit picks the scheme and the two schemes become DIFFERENT
// records, so it cannot be skipped over.
func TestExtractMosquitto(t *testing.T) {
	const password = "hunter2"
	const iterations = 101
	salt := []byte("sixteen-byte-sal")

	pbkdfKey := pbkdf2.Key([]byte(password), salt, iterations, 64, sha512.New)
	shaSum := sha512.Sum512(append([]byte(password), salt...))

	b64 := base64.StdEncoding.EncodeToString
	file := fmt.Sprintf("alice:$7$%d$%s$%s\n", iterations, b64(salt), b64(pbkdfKey)) +
		fmt.Sprintf("bob:$6$%s$%s\n", b64(salt), b64(shaSum[:])) +
		"# comment\ncarol:notahash\n"

	got, err := extractMosquittoRecords(writeFixture(t, "passwd", []byte(file)))
	if err != nil {
		t.Fatalf("extractMosquittoRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "alice:$pbkdf2-hmac-sha512$") {
		t.Fatalf("the $7$ line should become a PBKDF2 record: %s", got[0])
	}
	if !strings.HasPrefix(got[1], "bob:$dynamic_82$") {
		t.Fatalf("the $6$ line should become a salted SHA-512 record: %s", got[1])
	}
	// The file stores base64 and both records want hex, so this is what
	// catches a reader that copies the field across unchanged.
	_, pbkdfRecord, _ := strings.Cut(got[0], ":")
	_, shaRecord, _ := strings.Cut(got[1], ":")
	mustCrack(t, "netiq-pbkdf2", pbkdfRecord, password)
	mustCrack(t, "dynamic", shaRecord, password)
}

// ── PKCS#8, in John's spelling ───────────────────────────────────────────────

// openSSLKey builds an encrypted PKCS#8 key with the system's own openssl,
// which is the producer these records describe.
func openSSLKey(t *testing.T, args ...string) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed here, so no key can be produced by its own writer")
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.key")
	if out, err := exec.Command(bin, "genpkey", "-algorithm", "RSA",
		"-pkeyopt", "rsa_keygen_bits:1024", "-out", plain).CombinedOutput(); err != nil {
		t.Skipf("this openssl would not make a key: %v\n%s", err, out)
	}
	enc := filepath.Join(dir, "enc.key")
	full := append([]string{"pkcs8", "-topk8", "-in", plain, "-out", enc,
		"-passout", "pass:komodia"}, args...)
	if out, err := exec.Command(bin, full...).CombinedOutput(); err != nil {
		t.Skipf("this openssl refused %v: %v\n%s", args, err, out)
	}
	if _, err := os.Stat(enc); err != nil {
		t.Skip("openssl wrote no key")
	}
	return enc
}

func TestExtractPEMRoundTrip(t *testing.T) {
	// An eight-byte salt is what the $PEM$ record has room for, so this is
	// the shape it can describe.
	path := openSSLKey(t, "-v2", "des-ede3-cbc", "-v2prf", "hmacWithSHA1", "-saltlen", "8")

	got, err := extractPEMRecords(path)
	if err != nil {
		t.Fatalf("extractPEMRecords: %v", err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "$PEM$1$1$") {
		t.Fatalf("got %v, want one triple-DES $PEM$1 record", got)
	}
	if types := detectHashTypes(got[0]); !containsString(types, "pkcs8-pem-sha1") {
		t.Errorf("the record is not detected as a PEM key: %v", types)
	}
	mustCrack(t, "pkcs8-pem-sha1", got[0], "komodia")
}

// The $PEM$ record is narrower than the file it describes, and both narrowings
// are refused by name rather than papered over. A key from a current OpenSSL
// hits the salt one: the default is sixteen bytes and the record has room for
// eight, in John and in hashcat alike.
func TestExtractPEMRefusesWhatTheRecordCannotHold(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"a sixteen-byte salt", "use ssh2smith",
			[]string{"-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA1"}},
		{"a SHA-256 PRF", "no field for that",
			[]string{"-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-saltlen", "8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := openSSLKey(t, tc.args...)
			_, err := extractPEMRecords(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected a refusal naming the alternative, got %v", err)
			}
			// And the key really is readable the other way, which is
			// what makes the refusal a redirection rather than a
			// dead end.
			result, err := extractPKCS8Key(readFileForTest(t, path), path)
			if err != nil {
				t.Fatalf("ssh2smith's reader could not read it either: %v", err)
			}
			mustCrack(t, "pkcs8", result.hash, "komodia")
		})
	}
}

func readFileForTest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
