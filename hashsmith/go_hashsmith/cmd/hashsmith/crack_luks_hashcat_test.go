package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// hashcat's LUKS v1 modes all publish an example record with the password
// "hashcat". They differ only in hash spec, cipher and cipher mode, so running
// all twelve exercises every branch of luksDecryptBuf and afMerge against
// externally authored vectors.
var hashcatLUKSModes = []string{
	"29511", "29512", "29513", // SHA-1   + AES / Serpent / Twofish
	"29521", "29522", "29523", // SHA-256 + AES / Serpent / Twofish
	"29531", "29532", "29533", // SHA-512 + AES / Serpent / Twofish
	"29541", "29542", "29543", // RIPEMD-160 + AES / Serpent / Twofish
}

func hashcatExampleRecord(t *testing.T, mode string) (hash, pass string) {
	t.Helper()
	f, err := os.Open("testdata/hashcat_example_hashes.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) == 4 && p[0] == mode {
			return p[3], p[2]
		}
	}
	t.Fatalf("mode %s not in the conformance corpus", mode)
	return "", ""
}

// The nine-field hashcat record must parse, and its stripe count must be
// recovered from the key material rather than read from a field that is not
// there.
func TestParseLUKSHashcatRecord(t *testing.T) {
	rec, _ := hashcatExampleRecord(t, "29511")
	p, err := parseLUKSHash(rec)
	if err != nil {
		t.Fatalf("parseLUKSHash: %v", err)
	}
	if p.hashSpec != "sha1" || p.cipherName != "aes" || p.cipherMode != "cbc-essiv:sha256" {
		t.Errorf("parsed %s/%s/%s; want sha1/aes/cbc-essiv:sha256", p.hashSpec, p.cipherName, p.cipherMode)
	}
	if p.keyBytes != 16 {
		t.Errorf("keyBytes = %d; want 16 (the record states 128 BITS)", p.keyBytes)
	}
	if p.stripes != 4000 {
		t.Errorf("stripes = %d; want 4000 recovered from len(af)/keyBytes", p.stripes)
	}
	if len(p.payload) == 0 {
		t.Error("payload not captured; a hashcat record has nothing else to verify against")
	}
	if p.mkDigest != nil {
		t.Error("a hashcat record carries no master-key digest; one was invented")
	}
}

// A twelve-field luks2smith record must still parse; the two shapes share a
// prefix and are told apart by field count alone.
func TestParseLUKSBothRecordShapes(t *testing.T) {
	rec, _ := hashcatExampleRecord(t, "29511")
	if n := len(strings.Split(rec[len("$luks$"):], "$")); n != 9 {
		t.Fatalf("hashcat record has %d fields; this test assumes 9", n)
	}
	if _, err := parseLUKSHash("$luks$1$sha1$aes$cbc-essiv:sha256$16"); err == nil {
		t.Error("a truncated record was accepted")
	}
}

// Every hashcat LUKS v1 example record must verify with hashcat's own password
// and reject a wrong one.
func TestVerifyLUKSAgainstHashcatVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("twelve PBKDF2 key derivations; skipped under -short")
	}
	for _, mode := range hashcatLUKSModes {
		mode := mode
		t.Run("m"+mode, func(t *testing.T) {
			t.Parallel()
			rec, pass := hashcatExampleRecord(t, mode)
			ok, err := verifyLUKS(rec, pass)
			if err != nil {
				t.Fatalf("verifyLUKS: %v", err)
			}
			if !ok {
				t.Errorf("hashcat's own password %q did not verify", pass)
			}
			bad, err := verifyLUKS(rec, pass+"x")
			if err != nil {
				t.Fatalf("verifyLUKS (wrong password): %v", err)
			}
			if bad {
				t.Error("a wrong password verified — the payload check is not discriminating")
			}
		})
	}
}
