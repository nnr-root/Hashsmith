package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

const (
	pkcs12TestSalt = "005070587dcdb26f1bf120f0e0889794"
	pkcs12TestData = "3082098e308203fa06092a864886f70d010706"
	pkcs12TestPass = "hashsmith"
)

// MACs computed independently with Python's hashlib/hmac, following RFC 7292
// appendix B.2.  The same Python routine reproduces the MAC of a real
// OpenSSL-generated .pfx byte for byte, so it is a genuine oracle rather than a
// restatement of this implementation.
func TestPKCS12MACVectors(t *testing.T) {
	cases := []struct {
		algorithm  string
		iterations int
		mac        string
	}{
		{"sha256", 2048, "d0e94137693baa9ad0ea6c8fb1938969a220d8186f03e43c3021ea3e38884725"},
		{"sha1", 2048, "930ba72f5f6cfe1982771f3ac4f31cc2c3038319"},
		{"sha512", 1024, "ba0414a84b161316f21671fa93be956dc646db9dee76dc1d7ee94eb87bfaf0e173ece71932458f26a530a5a54e950af4a61aa5570910915f3273eade871ffb25"},
	}
	for _, c := range cases {
		record := fmt.Sprintf("$pfx$*%s*%d*%s*%s*%s",
			c.algorithm, c.iterations, pkcs12TestSalt, c.mac, pkcs12TestData)
		if ok, err := verifyPKCS12(record, pkcs12TestPass); err != nil || !ok {
			t.Errorf("%s: verify failed: ok=%v err=%v", c.algorithm, ok, err)
		}
		if bad, _ := verifyPKCS12(record, "wrong"); bad {
			t.Errorf("%s: accepted a wrong password", c.algorithm)
		}
		if !isPKCS12(record) {
			t.Errorf("%s: isPKCS12 rejected a well-formed record", c.algorithm)
		}
		if got := detectHashTypes(record); len(got) != 1 || got[0] != "pfx" {
			t.Errorf("%s: detectHashTypes = %v, want [pfx]", c.algorithm, got)
		}
		if ok, err := verifyCandidate(pkcs12TestPass, record, "pfx", "", "prefix"); err != nil || !ok {
			t.Errorf("%s: verifyCandidate failed: ok=%v err=%v", c.algorithm, ok, err)
		}
	}
}

// The derivation ID selects between the encryption key, the IV and the MAC key.
// Pinning two of them keeps the id parameter from silently going unused.
func TestPKCS12KDFDerivationIDs(t *testing.T) {
	salt, _ := hex.DecodeString(pkcs12TestSalt)
	cases := []struct {
		id, size int
		want     string
	}{
		{pkcs12IDKey, 32, "b4ddb8491c3dc869d91a48f79dc1d6cfe1b9a8f96607cd4e66fe9ce4bf47e91b"},
		{pkcs12IDIV, 16, "b4aeabacb4300103fbfdfdaa325c3f39"},
	}
	for _, c := range cases {
		got := pkcs12KDF(pkcs12TestPass, salt, 2048, c.id, c.size, sha256.New)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("id %d: got %x, want %s", c.id, got, c.want)
		}
	}
}

// The salt and password are repeated to a whole number of hash blocks; a
// zero-padding implementation passes short inputs and fails long ones, so both
// sides of the block boundary are exercised.
func TestPKCS12KDFFillRepeatsRatherThanPads(t *testing.T) {
	for _, n := range []int{1, 8, 63, 64, 65, 127, 128} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i + 1)
		}
		got := pkcs12Fill(b, 64)
		if len(got)%64 != 0 || len(got) < n {
			t.Fatalf("fill(%d) produced %d bytes", n, len(got))
		}
		for i := range got {
			if got[i] != b[i%n] {
				t.Fatalf("fill(%d) byte %d = %d, want %d (must repeat, not pad)", n, i, got[i], b[i%n])
			}
		}
	}
	if pkcs12Fill(nil, 64) != nil {
		t.Error("fill of an empty input should stay empty")
	}
}

// PKCS#12 passwords are BMPStrings: UTF-16BE plus a null terminator.
func TestPKCS12BMPString(t *testing.T) {
	for in_, want := range map[string]string{
		"":       "0000",
		"a":      "00610000",
		"ab":     "006100620000",
		"\u00e9": "00e90000", // non-ASCII must stay big-endian
	} {
		if got := hex.EncodeToString(pkcs12BMPString(in_)); got != want {
			t.Errorf("BMPString(%q) = %s, want %s", in_, got, want)
		}
	}
}

func TestPKCS12RejectsMalformedRecords(t *testing.T) {
	good := fmt.Sprintf("$pfx$*sha256*2048*%s*d0e94137693baa9ad0ea6c8fb1938969a220d8186f03e43c3021ea3e38884725*%s",
		pkcs12TestSalt, pkcs12TestData)
	bad := []string{
		"not a pfx record",
		"$pfx$*md5*2048*aabb*ccdd*eeff",        // unsupported digest
		"$pfx$*sha256*0*aabb*ccdd*eeff",        // zero iterations
		"$pfx$*sha256*2048**ccdd*eeff",         // empty salt
		"$pfx$*sha256*2048*zzzz*ccdd*eeff",     // salt not hex
		"$pfx$*sha256*2048*aabb*ccdd*eeff",     // MAC length wrong for sha256
		good[:len(good)-len(pkcs12TestData)-1], // missing the data field
	}
	for _, b := range bad {
		if ok, err := verifyPKCS12(b, "pw"); ok || err == nil {
			t.Errorf("verifyPKCS12(%q) = %v, %v; want a rejection", b, ok, err)
		}
	}
	if ok, err := verifyPKCS12(good, pkcs12TestPass); err != nil || !ok {
		t.Fatalf("the control record should still verify: ok=%v err=%v", ok, err)
	}
}
