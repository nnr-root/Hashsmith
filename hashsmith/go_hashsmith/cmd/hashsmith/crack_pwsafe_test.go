package main

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Stretched-key digest computed independently with Python's hashlib for the
// passphrase "hashsmith", salt 00..1f and 2048 iterations.
const pwsafeTestRecord = "$pwsafe$*3*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*2048*" +
	"6f2ad9b3cebdaa86a663f2a202b3d0b00e471ce104995ee07255e2d3edb31a37"

func TestPwsafeVector(t *testing.T) {
	if ok, err := verifyPwsafe(pwsafeTestRecord, "hashsmith"); err != nil || !ok {
		t.Errorf("verify failed: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyPwsafe(pwsafeTestRecord, "wrong"); bad {
		t.Error("accepted a wrong passphrase")
	}
	if got := detectHashTypes(pwsafeTestRecord); len(got) != 1 || got[0] != "pwsafe" {
		t.Errorf("detectHashTypes = %v, want [pwsafe]", got)
	}
	for _, typ := range []string{"pwsafe", "5200", "hashcat:5200"} {
		if ok, err := verifyCandidate("hashsmith", pwsafeTestRecord, typ, "", "prefix"); err != nil || !ok {
			t.Errorf("-t %s: ok=%v err=%v", typ, ok, err)
		}
	}
}

// The iteration count is part of the commitment, so a record claiming a
// different count must not verify.
func TestPwsafeHonoursIterationCount(t *testing.T) {
	p, err := parsePwsafeHash(pwsafeTestRecord)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pwsafeStretch("hashsmith", p.salt, p.iterations)) ==
		hex.EncodeToString(pwsafeStretch("hashsmith", p.salt, p.iterations+1)) {
		t.Error("an extra stretch iteration produced the same key")
	}
}

// pwsafe2smith must read the fixed-layout v3 header and reject anything else.
func TestPwsafeExtractor(t *testing.T) {
	dir := t.TempDir()

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	digest, _ := hex.DecodeString("6f2ad9b3cebdaa86a663f2a202b3d0b00e471ce104995ee07255e2d3edb31a37")
	header := append([]byte("PWS3"), salt...)
	header = binary.LittleEndian.AppendUint32(header, 2048)
	header = append(header, digest...)
	header = append(header, make([]byte, 32)...) // encrypted remainder, unused

	good := filepath.Join(dir, "good.psafe3")
	if err := os.WriteFile(good, header, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, info, err := extractPwsafeHash(good)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if hash != pwsafeTestRecord {
		t.Errorf("extracted\n %s\nwant\n %s", hash, pwsafeTestRecord)
	}
	if info == "" {
		t.Error("extractor reported no description")
	}

	bad := map[string][]byte{
		"wrong-tag": append([]byte("XXXX"), header[4:]...),
		"truncated": header[:40],
		"zero-iter": func() []byte {
			h := append([]byte(nil), header...)
			binary.LittleEndian.PutUint32(h[36:40], 0)
			return h
		}(),
	}
	for name, content := range bad {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := extractPwsafeHash(p); err == nil {
			t.Errorf("%s: extractor accepted a malformed database", name)
		}
	}
}

func TestPwsafeRejectsMalformedRecords(t *testing.T) {
	for _, bad := range []string{
		"$pwsafe$*2*00*2048*ab",                           // unsupported version
		"$pwsafe$*3*00*2048*ab",                           // salt too short
		"$pwsafe$*3*" + pwsafeTestRecord[11:75] + "*0*ab", // zero iterations
		"nonsense",
	} {
		if ok, err := verifyPwsafe(bad, "pw"); ok || err == nil {
			t.Errorf("verifyPwsafe(%q) = %v, %v; want a rejection", bad, ok, err)
		}
	}
}
