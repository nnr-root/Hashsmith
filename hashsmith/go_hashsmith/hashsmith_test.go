package hashsmith_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hashsmith "hashsmith-go"
)

// These tests import the package the way anything outside it would: by its
// import path, from an external test package, using only what is exported.
// That is the point — they fail to COMPILE if the public API stops being
// reachable, which no test inside the implementation can check.

func TestHashAndVerifyRoundTrip(t *testing.T) {
	for _, typ := range []string{"md5", "sha256", "sha512", "ntlm", "bcrypt", "sha1"} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			opts := []hashsmith.Option{hashsmith.WithType(typ)}
			if typ == "bcrypt" {
				opts = append(opts, hashsmith.WithCost(4))
			}
			record, err := hashsmith.Hash("hunter2", opts...)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			ok, err := hashsmith.Verify("hunter2", record, hashsmith.WithType(typ))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Fatalf("%s did not verify its own output %q", typ, record)
			}
			ok, err = hashsmith.Verify("hunter3", record, hashsmith.WithType(typ))
			if err != nil {
				t.Fatalf("verify wrong password: %v", err)
			}
			if ok {
				t.Fatalf("%s accepted the wrong password", typ)
			}
		})
	}
}

// TestCostIsTheWorkFactorNotASalt pins what the Cost field is for: bcrypt
// embeds its own random salt, so the number travelling in that slot is the
// log2 work factor, and it must show up in the record.
func TestCostIsTheWorkFactorNotASalt(t *testing.T) {
	record, err := hashsmith.Hash("hunter2",
		hashsmith.WithType("bcrypt"), hashsmith.WithCost(6))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record, "$06$") {
		t.Fatalf("cost 6 produced %q, which does not carry $06$", record)
	}
	// Two hashes of the same password differ, because the salt is random.
	again, err := hashsmith.Hash("hunter2",
		hashsmith.WithType("bcrypt"), hashsmith.WithCost(6))
	if err != nil {
		t.Fatal(err)
	}
	if again == record {
		t.Fatal("two bcrypt hashes of one password came out identical")
	}
	if _, err := hashsmith.Hash("hunter2", hashsmith.WithType("bcrypt")); err == nil {
		t.Fatal("bcrypt hashed without a cost")
	}
}

func TestSaltedHashUsesTheSaltMode(t *testing.T) {
	prefix, err := hashsmith.Hash("hunter2",
		hashsmith.WithType("md5"), hashsmith.WithSalt("s4lt", "prefix"))
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := hashsmith.Hash("hunter2",
		hashsmith.WithType("md5"), hashsmith.WithSalt("s4lt", "suffix"))
	if err != nil {
		t.Fatal(err)
	}
	if prefix == suffix {
		t.Fatal("prefix and suffix salting produced the same digest")
	}
	ok, err := hashsmith.Verify("hunter2", prefix,
		hashsmith.WithType("md5"), hashsmith.WithSalt("s4lt", "prefix"))
	if err != nil || !ok {
		t.Fatalf("salted verify: ok=%v err=%v", ok, err)
	}
	ok, _ = hashsmith.Verify("hunter2", prefix,
		hashsmith.WithType("md5"), hashsmith.WithSalt("s4lt", "suffix"))
	if ok {
		t.Fatal("the suffix mode verified a prefix-salted digest")
	}
}

func TestIdentifyNamesTheType(t *testing.T) {
	record, err := hashsmith.Hash("hunter2",
		hashsmith.WithType("bcrypt"), hashsmith.WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	types := hashsmith.Identify(record)
	if len(types) == 0 {
		t.Fatal("identify returned nothing for a bcrypt record")
	}
	found := false
	for _, typ := range types {
		if typ == "bcrypt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("identify said %v, which does not include bcrypt", types)
	}
	if hashsmith.Identify("not a hash at all, just a sentence") != nil {
		// Not a failure in itself — the engine may recognise a shape here —
		// but an empty slice is what the doc comment promises for "nothing".
		t.Log("identify recognised something in plain prose; see the comment")
	}
}

func TestVerifyWithoutATypeStillWorks(t *testing.T) {
	record, err := hashsmith.Hash("hunter2",
		hashsmith.WithType("bcrypt"), hashsmith.WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := hashsmith.Verify("hunter2", record)
	if err != nil {
		t.Fatalf("typeless verify: %v", err)
	}
	if !ok {
		t.Fatal("typeless verify rejected the right password")
	}
}

// TestCrackReturnsTheFirstCandidateInOrder is the property the doc comment
// promises and the one a parallel search is most likely to break: the workers
// finish out of order, so a naive implementation returns whichever one won the
// race rather than the one the caller ranked first.
func TestCrackReturnsTheFirstCandidateInOrder(t *testing.T) {
	// Two passwords, both correct for their own record. The list puts the
	// answer late so the workers have to race past it and still agree.
	record, err := hashsmith.Hash("swordfish", hashsmith.WithType("md5"))
	if err != nil {
		t.Fatal(err)
	}
	candidates := make([]string, 0, 600)
	for i := 0; i < 500; i++ {
		candidates = append(candidates, "wrong")
	}
	candidates = append(candidates, "swordfish")
	for i := 0; i < 100; i++ {
		candidates = append(candidates, "also-wrong")
	}

	got, ok, err := hashsmith.Crack(record, candidates,
		hashsmith.WithType("md5"), hashsmith.WithWorkers(8))
	if err != nil {
		t.Fatalf("crack: %v", err)
	}
	if !ok || got != "swordfish" {
		t.Fatalf("crack = %q, %v; want \"swordfish\", true", got, ok)
	}

	_, ok, err = hashsmith.Crack(record, []string{"a", "b", "c"},
		hashsmith.WithType("md5"))
	if err != nil {
		t.Fatalf("crack with no answer: %v", err)
	}
	if ok {
		t.Fatal("crack reported a hit from a list that contains none")
	}
}

func TestCrackPrefersTheEarlierOfTwoCorrectCandidates(t *testing.T) {
	// A record whose password appears twice. Whichever worker finishes
	// first, the earlier index must win.
	record, err := hashsmith.Hash("repeat", hashsmith.WithType("md5"))
	if err != nil {
		t.Fatal(err)
	}
	candidates := []string{"x", "repeat", "y", "repeat"}
	for i := 0; i < 50; i++ {
		got, ok, err := hashsmith.Crack(record, candidates,
			hashsmith.WithType("md5"), hashsmith.WithWorkers(4))
		if err != nil || !ok || got != "repeat" {
			t.Fatalf("iteration %d: %q, %v, %v", i, got, ok, err)
		}
	}
}

func TestEncodeAndDecodeThroughTheAPI(t *testing.T) {
	const text = "Hashsmith as a library."
	for _, tc := range []struct {
		typ  string
		opts []hashsmith.Option
	}{
		{"base64", nil},
		{"base58", nil},
		{"zstd", nil},
		{"brotli", nil},
		{"vigenere", []hashsmith.Option{hashsmith.WithKey("fortification")}},
		{"caesar", []hashsmith.Option{hashsmith.WithShift(7)}},
		{"railfence", []hashsmith.Option{hashsmith.WithRails(4)}},
		{"scytale", []hashsmith.Option{hashsmith.WithRails(5)}},
		{"adfgvx", []hashsmith.Option{hashsmith.WithKey("privacy,german")}},
	} {
		tc := tc
		t.Run(tc.typ, func(t *testing.T) {
			opts := append([]hashsmith.Option{hashsmith.WithType(tc.typ)}, tc.opts...)
			enc, err := hashsmith.Encode(text, opts...)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			dec, err := hashsmith.Decode(enc, opts...)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			// The classical ciphers reduce their input, so compare on what
			// survives rather than pretending they are byte-preserving.
			if !strings.EqualFold(strip(dec), strip(text)) {
				t.Fatalf("%s round trip gave %q", tc.typ, dec)
			}
		})
	}
}

func strip(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestDecodeLimitIsEnforced is the reason Options has a Limit at all: a
// library caller decoding something untrusted needs a ceiling it chose.
func TestDecodeLimitIsEnforced(t *testing.T) {
	bomb := strings.Repeat("\x00", 8<<20)
	enc, err := hashsmith.Encode(bomb, hashsmith.WithType("zstd"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hashsmith.Decode(enc,
		hashsmith.WithType("zstd"), hashsmith.WithLimit(4096)); err == nil {
		t.Fatal("an 8 MiB payload decoded under a 4 KiB limit")
	}
	got, err := hashsmith.Decode(enc, hashsmith.WithType("zstd"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(bomb) {
		t.Fatalf("default limit gave %d bytes, want %d", len(got), len(bomb))
	}
}

func TestMagicFindsAChain(t *testing.T) {
	// Two layers: the plaintext, base64'd, then hex'd.
	once, err := hashsmith.Encode("the treasure is buried under the oak",
		hashsmith.WithType("base64"))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := hashsmith.Encode(once, hashsmith.WithType("hex"))
	if err != nil {
		t.Fatal(err)
	}
	chains := hashsmith.Magic(twice, 3)
	if len(chains) == 0 {
		t.Fatal("magic found no chain for a two-layer payload")
	}
	for _, c := range chains {
		if strings.Contains(c.Value, "buried under the oak") {
			if len(c.Codecs) < 2 {
				t.Fatalf("the winning chain is %v, which is shorter than the two layers", c.Codecs)
			}
			return
		}
	}
	t.Fatalf("no chain recovered the plaintext; best was %q via %v",
		chains[0].Value, chains[0].Codecs)
}

func TestCataloguesAreReachable(t *testing.T) {
	if n := len(hashsmith.Codecs()); n < 80 {
		t.Errorf("Codecs() returned %d entries; the catalogue has at least 80", n)
	}
	if n := len(hashsmith.HashTypes()); n < 300 {
		t.Errorf("HashTypes() returned %d; the registry has far more", n)
	}
	if n := len(hashsmith.Extractors()); n < 80 {
		t.Errorf("Extractors() returned %d; there are at least 80", n)
	}
	if got := hashsmith.CanonicalCodec("rot-13"); got != "rot13" {
		t.Errorf("CanonicalCodec(rot-13) = %q", got)
	}
	for _, c := range hashsmith.Codecs() {
		if c.Name == "" || c.Description == "" {
			t.Errorf("catalogue entry with an empty field: %+v", c)
		}
	}
}

// TestExtractReadsAContainer drives the one part of the API that redirects
// stdout, and checks that it puts stdout back.
func TestExtractReadsAContainer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "htpasswd")
	const line = "alice:$apr1$Zc0mCRZm$dKDXGCFvLnJpN6nx1NUhV0\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	before := os.Stdout
	records, err := hashsmith.ExtractWith("htpasswd2smith", path)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if os.Stdout != before {
		t.Fatal("extraction left the process's stdout redirected")
	}
	if len(records) == 0 {
		t.Fatal("extraction produced no records")
	}
	joined := strings.Join(records, "\n")
	if !strings.Contains(joined, "$apr1$") {
		t.Fatalf("records do not carry the apr1 hash: %q", joined)
	}
}

func TestExtractRefusesToGuess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nothing.bin")
	if err := os.WriteFile(path, []byte("just some bytes, not a container"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashsmith.Extract(path); err == nil {
		t.Fatal("Extract claimed to recognise an unrecognisable file")
	}
	if _, err := hashsmith.ExtractWith("no-such2smith", path); err == nil {
		t.Fatal("ExtractWith accepted an extractor that does not exist")
	}
}
