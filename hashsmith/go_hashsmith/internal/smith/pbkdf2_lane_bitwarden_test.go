package smith

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// bitwardenType0HashcatVector mirrors extract_bitwarden_test.go's own
// published encrypted-key record, password "openwall123".
const bitwardenType0HashcatVector = "$bitwarden$0*5000*lulu@mailinator.com*20d9c3c9daaed076026b6cb5887d3273*3bbcb4c7cec45d71c7238291573eb8a8a0f71e6191fb708b07f2cb43b26a56b533ba35a5906abdc08600baedb18fbc042a3b50f4549890210a254129b0ae749394c3c39b33ca183c605ee97b167329d3"

// bitwardenType2FourFieldVector mirrors selftest_vectors.go's own
// cross-checked record (hashIter implicit at 1), password "hashsmith".
const bitwardenType2FourFieldVector = "$bitwarden$2*100000*dXNlckBleGFtcGxlLmNvbQ==*1T7YrDYENfccHpf9+YnmLc1iQlw0SOoKPU7xefd1bRM="

// bitwardenType2FiveFieldVector mirrors hashcat's own mode 23400 example
// record (testdata/hashcat_example_hashes.tsv), which carries an explicit
// hashIter=2, password "hashcat".
const bitwardenType2FiveFieldVector = "$bitwarden$2*100000*2*bm9yZXBseUBoYXNoY2F0Lm5ldA==*+v5rHxYydSRUDlan+4pSoiYQwAgEhdmivlb+exQX+fg="

func TestPBKDF2BitwardenLaneHasherMatchesVectors(t *testing.T) {
	for _, tc := range []struct {
		target, password string
	}{
		{bitwardenType0HashcatVector, "openwall123"},
		{bitwardenType2FourFieldVector, "hashsmith"},
		{bitwardenType2FiveFieldVector, "hashcat"},
	} {
		h := newPBKDF2BitwardenLaneHasher(tc.target)
		if h == nil {
			t.Fatalf("newPBKDF2BitwardenLaneHasher refused %q", tc.target)
		}
		out := make([]bool, 1)
		h.Run([][]byte{[]byte(tc.password)}, out)
		if !out[0] {
			t.Fatalf("lane hasher did not match %q with the correct password", tc.target)
		}
		h.Run([][]byte{[]byte("wrong")}, out)
		if out[0] {
			t.Fatalf("lane hasher false-matched a wrong password against %q", tc.target)
		}
	}
}

func TestPBKDF2BitwardenLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	for _, tc := range []struct {
		name, target, right string
	}{
		{"type0", bitwardenType0HashcatVector, "openwall123"},
		{"type2-four-field", bitwardenType2FourFieldVector, "hashsmith"},
		{"type2-five-field", bitwardenType2FiveFieldVector, "hashcat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidates := []string{
				"wrong1", "wrong2", "", "a", "12345678", "wrong3",
				"wrong4", "wrong5", tc.right,
			}
			h := newPBKDF2BitwardenLaneHasher(tc.target)
			if h == nil {
				t.Fatal("newPBKDF2BitwardenLaneHasher refused the record")
			}
			for n := 1; n <= len(candidates); n++ {
				n := n
				t.Run(itoa(n), func(t *testing.T) {
					pw := make([][]byte, n)
					for i := 0; i < n; i++ {
						pw[i] = []byte(candidates[i])
					}
					out := make([]bool, n)
					h.Run(pw, out)
					for i := 0; i < n; i++ {
						want, err := verifyBitwarden(tc.target, candidates[i])
						if err != nil {
							t.Fatalf("verifyBitwarden(%q): %v", candidates[i], err)
						}
						if out[i] != want {
							t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
								n, candidates[i], i, out[i], want)
						}
					}
				})
			}
		})
	}
}

func TestPBKDF2BitwardenLaneHasherIsStateless(t *testing.T) {
	for _, tc := range []struct {
		name, target, right string
	}{
		{"type0", bitwardenType0HashcatVector, "openwall123"},
		{"type2", bitwardenType2FourFieldVector, "hashsmith"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPBKDF2BitwardenLaneHasher(tc.target)
			if h == nil {
				t.Fatal("newPBKDF2BitwardenLaneHasher refused the record")
			}

			full := make([][]byte, pbkdf2Sha256Lanes)
			for i := range full {
				full[i] = []byte(tc.right)
			}
			fullOut := make([]bool, pbkdf2Sha256Lanes)
			h.Run(full, fullOut)
			for i, ok := range fullOut {
				if !ok {
					t.Fatalf("full group lane %d: expected a match, got none", i)
				}
			}

			shortWrong := [][]byte{[]byte("nope"), []byte("still nope")}
			shortOut := make([]bool, len(shortWrong))
			h.Run(shortWrong, shortOut)
			for i, ok := range shortOut {
				if ok {
					t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
				}
			}
		})
	}
}

func TestNewPBKDF2BitwardenLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$bitwarden$1*100000*aa*bb",
		"$bitwarden$0*5000*lulu@mailinator.com*tooshort*00",
	}
	for _, c := range cases {
		if h := newPBKDF2BitwardenLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2BitwardenLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherBitwardenGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("bitwarden", bitwardenType2FourFieldVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"bitwarden\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"bitwarden\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"bitwarden\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}
}

// TestPBKDF2HMACSHA256DeriveBatchNPerLaneSaltMatchesReference checks the
// new per-lane-salt primitive directly against golang.org/x/crypto/pbkdf2,
// each of the 8 lanes given its OWN password and its OWN salt — the shape
// no shared-salt test in this codebase exercises — across dkLen values
// straddling one and two SHA-256 blocks, independent of Bitwarden or any
// other format that happens to use it.
func TestPBKDF2HMACSHA256DeriveBatchNPerLaneSaltMatchesReference(t *testing.T) {
	passwords := [pbkdf2Sha256Lanes]string{
		"", "a", "password", "correct horse battery staple",
		"12345678", "hashsmith", "the-right-password", "unicode-éè",
	}
	salts := [pbkdf2Sha256Lanes]string{
		"salt0", "s", "another-salt", "",
		"salt-four", "salt-five-longer-than-the-rest", "6", "salt7",
	}
	iter := 41
	for _, dkLen := range []int{32, 48, 64} {
		dkLen := dkLen
		t.Run(itoa(dkLen), func(t *testing.T) {
			var pwLanes, saltLanes [pbkdf2Sha256Lanes][]byte
			for i := range passwords {
				pwLanes[i] = []byte(passwords[i])
				saltLanes[i] = []byte(salts[i])
			}
			got := pbkdf2HMACSHA256DeriveBatchNPerLaneSalt(&pwLanes, &saltLanes, iter, dkLen)
			for i := range passwords {
				want := pbkdf2.Key([]byte(passwords[i]), []byte(salts[i]), iter, dkLen, sha256.New)
				if !bytes.Equal(got[i], want) {
					t.Errorf("lane %d (password %q, salt %q): got %x, want %x", i, passwords[i], salts[i], got[i], want)
				}
			}
		})
	}
}
