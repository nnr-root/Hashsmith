package smith

import "testing"

// lastpassLPVector and lastpassCLIVector mirror selftest_vectors.go's own
// cross-checked vectors.
const (
	lastpassLPVector  = "$lp$hackme@mailinator.com$6f5d8cec3615fc9ac7ba2e0569bce4f5"
	lastpassLPPass    = "strongpassword"
	lastpassCLIVector = "$lpcli$0$lulu@mailinator.com$1234$3fec6cd2d8c049cbafe9fa6a9343f42f$f21d8e60ad22db53033e431700fb5e0c"
	lastpassCLIPass   = "Badpassword098765"
)

func TestPBKDF2LastpassLPLaneHasherMatchesCrosscheckedVector(t *testing.T) {
	h := newPBKDF2LastpassLPLaneHasher(lastpassLPVector)
	if h == nil {
		t.Fatal("newPBKDF2LastpassLPLaneHasher refused the cross-checked published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte(lastpassLPPass)}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the cross-checked LP record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the cross-checked LP record")
	}
}

func TestPBKDF2LastpassCLILaneHasherMatchesCrosscheckedVector(t *testing.T) {
	h := newPBKDF2LastpassCLILaneHasher(lastpassCLIVector)
	if h == nil {
		t.Fatal("newPBKDF2LastpassCLILaneHasher refused the cross-checked published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte(lastpassCLIPass)}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the cross-checked CLI record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the cross-checked CLI record")
	}
}

func TestPBKDF2LastpassLaneHashersMatchScalarAcrossBatchSizes(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		right   string
		newHash func(string) laneHasher
		verify  func(target, candidate string) (bool, error)
	}{
		{"lp", lastpassLPVector, lastpassLPPass, func(t string) laneHasher {
			if h := newPBKDF2LastpassLPLaneHasher(t); h != nil {
				return h
			}
			return nil
		}, verifyLastPassLP},
		{"cli", lastpassCLIVector, lastpassCLIPass, func(t string) laneHasher {
			if h := newPBKDF2LastpassCLILaneHasher(t); h != nil {
				return h
			}
			return nil
		}, verifyLastPassCLI},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			candidates := []string{
				"wrong1", "wrong2", "", "a", "12345678", "wrong3",
				"wrong4", "wrong5", c.right,
			}
			h := c.newHash(c.target)
			if h == nil {
				t.Fatal("lane hasher refused the cross-checked published record")
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
						want, err := c.verify(c.target, candidates[i])
						if err != nil {
							t.Fatalf("verify(%q): %v", candidates[i], err)
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

func TestPBKDF2LastpassLaneHashersAreStateless(t *testing.T) {
	full := make([][]byte, pbkdf2Sha256Lanes)
	for i := range full {
		full[i] = []byte(lastpassLPPass)
	}
	h := newPBKDF2LastpassLPLaneHasher(lastpassLPVector)
	if h == nil {
		t.Fatal("newPBKDF2LastpassLPLaneHasher refused the cross-checked published record")
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
}

func TestNewPBKDF2LastpassLaneHashersRefuseMalformedRecords(t *testing.T) {
	lpCases := []string{"", "not a record", "$lp$"}
	for _, c := range lpCases {
		if h := newPBKDF2LastpassLPLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2LastpassLPLaneHasher(%q) should have been refused", c)
		}
	}
	cliCases := []string{"", "not a record", "$lpcli$0$too$few"}
	for _, c := range cliCases {
		if h := newPBKDF2LastpassCLILaneHasher(c); h != nil {
			t.Errorf("newPBKDF2LastpassCLILaneHasher(%q) should have been refused", c)
		}
	}
}

// TestNewPBKDF2LastpassCLILaneHasherRefusesIterationsOne confirms the
// iterations==1 special case (plain SHA-256, not PBKDF2 — see
// verifyLastPassCLI's own comment) falls back to the scalar path rather
// than being silently mishandled by the batched PBKDF2 primitive.
func TestNewPBKDF2LastpassCLILaneHasherRefusesIterationsOne(t *testing.T) {
	target := "$lpcli$0$someone@example.com$1$00000000000000000000000000000000$00000000000000000000000000000000"
	if h := newPBKDF2LastpassCLILaneHasher(target); h != nil {
		t.Fatal("newPBKDF2LastpassCLILaneHasher accepted an iterations==1 record (not PBKDF2)")
	}
}

func TestNewLaneHasherLastpassGatesAreInternallyConsistent(t *testing.T) {
	for _, c := range []struct {
		typ    string
		target string
		right  string
	}{
		{"lastpass-lp", lastpassLPVector, lastpassLPPass},
		{"lastpass-cli", lastpassCLIVector, lastpassCLIPass},
	} {
		t.Run(c.typ, func(t *testing.T) {
			factory, lanes, ok := newLaneHasher(c.typ, c.target, "", "")
			wantOK := pbkdf2Sha256AVX2Eligible()
			if ok != wantOK {
				t.Fatalf("newLaneHasher(%q, ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", c.typ, ok, wantOK)
			}
			if !ok {
				t.Skip("not eligible on this hardware/build — nothing further to check")
			}
			if lanes != pbkdf2Sha256Lanes {
				t.Fatalf("newLaneHasher(%q, ...) lanes = %d, want %d", c.typ, lanes, pbkdf2Sha256Lanes)
			}
			h := factory()
			if h == nil {
				t.Fatal("factory returned nil despite reporting eligible")
			}
			out := make([]bool, 1)
			h.Run([][]byte{[]byte(c.right)}, out)
			if !out[0] {
				t.Fatal("the wired-up hasher did not match the cross-checked record")
			}
		})
	}
}
