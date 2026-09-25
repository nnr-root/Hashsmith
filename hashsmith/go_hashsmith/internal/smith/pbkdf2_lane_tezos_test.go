package smith

import "testing"

// tezosCrosscheckedVector mirrors selftest_vectors.go's own crosschecked
// vector, passphrase "4FGU8MpuCo".
const tezosCrosscheckedVector = "$tezos$1*2048*put guide flat machine express cave hello connect stay local spike ski romance express brass*jbzbdybr.vpbdbxnn@tezos.example.org*tz1eTjPtwYjdcBMStwVdEcwY2YE3th1bXyMR*a19fce77caa0729c68072dc3eb274c7626a71880d926"

func TestPBKDF2TezosLaneHasherMatchesCrosscheckedVector(t *testing.T) {
	h := newPBKDF2TezosLaneHasher(tezosCrosscheckedVector)
	if h == nil {
		t.Fatal("newPBKDF2TezosLaneHasher refused the crosschecked record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("4FGU8MpuCo")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the crosschecked record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the crosschecked record")
	}
}

func TestPBKDF2TezosLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "4FGU8MpuCo"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2TezosLaneHasher(tezosCrosscheckedVector)
	if h == nil {
		t.Fatal("newPBKDF2TezosLaneHasher refused the crosschecked record")
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
				want, err := verifyTezos(tezosCrosscheckedVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyTezos(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2TezosLaneHasherIsStateless(t *testing.T) {
	right := "4FGU8MpuCo"
	h := newPBKDF2TezosLaneHasher(tezosCrosscheckedVector)
	if h == nil {
		t.Fatal("newPBKDF2TezosLaneHasher refused the crosschecked record")
	}

	full := make([][]byte, pbkdf2Sha512Lanes)
	for i := range full {
		full[i] = []byte(right)
	}
	fullOut := make([]bool, pbkdf2Sha512Lanes)
	h.Run(full, fullOut)
	for i, ok := range fullOut {
		if !ok {
			t.Fatalf("full group lane %d: expected a match, got none", i)
		}
	}

	shortWrong := [][]byte{[]byte("nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

func TestNewPBKDF2TezosLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$tezos$1*AA",
	}
	for _, c := range cases {
		if h := newPBKDF2TezosLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2TezosLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherTezosGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("tezos", tezosCrosscheckedVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"tezos\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"tezos\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"tezos\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("4FGU8MpuCo")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the crosschecked record")
	}
}
