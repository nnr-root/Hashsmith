package smith

import "testing"

// ethereumPBKDF2Vector mirrors crack_ethereum_test.go's own go-ethereum
// PBKDF2 vector, passphrase "testpassword".
const ethereumPBKDF2Vector = "$ethereum$p*262144" +
	"*ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd" +
	"*5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46" +
	"*517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"

// ethereumScryptVector is the scrypt-variant sibling from the same test —
// used only to confirm the lane hasher correctly refuses it.
const ethereumScryptVector = "$ethereum$s*262144*1*8" +
	"*ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19" +
	"*d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c" +
	"*2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"

func TestPBKDF2EthereumLaneHasherMatchesGoEthereumVector(t *testing.T) {
	h := newPBKDF2EthereumLaneHasher(ethereumPBKDF2Vector)
	if h == nil {
		t.Fatal("newPBKDF2EthereumLaneHasher refused go-ethereum's own published PBKDF2 vector")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("testpassword")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match go-ethereum's own vector with the correct passphrase")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong passphrase against go-ethereum's vector")
	}
}

func TestPBKDF2EthereumLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2EthereumLaneHasher(ethereumPBKDF2Vector)
	if h == nil {
		t.Fatal("newPBKDF2EthereumLaneHasher refused go-ethereum's own published PBKDF2 vector")
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
				want, err := verifyEthereum(ethereumPBKDF2Vector, candidates[i])
				if err != nil {
					t.Fatalf("verifyEthereum(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2EthereumLaneHasherIsStateless(t *testing.T) {
	right := "testpassword"
	h := newPBKDF2EthereumLaneHasher(ethereumPBKDF2Vector)
	if h == nil {
		t.Fatal("newPBKDF2EthereumLaneHasher refused go-ethereum's own published PBKDF2 vector")
	}

	full := make([][]byte, pbkdf2Sha256Lanes)
	for i := range full {
		full[i] = []byte(right)
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

func TestNewPBKDF2EthereumLaneHasherRefusesScryptAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		ethereumScryptVector,
		"$ethereum$p*not-a-number*aa*bb*cc",
	}
	for _, c := range cases {
		if h := newPBKDF2EthereumLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2EthereumLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherEthereumGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("ethereum", ethereumPBKDF2Vector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"ethereum\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"ethereum\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"ethereum\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("testpassword")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match go-ethereum's own PBKDF2 vector")
	}

	// A scrypt record must fall back to the scalar path, not be silently
	// accepted by an eligible PBKDF2 hasher.
	if _, _, ok := newLaneHasher("ethereum", ethereumScryptVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"ethereum\", ...) accepted a scrypt-variant record")
	}
}
