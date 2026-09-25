package smith

import "testing"

// mongoDBSCRAM256ClientKeyVector and mongoDBSCRAM256ServerKeyVector mirror
// crack_mongodb_test.go's own vectors, passphrase "123hashcat" — version 1
// (Client Key, SHA-256-wrapped) and version 2 (Server Key, unwrapped).
const (
	mongoDBSCRAM256ClientKeyVector = "$mongodb-scram$1$hashcat$15000$Wfq3vMoqSEAwCyLsQF/hk5C5cB0aLtWS9FHeuw==$OUYBeh+/fypyyQaXfFg1Yvi8+qSXl+I1CHioOrdgtJw="
	mongoDBSCRAM256ServerKeyVector = "$mongodb-scram$2$hashcat$15000$Wfq3vMoqSEAwCyLsQF/hk5C5cB0aLtWS9FHeuw==$KSsV1BssuAHZMF4l6ziZ/5LGjA/qsCBcf++HroqpGNY="
)

// mongoDBSCRAM256HashcatDialectVector mirrors hashcat's own mode 24200
// example record (testdata/hashcat_example_hashes.tsv): version 1 in the
// '*'-separated dialect, which parseMongoDBSCRAM256 remaps to the
// ServerKey shape, password "hashcat".
const mongoDBSCRAM256HashcatDialectVector = "$mongodb-scram$*1*dXNlcg==*15000*qYaA1K1ZZSSpWfY+yqShlcTn0XVcrNipxiYCLQ==*QWVry9aTS/JW+y5CWCBr8lcEH9Kr/D4je60ncooPer8="

// mongoDBSCRAM1Vector is the SHA-1 sibling — used only to confirm the lane
// hasher correctly refuses it.
const mongoDBSCRAM1Vector = "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM="

func TestPBKDF2MongoDBSCRAM256LaneHasherMatchesVectors(t *testing.T) {
	for _, target := range []string{
		mongoDBSCRAM256ClientKeyVector, mongoDBSCRAM256ServerKeyVector,
	} {
		h := newPBKDF2MongoDBSCRAM256LaneHasher(target)
		if h == nil {
			t.Fatalf("newPBKDF2MongoDBSCRAM256LaneHasher refused %q", target)
		}
		out := make([]bool, 1)
		h.Run([][]byte{[]byte("123hashcat")}, out)
		if !out[0] {
			t.Fatalf("lane hasher did not match %q with the correct password", target)
		}
		h.Run([][]byte{[]byte("wrong")}, out)
		if out[0] {
			t.Fatalf("lane hasher false-matched a wrong password against %q", target)
		}
	}
}

func TestPBKDF2MongoDBSCRAM256LaneHasherMatchesHashcatDialectVector(t *testing.T) {
	h := newPBKDF2MongoDBSCRAM256LaneHasher(mongoDBSCRAM256HashcatDialectVector)
	if h == nil {
		t.Fatal("newPBKDF2MongoDBSCRAM256LaneHasher refused hashcat's own published dialect record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match hashcat's own published dialect record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against hashcat's own published dialect record")
	}
}

// TestPBKDF2MongoDBSCRAM256LaneHasherHandlesSASLprepEquivalence checks that
// two candidates SASLprep folds to the same string (RFC 4013 maps the soft
// hyphen U+00AD away) both match, mirroring
// TestMongoDBSCRAMSHA256SASLprep's own scalar check.
func TestPBKDF2MongoDBSCRAM256LaneHasherHandlesSASLprepEquivalence(t *testing.T) {
	target := "$mongodb-scram$1$IX$4096$c2FsdHNhbHQ=$9Z0EoeLxUdxgC/gc+oQWy0nrlhFRRqlula1RZqLyxcU="
	h := newPBKDF2MongoDBSCRAM256LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2MongoDBSCRAM256LaneHasher refused the SASLprep vector")
	}
	for _, password := range []string{"IX", "I­X"} {
		out := make([]bool, 1)
		h.Run([][]byte{[]byte(password)}, out)
		if !out[0] {
			t.Errorf("SASLprep candidate %q did not match", password)
		}
	}
}

func TestPBKDF2MongoDBSCRAM256LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	// Includes a soft hyphen and a lone surrogate-adjacent codepoint to
	// exercise both the SASLprep-succeeds and SASLprep-rejects paths
	// alongside ordinary wrong candidates.
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong­5", right,
	}
	for _, target := range []string{mongoDBSCRAM256ClientKeyVector, mongoDBSCRAM256ServerKeyVector} {
		t.Run(target[len(target)-8:], func(t *testing.T) {
			h := newPBKDF2MongoDBSCRAM256LaneHasher(target)
			if h == nil {
				t.Fatal("newPBKDF2MongoDBSCRAM256LaneHasher refused the record")
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
						want, err := verifyMongoDB(target, candidates[i])
						if err != nil {
							want = false
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

func TestPBKDF2MongoDBSCRAM256LaneHasherIsStateless(t *testing.T) {
	right := "123hashcat"
	h := newPBKDF2MongoDBSCRAM256LaneHasher(mongoDBSCRAM256ClientKeyVector)
	if h == nil {
		t.Fatal("newPBKDF2MongoDBSCRAM256LaneHasher refused the record")
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

func TestNewPBKDF2MongoDBSCRAM256LaneHasherRefusesSHA1AndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		mongoDBSCRAM1Vector,
		"$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=", // hashcat SHA-1 dialect
		"$mongodb-scram$1$hashcat$too$few$fields",
	}
	for _, c := range cases {
		if h := newPBKDF2MongoDBSCRAM256LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2MongoDBSCRAM256LaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherMongoDBGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("mongodb", mongoDBSCRAM256ClientKeyVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"mongodb\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"mongodb\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"mongodb\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("123hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}

	// The SHA-1 shape must fall back to the scalar path.
	if _, _, ok := newLaneHasher("mongodb", mongoDBSCRAM1Vector, "", ""); ok {
		t.Fatal("newLaneHasher(\"mongodb\", ...) accepted a SCRAM-SHA-1 record")
	}
}
