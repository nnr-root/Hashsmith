package smith

import "testing"

// geliHashcatVector mirrors selftest_vectors.go's own cross-checked
// vector, passphrase "openwall12345".
const geliHashcatVector = "$geli$0$7$22$128$0$1$256$31700bceaad80bc02f27644572288e765bd9356528f2a0eeef8144d8c1381a0da7ab32ec2570b254e57218924defaa0e233a55de818d8e97ae8c28cb85bc2842$a55f6782b63a048a3c39fec977e98c6387d6c64cf5be427cd450ecd9f5294834754f058edf3b62f64f3ba7b07ac1d769df17dcd6464330970e55f5c580885cde2d7bd544cd7946e3f9a47f3643f03687504f38ed7745024fd5039043e41a9f57cd238787c8dea0c32be72e82e6a20d3094a7a524d2cf36cc47b71bc663782e7891db3fb5c68ec4c29ac7cb19b2f9b157f69faceec4ed858b46d916a370f2b2c7fd5fb15bb45c72bd6da02de37094c59758ab9e3980f6f82ce178c5e050fd1737bf8bf8c00116d055e273b3ea7fa93aa96baade62815ca1e99639909059b5f09c34ddd7052b6a1384fc5908265dbda25c63efa473146674e39b765e1dcb4f85f6dea081f84f95b97897e1634e44120967808b2377f417befded2d4366c7ba1de28f973fb01d5627817b53a43f214ae82b1db1c3a5424fb8ae43118eb8446bc16d1f8f829ecd6165a4ad87ff715033a0d16ea8898c11705c06564012fb1e0bf4599989e65d203158e519b17fbff2df2ccc3455bbf29bdce8cae5b9399822243416"

func TestPBKDF2GELILaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2GELILaneHasher(geliHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2GELILaneHasher refused the published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("openwall12345")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the published record")
	}
}

func TestPBKDF2GELILaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2GELILaneHasher(geliHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2GELILaneHasher refused the published record")
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
				want, err := verifyGELI(geliHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyGELI(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2GELILaneHasherIsStateless(t *testing.T) {
	right := "openwall12345"
	h := newPBKDF2GELILaneHasher(geliHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2GELILaneHasher refused the published record")
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

func TestNewPBKDF2GELILaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$geli$0$7$22$128$0$1$256$00",
	}
	for _, c := range cases {
		if h := newPBKDF2GELILaneHasher(c); h != nil {
			t.Errorf("newPBKDF2GELILaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherGELIGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("geli", geliHashcatVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"geli\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"geli\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"geli\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("openwall12345")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}
}
