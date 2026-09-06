package bcryptlane

import (
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestEncryptBlockLanesMatchSerial isolates the cipher-level lane code from the
// Hasher plumbing: it compares encryptBlock2/encryptBlock4 directly against N
// independent encryptBlock calls, so a cipher-level failure and a plumbing
// failure cannot look the same.
func TestEncryptBlockLanesMatchSerial(t *testing.T) {
	mk := func(key string) *state {
		c := &state{}
		initState(c)
		expandKey([]byte(key), c)
		return c
	}
	c0, c1 := mk("alpha\x00"), mk("bravo\x00")
	w0, x0 := encryptBlock(0x01234567, 0x89abcdef, c0)
	w1, x1 := encryptBlock(0xdeadbeef, 0x0badf00d, c1)
	g0, h0, g1, h1 := encryptBlock2(0x01234567, 0x89abcdef, 0xdeadbeef, 0x0badf00d, c0, c1)
	if g0 != w0 || h0 != x0 || g1 != w1 || h1 != x1 {
		t.Errorf("encryptBlock2 diverged: got (%08x %08x)(%08x %08x) want (%08x %08x)(%08x %08x)",
			g0, h0, g1, h1, w0, x0, w1, x1)
	}

	cs := []*state{mk("a\x00"), mk("bb\x00"), mk("ccc\x00"), mk("dddd\x00")}
	ls := []uint32{1, 2, 3, 4}
	rs := []uint32{5, 6, 7, 8}
	var wantL, wantR [4]uint32
	for i := range cs {
		wantL[i], wantR[i] = encryptBlock(ls[i], rs[i], cs[i])
	}
	a0, b0, a1, b1, a2, b2, a3, b3 := encryptBlock4(
		ls[0], rs[0], ls[1], rs[1], ls[2], rs[2], ls[3], rs[3], cs[0], cs[1], cs[2], cs[3])
	got := [8]uint32{a0, b0, a1, b1, a2, b2, a3, b3}
	for i := 0; i < 4; i++ {
		if got[i*2] != wantL[i] || got[i*2+1] != wantR[i] {
			t.Errorf("encryptBlock4 lane%d: got (%08x %08x) want (%08x %08x)",
				i, got[i*2], got[i*2+1], wantL[i], wantR[i])
		}
	}
}

// TestLaneInvariance is the test that makes Task 5's tuning safe: whatever width
// ships, the answers must be identical. It compares every generated width
// against the single-lane path already proven equal to x/crypto in Task 3.
func TestLaneInvariance(t *testing.T) {
	rng := rand.New(rand.NewSource(4041))
	for trial := 0; trial < 12; trial++ {
		cost := 4 + rng.Intn(2)
		correct := randPassword(rng)
		crypt, err := bcrypt.GenerateFromPassword(correct, cost)
		if err != nil {
			t.Fatal(err)
		}
		h, err := NewHasher(string(crypt))
		if err != nil {
			t.Fatal(err)
		}

		// A batch of 8 with the correct password at a rotating position, so
		// every lane index is exercised as the hit across trials.
		pw := make([][]byte, 8)
		hit := trial % 8
		for i := range pw {
			pw[i] = randPassword(rng)
		}
		pw[hit] = correct

		want := make([]bool, 8)
		for i := range pw {
			want[i] = h.one(pw[i])
		}
		if !want[hit] {
			t.Fatalf("trial %d: single-lane oracle rejected the correct password", trial)
		}

		got := make([]bool, 8)
		h.Run(pw, got)
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("trial %d lane %d: Run gave %v, single-lane gave %v", trial, i, got[i], want[i])
			}
		}
	}
}

// TestPartialBatch covers the tail: a wordlist whose length is not a multiple of
// the lane width must still test every candidate, including the last one.
func TestPartialBatch(t *testing.T) {
	correct := []byte("tail-case")
	crypt, err := bcrypt.GenerateFromPassword(correct, 4)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHasher(string(crypt))
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 9; n++ {
		for hit := 0; hit < n; hit++ {
			pw := make([][]byte, n)
			for i := range pw {
				pw[i] = []byte("wrong")
			}
			pw[hit] = correct
			out := make([]bool, n)
			h.Run(pw, out)
			for i := range out {
				if want := i == hit; out[i] != want {
					t.Errorf("n=%d hit=%d: out[%d] = %v, want %v", n, hit, i, out[i], want)
				}
			}
		}
	}
}

// TestNoBoundsChecksInRounds guards the property the vendored code already
// has: the Feistel round code (encryptBlock, and here encryptBlock2/4/8) is
// byte-indexed into fixed [256]uint32 S-boxes, which the compiler can prove
// safe, and it runs ~522 times per key expansion - by far the hottest loop in
// the program. Lane state held in slices instead of fixed-size arrays there
// would reintroduce checks that defeat register allocation in exactly that
// loop, which is what this test exists to catch.
//
// The check is scoped to the encryptBlockN function bodies rather than the
// whole file. Scanning the whole file also catches nextWord/saltWord's own
// circular-buffer bounds check (b[j] with a wraparound j the compiler cannot
// prove in range across loop iterations) at every inlined call site inside
// expandKeyN/expandKeyWithSaltN, plus the pw[i]/h.keyScratch[i] batch-index
// check in runN against the caller-supplied pw slice. Both are pre-existing:
// the first is upstream getNextWord's own limitation (blowfish.go:44/64/104/
// 110/111/...), duplicated once per lane because it is called once per lane;
// the second is the same one-check-per-batch cost the original Run already
// paid indexing pw. Neither runs once per Feistel round, and neither is
// something this task's fixed-arity design could avoid without hand-editing
// Task 2/3's nextWord/saltWord - so scoping to the round code is what
// actually tests the claim in this comment's first paragraph.
func TestNoBoundsChecksInRounds(t *testing.T) {
	src, err := os.ReadFile("eks_lanes.go")
	if err != nil {
		t.Fatalf("read eks_lanes.go: %v", err)
	}
	funcStart := regexp.MustCompile(`^func encryptBlock\d+\(`)
	type span struct{ lo, hi int }
	var spans []span
	lines := strings.Split(string(src), "\n")
	for i := 0; i < len(lines); i++ {
		if !funcStart.MatchString(lines[i]) {
			continue
		}
		lo := i + 1 // 1-indexed source line of the func line
		hi := lo
		for j := i + 1; j < len(lines); j++ {
			hi = j + 1
			if lines[j] == "}" {
				break
			}
		}
		spans = append(spans, span{lo, hi})
	}
	const wantWidths = 3 // widths 2, 4, 8 per bcryptlane_gen.py's WIDTHS
	if len(spans) != wantWidths {
		t.Fatalf("found %d encryptBlockN bodies, want %d (one per generated width)", len(spans), wantWidths)
	}

	out, err := exec.Command("go", "build", "-gcflags=-d=ssa/check_bce/debug=1", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	lineRe := regexp.MustCompile(`^\./eks_lanes\.go:(\d+):`)
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, "IsInBounds") {
			continue
		}
		m := lineRe.FindStringSubmatch(l)
		if m == nil {
			continue // not an eks_lanes.go line
		}
		n, _ := strconv.Atoi(m[1])
		for _, sp := range spans {
			if n >= sp.lo && n <= sp.hi {
				t.Errorf("bounds check in generated round code: %s", l)
			}
		}
	}
}

func benchWidth(b *testing.B, width int) {
	crypt, _ := bcrypt.GenerateFromPassword([]byte("benchmark"), 5)
	h, _ := NewHasher(string(crypt))
	pw := make([][]byte, width)
	for i := range pw {
		pw[i] = []byte("candidate")
	}
	out := make([]bool, width)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Run(pw, out)
	}
	// ns/op divided by width is the per-candidate cost; report it directly.
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*width), "ns/candidate")
}

func BenchmarkWidth1(b *testing.B) { benchWidth(b, 1) }
func BenchmarkWidth2(b *testing.B) { benchWidth(b, 2) }
func BenchmarkWidth4(b *testing.B) { benchWidth(b, 4) }
func BenchmarkWidth8(b *testing.B) { benchWidth(b, 8) }
