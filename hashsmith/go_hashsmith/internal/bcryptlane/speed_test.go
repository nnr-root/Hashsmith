package bcryptlane

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// bcryptSpeedupFloor is a ratchet, not a target. Raise it as the core improves;
// never lower it to make a change pass.
//
// It is a RATIO against x/crypto/bcrypt measured in this same process, not an
// absolute c/s figure. An absolute floor would encode one machine's clock speed
// and flake on every other runner; the ratio is the quantity the work is
// actually about and is stable across hardware.
//
// Set from the measurement in docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md
// with a 15% margin below the observed value to absorb runner variance.
const bcryptSpeedupFloor = 1.92 * 0.85 // measured 1.92x speedup at Lanes=4, see docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md

func TestSpeedupOverXCrypto(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test; run without -short")
	}
	crypt, err := bcrypt.GenerateFromPassword([]byte("ratchet"), 5)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHasher(string(crypt))
	if err != nil {
		t.Fatal(err)
	}
	pw := make([][]byte, Lanes)
	for i := range pw {
		pw[i] = []byte("candidate")
	}
	out := make([]bool, Lanes)

	lane := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h.Run(pw, out)
		}
	})
	perCandidate := float64(lane.NsPerOp()) / float64(Lanes)

	ref := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bcrypt.CompareHashAndPassword(crypt, []byte("candidate"))
		}
	})

	got := float64(ref.NsPerOp()) / perCandidate
	t.Logf("x/crypto %d ns/op, bcryptlane %.0f ns/candidate at %d lanes, speedup %.2fx",
		ref.NsPerOp(), perCandidate, Lanes, got)
	if got < bcryptSpeedupFloor {
		t.Errorf("speedup %.2fx is below the %.2fx floor", got, bcryptSpeedupFloor)
	}
}
