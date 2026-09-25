// internal/smith/markov_positional_test.go
package smith

import (
	"os"
	"testing"
)

func TestMarkovRadix(t *testing.T) {
	cases := []struct{ threshold, domain, want int }{
		{0, 256, 256},   // unset = unlimited
		{300, 256, 256}, // clamps to the domain
		{8, 256, 8},
		{-1, 256, 256}, // negative treated as unset
	}
	for _, c := range cases {
		if got := markovRadix(c.threshold, c.domain); got != c.want {
			t.Errorf("markovRadix(%d, %d) = %d, want %d", c.threshold, c.domain, got, c.want)
		}
	}
}

func TestLoadHCStat2BuildsExpectedRanking(t *testing.T) {
	// Fixture is trained on "aab", "aac", "aad", "zzz" — 'a' strictly
	// dominates position 0 (3 votes vs 'z' at 1), so it must rank first.
	m, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 0)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	if !m.positional {
		t.Fatal("loadHCStat2 must produce a positional model")
	}
	if m.radix != 256 {
		t.Fatalf("radix = %d, want 256 (no threshold given)", m.radix)
	}
	if got := m.posFirst[0][0]; got != 'a' {
		t.Errorf("posFirst[0][0] = %q, want 'a'", got)
	}
	// position 1, conditioned on 'a' at position 0: 'a' appears in all
	// three "aXY" words, strictly dominating 'z'.
	if got := m.posCond[0]['a'][0]; got != 'a' {
		t.Errorf("posCond[0]['a'][0] = %q, want 'a'", got)
	}

	// A length-3 candidate built greedily from this ranking should spell
	// "aaa" — not necessarily a trained word (position 2 has a 4-way tie
	// among 'b','c','d','z', broken deterministically by byte value), but
	// position 0 and 1 must be 'a'.
	layout := markovLayout(m, 3, 3)
	c := layout.candidate(0)
	if c[0] != 'a' || c[1] != 'a' {
		t.Errorf("most-likely length-3 candidate = %q, want to start \"aa\"", c)
	}
}

func TestLoadHCStat2ThresholdShrinksRadixAndKeyspace(t *testing.T) {
	full, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 0)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	limited, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 4)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	if limited.radix != 4 {
		t.Fatalf("radix = %d, want 4", limited.radix)
	}
	fullLayout := markovLayout(full, 3, 3)
	limitedLayout := markovLayout(limited, 3, 3)
	if limitedLayout.total >= fullLayout.total {
		t.Errorf("thresholded total (%d) should be smaller than unthresholded (%d)",
			limitedLayout.total, fullLayout.total)
	}
	if limitedLayout.total != 4*4*4 {
		t.Errorf("thresholded total = %d, want 4^3 = 64", limitedLayout.total)
	}
}

func TestTrainMarkovThresholdShrinksRadix(t *testing.T) {
	dir := t.TempDir()
	wl := dir + "/t.txt"
	if err := os.WriteFile(wl, []byte("abc\ncab\nbca\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := trainMarkov("abc", wl, 2)
	if err != nil {
		t.Fatal(err)
	}
	if m.radix != 2 {
		t.Fatalf("radix = %d, want 2", m.radix)
	}
	if len(m.first) != 2 || len(m.cond['a']) != 2 {
		t.Fatalf("ranked lists were not truncated to the threshold")
	}
}
