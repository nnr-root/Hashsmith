// internal/smith/markov_hcstat2_e2e_test.go
package smith

import "testing"

// TestMarkovHCStat2FindsTrainedPassword loads the committed real .hcstat2
// fixture (trained on "aab", "aac", "aad", "zzz") and confirms a brute-force
// walk ordered by it finds "aab" — and reaches it well before the
// lexicographic position brute force would, proving the ranking is doing
// real work rather than just passing candidates through unchanged.
func TestMarkovHCStat2FindsTrainedPassword(t *testing.T) {
	m, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 0)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	layout := markovLayout(m, 3, 3)

	target := "aab"
	foundAt := int64(-1)
	for i := int64(0); i < layout.total; i++ {
		if layout.candidate(i) == target {
			foundAt = i
			break
		}
	}
	if foundAt < 0 {
		t.Fatalf("markov layout never produced %q across its full keyspace (total=%d)", target, layout.total)
	}

	// Plain lexicographic brute force over the same 256-byte domain would
	// reach "aab" at index 'a'*256*256 + 'a'*256 + 'b' — astronomically
	// larger than where the trained ranking should place it, since 'a'
	// dominates positions 0 and 1 in the training data.
	lexicographicIndex := int64('a')*256*256 + int64('a')*256 + int64('b')
	if foundAt >= lexicographicIndex {
		t.Errorf("markov ranking did not surface %q earlier than lexicographic brute force would (found at %d, lexicographic at %d)",
			target, foundAt, lexicographicIndex)
	}
}
