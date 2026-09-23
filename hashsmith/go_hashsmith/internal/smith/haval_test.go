package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestHavalAgainstJohnsVectors checks every one of the fifteen variants
// against John's own, which is the only independent source for a hash this
// old that no library implements.
func TestHavalAgainstJohnsVectors(t *testing.T) {
	// John's dynamic table gives one format per (size, passes) pair.
	for _, tc := range []struct {
		number       int
		size, passes int
	}{
		{160, 128, 3}, {170, 128, 4}, {180, 128, 5},
		{190, 160, 3}, {200, 160, 4}, {210, 160, 5},
		{220, 192, 3}, {230, 192, 4}, {240, 192, 5},
		{250, 224, 3}, {260, 224, 4}, {270, 224, 5},
		{280, 256, 3}, {290, 256, 4}, {300, 256, 5},
	} {
		format := "dynamic_" + itoa(tc.number) + " $dynamic_" + itoa(tc.number) + "$"
		record, pass := johnVector(t, format)
		want := record[strings.LastIndexByte(record, '$')+1:]
		got := hex.EncodeToString(havalSum([]byte(pass), tc.size, tc.passes))
		if !strings.EqualFold(got, want) {
			t.Errorf("haval%d_%d(%q) = %s, want %s", tc.size, tc.passes, pass, got, want)
		}
		if len(got) != tc.size/4 {
			t.Errorf("haval%d_%d produced %d hex characters", tc.size, tc.passes, len(got))
		}
	}
}

// TestHavalParametersChangeTheAnswer pins that the pass count and the output
// size are both mixed into the padding rather than only selecting rounds and
// a truncation. Two HAVALs of the same message that differ in either must
// differ from the first byte, so a shorter output is never a prefix of a
// longer one and an extra pass is never an extension of a shorter one.
func TestHavalParametersChangeTheAnswer(t *testing.T) {
	const msg = "the same message every time"
	for _, size := range []int{128, 160, 192, 224, 256} {
		var prev []byte
		for _, passes := range []int{3, 4, 5} {
			got := havalSum([]byte(msg), size, passes)
			if len(got) != size/8 {
				t.Fatalf("haval%d_%d returned %d bytes", size, passes, len(got))
			}
			if prev != nil && hex.EncodeToString(prev) == hex.EncodeToString(got) {
				t.Errorf("haval%d_%d matches the previous pass count", size, passes)
			}
			prev = got
		}
	}
	full := hex.EncodeToString(havalSum([]byte(msg), 256, 5))
	for _, size := range []int{128, 160, 192, 224} {
		short := hex.EncodeToString(havalSum([]byte(msg), size, 5))
		if strings.HasPrefix(full, short) {
			t.Errorf("haval%d_5 is a prefix of haval256_5, so the fold is a truncation", size)
		}
	}
}

// TestHavalSpansBlocks checks a message long enough to need several blocks
// and one that lands exactly on the padding boundary, which is where an
// off-by-one in the padding shows up.
func TestHavalSpansBlocks(t *testing.T) {
	for _, n := range []int{0, 1, 117, 118, 119, 127, 128, 129, 255, 256, 1000} {
		msg := strings.Repeat("a", n)
		if got := havalSum([]byte(msg), 256, 5); len(got) != 32 {
			t.Errorf("length %d: produced %d bytes", n, len(got))
		}
	}
	// A message of exactly 118 bytes forces a second block, since the
	// parameters and length need the last ten bytes of one.
	a := havalSum([]byte(strings.Repeat("a", 118)), 256, 5)
	b := havalSum([]byte(strings.Repeat("a", 119)), 256, 5)
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Error("118 and 119 bytes hash the same")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestMDC2AgainstPublishedVectors checks MDC-2 against the two pangram
// digests OpenSSL publishes, which differ in a single letter — the case a
// chaining construction has to get right.
func TestMDC2AgainstPublishedVectors(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{"The quick brown fox jumps over the lazy dog", "000ed54e093d61679aefbeae05bfe33a"},
		{"The quick brown fox jumps over the lazy cog", "775f59f8e51aec29c57ac6ab850d58e8"},
		{"", "52525252525252522525252525252525"},
	} {
		if got := mdc2Hex([]byte(tc.msg)); !strings.EqualFold(got, tc.want) {
			t.Errorf("mdc2(%q) = %s, want %s", tc.msg, got, tc.want)
		}
	}
	// The two chains must not be the same hash twice: if the halves stopped
	// crossing over, both would start from their own constant and the two
	// eight-byte halves of the result would be independent. A one-bit change
	// has to move both.
	a := mdc2Sum([]byte("a message that is longer than one block"))
	b := mdc2Sum([]byte("a message that is longer than one blocL"))
	same := 0
	for i := range a {
		if a[i] == b[i] {
			same++
		}
	}
	if same > 4 {
		t.Errorf("a one-character change left %d of 16 digest bytes unchanged", same)
	}
}
