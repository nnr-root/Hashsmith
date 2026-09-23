package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The published HAS-160 vectors, plus John's own for its has-160 format (the
// last line), which is a 62-byte message and so exercises the padding path
// that carries the length into a second block.
func TestHAS160(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{"", "307964ef34151d37c8047adec7ab50f4ff89762d"},
		{"a", "4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8"},
		{"abc", "975e810488cf2a3d49838478124afce4b1c78804"},
		{"message digest", "2338dbc8638d31225f73086246ba529f96710bc6"},
		{"abcdefghijklmnopqrstuvwxyz", "596185c9ab6703d0d0dbb98702bc0f5729cd1d3c"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"cb5d7efbca2f02e0fb7167cabb123af5795764e5"},
		{strings.Repeat("1234567890", 8), "07f05c8c0773c55ca3a5a695ce6aca4c438911b5"},
	} {
		h := newHAS160()
		_, _ = h.Write([]byte(tc.msg))
		if got := hex.EncodeToString(h.Sum(nil)); got != tc.want {
			t.Errorf("HAS-160(%.30q) = %s, want %s", tc.msg, got, tc.want)
		}
	}
}

func TestHAS160Streaming(t *testing.T) {
	msg := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)
	whole := newHAS160()
	_, _ = whole.Write([]byte(msg))
	piecemeal := newHAS160()
	for i := 0; i < len(msg); i++ {
		_, _ = piecemeal.Write([]byte(msg[i : i+1]))
	}
	if a, b := hex.EncodeToString(whole.Sum(nil)), hex.EncodeToString(piecemeal.Sum(nil)); a != b {
		t.Errorf("byte-at-a-time = %s, all at once = %s", b, a)
	}
}
