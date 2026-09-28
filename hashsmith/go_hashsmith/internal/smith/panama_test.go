package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The empty message is Panama's published vector and "T" is John's own for
// its Panama format. The remaining four were computed here and then handed to
// John, which recovered every plaintext from them under --format=panama.
func TestPanama(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{"", "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b"},
		{"T", "049d698307d8541f22870dfa0a551099d3d02bc6d57c610a06a4585ed8d35ff8"},
		{"abc", "a2a70386b81fb918be17f00ff3e3b376a0462c4dc2eec7f2c63202c8874c037d"},
		{"hashsmith", "396b4c6c882afab07a757e7c0e61623d7565661fb23c5ceacc3f125ac75a1a34"},
		// Two messages longer than one 32-byte block, so the push loop runs
		// more than once before the pull phase.
		{"The quick brown fox jumps over the lazy dog",
			"5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1"},
		{"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			"1ee98a446ff99199353547819fbe796b672c8efb040d776ba154e18d243cbc3f"},
	} {
		h := newPanama()
		_, _ = h.Write([]byte(tc.msg))
		if got := hex.EncodeToString(h.Sum(nil)); got != tc.want {
			t.Errorf("Panama(%.30q) = %s, want %s", tc.msg, got, tc.want)
		}
	}
}

func TestPanamaStreaming(t *testing.T) {
	msg := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)
	whole := newPanama()
	_, _ = whole.Write([]byte(msg))
	piecemeal := newPanama()
	for i := 0; i < len(msg); i++ {
		_, _ = piecemeal.Write([]byte(msg[i : i+1]))
	}
	if a, b := hex.EncodeToString(whole.Sum(nil)), hex.EncodeToString(piecemeal.Sum(nil)); a != b {
		t.Errorf("byte-at-a-time = %s, all at once = %s", b, a)
	}
}
