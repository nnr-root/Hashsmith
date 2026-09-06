package bcryptlane

import (
	"testing"

	"golang.org/x/crypto/blowfish"
)

// TestNextWordMatchesCursor pins the absolute-position readers to upstream's
// cursor semantics, including the wrap that happens mid-word for key lengths
// that are not multiples of four.
func TestNextWordMatchesCursor(t *testing.T) {
	for _, key := range [][]byte{[]byte("a"), []byte("abc"), []byte("abcd"), []byte("seven77"), []byte("password")} {
		j := 0
		for i := 0; i < 18; i++ {
			// upstream's inlined cursor read
			var want uint32
			for k := 0; k < 4; k++ {
				want = want<<8 | uint32(key[j])
				j++
				if j >= len(key) {
					j = 0
				}
			}
			if got := nextWord(key, i*4); got != want {
				t.Errorf("key %q word %d: nextWord = %08x, cursor = %08x", key, i, got, want)
			}
		}
	}
}

// TestVendoredMatchesUpstream pins the vendored copy to the library it replaces.
// Any divergence here is a transcription error, and every later test in this
// package would inherit it.
func TestVendoredMatchesUpstream(t *testing.T) {
	keys := [][]byte{[]byte("a\x00"), []byte("password\x00"), []byte("a much longer key than blowfish nominally accepts, well past 56 bytes\x00")}
	salt := []byte("0123456789abcdef")

	for _, key := range keys {
		up, err := blowfish.NewSaltedCipher(key, salt)
		if err != nil {
			t.Fatalf("upstream rejected key %q: %v", key, err)
		}
		got := newSaltedState(key, salt)
		if got == nil {
			t.Fatalf("newSaltedState returned nil for key %q", key)
		}
		// Drive both through the same schedule bcrypt uses, then compare
		// ciphertext rather than reaching into upstream's unexported state.
		for j := 0; j < 4; j++ {
			blowfish.ExpandKey(key, up)
			expandKey(key, got)
			blowfish.ExpandKey(salt, up)
			expandKey(salt, got)
		}
		src := []byte("OrpheanB")
		wantBuf := make([]byte, 8)
		up.Encrypt(wantBuf, src)

		l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
		r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
		gl, gr := encryptBlock(l, r, got)
		gotBuf := []byte{
			byte(gl >> 24), byte(gl >> 16), byte(gl >> 8), byte(gl),
			byte(gr >> 24), byte(gr >> 16), byte(gr >> 8), byte(gr),
		}
		if string(gotBuf) != string(wantBuf) {
			t.Errorf("key %q: vendored %x, upstream %x", key, gotBuf, wantBuf)
		}
	}
}
