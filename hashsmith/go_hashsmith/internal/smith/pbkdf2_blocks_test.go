package smith

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// The claim pbkdf2Range rests on is that PBKDF2 output blocks are independent,
// so a longer derivation extends a shorter one rather than replacing it. If
// that is wrong, VeraCrypt cracking silently stops working. It is checked
// against x/crypto/pbkdf2, at every block boundary, for every PRF the
// VeraCrypt path can select.
func TestPBKDF2RangeMatchesXCrypto(t *testing.T) {
	hashes := map[string]func() hash.Hash{
		"sha1":              sha1.New,
		"sha256":            sha256.New,
		"sha512":            sha512.New,
		"ripemd160":         newRIPEMD160,
		"whirlpool":         newWhirlpool,
		"streebog512native": newStreebog512Native,
	}
	for name, newHash := range hashes {
		hLen := newHash().Size()
		for _, iter := range []int{1, 2, 37} {
			// Ten blocks covers dkLen 192 for the narrowest PRF here.
			want := pbkdf2.Key([]byte("passphrase"), []byte("saltsalt"), iter, 10*hLen, newHash)

			got := pbkdf2Range([]byte("passphrase"), []byte("saltsalt"), iter, 1, 11, newHash)
			if string(got) != string(want) {
				t.Fatalf("%s iter=%d: pbkdf2Range(1,11) differs from pbkdf2.Key", name, iter)
			}

			// And the property the VeraCrypt change actually uses: deriving a
			// prefix and then extending it gives the same bytes as deriving
			// the whole thing at once, at every split.
			for split := 1; split <= 10; split++ {
				head := pbkdf2Range([]byte("passphrase"), []byte("saltsalt"), iter, 1, split+1, newHash)
				tail := pbkdf2Range([]byte("passphrase"), []byte("saltsalt"), iter, split+1, 11, newHash)
				if string(append(head, tail...)) != string(want) {
					t.Fatalf("%s iter=%d: extending after block %d diverged", name, iter, split)
				}
			}
		}
	}
}

// pbkdf2BlocksFor decides how much of the key the single-cipher fast path
// covers; if it under-counts, the code slices a short buffer and panics.
func TestPBKDF2BlocksForCoversTheRequestedLength(t *testing.T) {
	for name, newHash := range map[string]func() hash.Hash{
		"ripemd160":         newRIPEMD160, // 20 bytes: 64 -> 4 blocks, 192 -> 10
		"whirlpool":         newWhirlpool, // 64 bytes: 64 -> 1 block,  192 -> 3
		"streebog512native": newStreebog512Native,
		"sha256":            sha256.New, // 32 bytes: 64 -> 2 blocks, 192 -> 6
		"sha512":            sha512.New,
	} {
		hLen := newHash().Size()
		for _, dkLen := range []int{64, 192} {
			n := pbkdf2BlocksFor(dkLen, newHash)
			if n*hLen < dkLen {
				t.Errorf("%s: %d blocks of %d bytes do not cover dkLen %d", name, n, hLen, dkLen)
			}
			if (n-1)*hLen >= dkLen {
				t.Errorf("%s: %d blocks of %d bytes is more than dkLen %d needs", name, n, hLen, dkLen)
			}
		}
	}
}

// RFC 6070's PBKDF2-HMAC-SHA1 vectors, run through pbkdf2Range rather than
// through x/crypto, so the range function is pinned to published output and
// not only to another implementation.
func TestPBKDF2RangeMatchesRFC6070(t *testing.T) {
	cases := []struct {
		pw, salt string
		iter     int
		dkLen    int
		want     string
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
			"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
	}
	for _, c := range cases {
		blocks := pbkdf2BlocksFor(c.dkLen, sha1.New)
		got := pbkdf2Range([]byte(c.pw), []byte(c.salt), c.iter, 1, blocks+1, sha1.New)
		if h := hex.EncodeToString(got[:c.dkLen]); h != c.want {
			t.Errorf("PBKDF2(%q, %q, %d, %d) = %s, want %s", c.pw, c.salt, c.iter, c.dkLen, h, c.want)
		}
	}
}
