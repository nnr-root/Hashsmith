package smith

// newTwofishCipher adapts x/crypto's Twofish to crypto/cipher.Block.
//
// x/crypto returns *twofish.Cipher, which already satisfies the interface;
// this exists so the cipher choice reads the same as the others and so the
// dependency is named in one place.

import (
	"crypto/cipher"

	"golang.org/x/crypto/twofish"
)

func newTwofishCipher(key []byte) (cipher.Block, error) {
	return twofish.NewCipher(key)
}
