package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"ekyu.moe/cryptonight"
)

func verifyMonero(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$monero$0*") {
		return false, errors.New("invalid Monero wallet record")
	}
	encoded := strings.TrimPrefix(target, "$monero$0*")
	if len(encoded) < 84 || len(encoded) > 256<<20 || len(encoded)%2 != 0 {
		return false, errors.New("invalid or truncated Monero keys file")
	}
	// Only the IV and first encrypted JSON block participate in verification;
	// avoid decoding and allocating the remainder of a potentially large wallet
	// once per password candidate.
	wallet, err := hex.DecodeString(encoded[:84])
	if err != nil {
		return false, errors.New("invalid Monero keys file header")
	}
	key := cryptonight.Sum([]byte(candidate), 0)
	if len(key) != 32 {
		return false, errors.New("CryptoNight returned an invalid key")
	}
	nonce := binary.LittleEndian.Uint64(wallet[:8])
	ciphertext := wallet[10:42]
	for _, rounds := range []int{20, 8} {
		stream := chachaOriginalBlock(key, 0, nonce, rounds)
		plain := make([]byte, len(ciphertext))
		for i := range plain {
			plain[i] = ciphertext[i] ^ stream[i]
		}
		if bytes.Contains(plain, []byte("key_data")) || bytes.Contains(plain, []byte("m_creation_timestamp")) {
			return true, nil
		}
	}
	return false, nil
}
