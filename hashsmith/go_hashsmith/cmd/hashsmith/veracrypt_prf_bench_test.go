package main

import (
	"hash"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// These benchmarks are the evidence for two changes on the VeraCrypt KDF path,
// and they are written as A/B pairs so the evidence stays checkable rather than
// being a number in a commit message.
//
// 20,000 iterations matches the figure the roadmap records for the original
// measurement. One output block per run, so the PRFs are comparable to each
// other per iteration rather than per derived key.
//
// Measured on an Apple M2, 2026-09-21, quiet machine, -benchtime 2s -count 3:
//
//	RIPEMD-160  x/crypto   28.27 ms   ->  native      19.83 ms   1.42x
//	Whirlpool   no marshal 107.7 ms   ->  marshalable 74.0 ms    1.46x
//	Streebog    no marshal 221.3 ms   ->  marshalable 177.2 ms   1.25x
//
// The RIPEMD-160 pair measures the whole swap away from x/crypto/ripemd160;
// most of that gap is the marshaler, which that package does not implement.
// The other two isolate the marshaler alone by hiding it behind a wrapper.
func benchVeraCryptPRF(b *testing.B, newHash func() hash.Hash) {
	hLen := newHash().Size()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pbkdf2.Key([]byte("passphrase"), []byte("saltsaltsaltsalt"), 20000, hLen, newHash)
	}
}

// hiddenMarshaler wraps a hash so crypto/hmac cannot see its BinaryMarshaler
// and must re-compress the ipad and opad blocks for every message.
type hiddenMarshaler struct{ hash.Hash }

func BenchmarkVeraCryptPRFRipemd160XCrypto(b *testing.B) { benchVeraCryptPRF(b, ripemd160.New) }
func BenchmarkVeraCryptPRFRipemd160Native(b *testing.B)  { benchVeraCryptPRF(b, newRIPEMD160) }

func BenchmarkVeraCryptPRFWhirlpool(b *testing.B) { benchVeraCryptPRF(b, newWhirlpool) }
func BenchmarkVeraCryptPRFWhirlpoolNoMarshal(b *testing.B) {
	benchVeraCryptPRF(b, func() hash.Hash { return hiddenMarshaler{newWhirlpool()} })
}

func BenchmarkVeraCryptPRFStreebog512(b *testing.B) { benchVeraCryptPRF(b, newStreebog512Native) }
func BenchmarkVeraCryptPRFStreebog512NoMarshal(b *testing.B) {
	benchVeraCryptPRF(b, func() hash.Hash { return hiddenMarshaler{newStreebog512Native()} })
}
