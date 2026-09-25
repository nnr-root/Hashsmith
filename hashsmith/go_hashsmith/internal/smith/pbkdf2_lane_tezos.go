package smith

import (
	"crypto/ed25519"
	"crypto/hmac"

	"golang.org/x/crypto/blake2b"
)

// pbkdf2TezosLaneHasher implements laneHasher for Tezos fundraiser wallets
// (crack_tezos.go). Unlike every other SHA-512 format wired so far, the
// PBKDF2 PASSWORD here is the fixed, shared fundraiser mnemonic — identical
// across every lane — while the candidate lives in each lane's own SALT
// ("mnemonic"+email+candidate), the inverse of Bitwarden's per-lane-salt
// shape. That is exactly what pbkdf2HMACSHA512DeriveBatchNPerLaneSalt
// computes: one shared password, one salt per lane. The derived key is
// ed25519.SeedSize*2 = 64 bytes, fitting a single SHA-512 block, but the
// per-lane-salt primitive is multi-block from the start (see its own
// comment), so no single-block twin is needed here either.
type pbkdf2TezosLaneHasher struct {
	rec *tezosRecord
}

// newPBKDF2TezosLaneHasher parses targetHash via the same parseTezos
// verifyTezos uses, returning nil only when the record itself does not
// parse.
func newPBKDF2TezosLaneHasher(targetHash string) *pbkdf2TezosLaneHasher {
	rec, err := parseTezos(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2TezosLaneHasher{rec: rec}
}

// Run batches the shared mnemonic as every lane's PBKDF2 password, each
// lane's own "mnemonic"+email+candidate as its salt, then does the
// existing scalar Ed25519 + BLAKE2b-160 check (verifyTezos's own logic,
// unchanged) per lane on the result.
func (h *pbkdf2TezosLaneHasher) Run(pw [][]byte, out []bool) {
	mnemonic := []byte(h.rec.mnemonic)
	prefix := "mnemonic" + h.rec.email

	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha512Lanes {
			n = pbkdf2Sha512Lanes
		}
		var passwords, salts [pbkdf2Sha512Lanes][]byte
		for k := 0; k < n; k++ {
			passwords[k] = mnemonic
			salts[k] = append([]byte(prefix), pw[i+k]...)
		}
		for k := n; k < pbkdf2Sha512Lanes; k++ {
			passwords[k] = passwords[n-1]
			salts[k] = salts[n-1]
		}
		seeds := pbkdf2HMACSHA512DeriveBatchNPerLaneSalt(&passwords, &salts, h.rec.iterations, ed25519.SeedSize*2)
		for k := 0; k < n; k++ {
			out[i+k] = tezosSeedMatches(seeds[k], h.rec.keyHash)
		}
		i += n
	}
}

// tezosSeedMatches is verifyTezos's post-PBKDF2 check, extracted so both
// the scalar path and this lane hasher share one source of truth: derive
// the Ed25519 public key from the seed's first 32 bytes, BLAKE2b-160 it,
// and compare against the record's stored key hash.
func tezosSeedMatches(seed []byte, keyHash []byte) bool {
	pub := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
	h, err := blake2b.New(tezosKeyHashSize, nil)
	if err != nil {
		return false
	}
	_, _ = h.Write(pub)
	return hmac.Equal(h.Sum(nil), keyHash)
}
