package smith

import "crypto/sha256"

// pbkdf2LUKSLaneHasher implements laneHasher for LUKS v1 records
// (crack_luks.go), batching pbkdf2Sha256Lanes candidate passwords through
// the shared pbkdf2HMACSHA256DeriveBatch primitive to derive the SLOT key —
// the expensive step, since slotIter is where a real volume's cost lives.
//
// Only records whose hash spec is SHA-256 and whose key is no longer than
// one PBKDF2 block (32 bytes) are accelerated: every other hash spec
// (SHA-1/512, RIPEMD-160, Whirlpool) and any longer key (AES-256-XTS needs
// a 64-byte master key, for instance) fall back to the scalar path, which
// already handles all of them. The much smaller second PBKDF2 call that
// confirms the master-key digest is not batched — it is typically a small
// fraction of slotIter's cost and stays scalar per lane, same as every
// other two-stage format this project has wired (see AzureSync/Mozilla's
// per-lane transforms for the shape, and DPAPI's own comment for why a
// tiny second stage is not worth chasing on its own).
type pbkdf2LUKSLaneHasher struct {
	p *luksParams
}

// newPBKDF2LUKSLaneHasherFromParams builds a lane hasher for an already-
// parsed record, refusing (returning nil) anything outside the SHA-256,
// ≤32-byte-key case described above.
func newPBKDF2LUKSLaneHasherFromParams(p *luksParams) *pbkdf2LUKSLaneHasher {
	if p.hashSpec != "sha256" || p.keyBytes <= 0 || p.keyBytes > 32 {
		return nil
	}
	return &pbkdf2LUKSLaneHasher{p: p}
}

// newPBKDF2LUKSLaneHasher parses targetHash via the same parseLUKSHash
// verifyLUKS uses, for the generic "-t luks" type — any hash spec and
// cipher the record itself names.
func newPBKDF2LUKSLaneHasher(targetHash string) *pbkdf2LUKSLaneHasher {
	p, err := parseLUKSHash(targetHash)
	if err != nil {
		return nil
	}
	return newPBKDF2LUKSLaneHasherFromParams(p)
}

// newPBKDF2LUKSModeLaneHasher parses targetHash for one of Hashcat's split
// LUKS v1 types (luksModeSpecs), additionally requiring the record's hash
// spec and cipher to match the selected mode — mirroring verifyLUKSMode's
// own check — before applying the same SHA-256/≤32-byte-key gate.
func newPBKDF2LUKSModeLaneHasher(targetHash string, mode luksModeSpec) *pbkdf2LUKSLaneHasher {
	p, err := parseLUKSHash(targetHash)
	if err != nil || p.hashSpec != mode.hashSpec || p.cipherName != mode.cipherName {
		return nil
	}
	return newPBKDF2LUKSLaneHasherFromParams(p)
}

// Run derives the slot key for a batch of candidates, then runs each lane's
// own (cheap, scalar) decrypt-and-confirm tail.
func (h *pbkdf2LUKSLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.p.slotSalt, h.p.slotIter)
		for k := 0; k < n; k++ {
			ok, err := luksSlotKeyMatches(h.p, derived[k][:h.p.keyBytes], sha256.New)
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
