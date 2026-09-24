package smith

// pbkdf2VeraCryptSHA256LaneHasher implements laneHasher for VeraCrypt's
// SHA-256 KDF modes (cryptCascadeModes with kdf=="sha256" — TrueCrypt never
// supports this KDF), batching pbkdf2Sha256Lanes candidate passwords
// through pbkdf2HMACSHA256DeriveBatchN — the multi-block primitive, since
// the derived key here is 128 or 192 bytes (bits/8 for bits ∈
// {1024,1536}, or 64 bytes for the boot-only bits=512 mode), two to six
// SHA-256 blocks.
//
// Only the explicit split modes (verifyCryptCascadeMode, dispatched via
// the cryptCascadeModes map — e.g. "veracrypt-sha256-xts1024") are
// accelerated. The bare "-t veracrypt"/"-t truecrypt" auto-detect path
// (verifyCryptHeader) tries several KDFs in sequence for ONE candidate at
// a time; restructuring that loop to batch is a separate, larger change
// not attempted here, so it keeps using the scalar path for every KDF,
// SHA-256 included.
type pbkdf2VeraCryptSHA256LaneHasher struct {
	salt      []byte
	encrypted []byte
	iter      int
	bits      int
}

// newPBKDF2VeraCryptSHA256LaneHasher parses targetHash via the same
// parseCryptHeader verifyCryptCascadeMode uses, for a mode whose KDF is
// SHA-256, returning nil (caller falls back to the scalar path) for any
// other KDF or a header that does not parse.
func newPBKDF2VeraCryptSHA256LaneHasher(targetHash string, mode cryptCascadeMode) *pbkdf2VeraCryptSHA256LaneHasher {
	if mode.kdf != "sha256" {
		return nil
	}
	header, err := parseCryptHeader(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2VeraCryptSHA256LaneHasher{
		salt:      header[:64],
		encrypted: header[64:512],
		iter:      veraCryptSHA256Iterations(mode.boot),
		bits:      mode.bits,
	}
}

// Run mirrors pbkdf2AnsibleLaneHasher.Run's shape, calling
// vcHeaderValidThroughWidth — the same cascade/CRC check
// verifyCryptCascadeMode itself uses — on each lane's derived key.
func (h *pbkdf2VeraCryptSHA256LaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatchN(&lanes, h.salt, h.iter, h.bits/8)
		for k := 0; k < n; k++ {
			out[i+k] = vcHeaderValidThroughWidth(derived[k], h.encrypted, h.bits)
		}
		i += n
	}
}
