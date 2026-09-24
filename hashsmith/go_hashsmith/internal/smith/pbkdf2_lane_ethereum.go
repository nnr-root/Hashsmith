package smith

// pbkdf2EthereumLaneHasher implements laneHasher for Ethereum keystore
// records using the PBKDF2 KDF marker (crack_ethereum.go), batching
// pbkdf2Sha256Lanes candidate passwords through the shared
// pbkdf2HMACSHA256DeriveBatch primitive. The scrypt ("s") variant is not
// accelerated here — parseEthereumPBKDF2Record refuses it, so a record
// using it falls back to the scalar path, which already handles both.
type pbkdf2EthereumLaneHasher struct {
	rec ethereumPBKDF2Record
}

// newPBKDF2EthereumLaneHasher parses targetHash via the same
// parseEthereumPBKDF2Record verifyEthereum's "p" case uses, returning nil
// (caller falls back to the scalar path) for anything that is not a
// PBKDF2-variant record.
func newPBKDF2EthereumLaneHasher(targetHash string) *pbkdf2EthereumLaneHasher {
	rec, err := parseEthereumPBKDF2Record(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2EthereumLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2EthereumLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iter)
		for k := 0; k < n; k++ {
			out[i+k] = ethereumMatches(derived[k][:], h.rec.ciphertext, h.rec.mac)
		}
		i += n
	}
}
