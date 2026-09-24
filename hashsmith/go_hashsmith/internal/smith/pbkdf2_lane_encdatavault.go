package smith

// pbkdf2EncDataVaultLaneHasher implements laneHasher for ENCsecurity
// Datavault's PBKDF2 form ($encdv-pbkdf2$, crack_encdatavault.go), batching
// pbkdf2Sha256Lanes candidate passwords through
// pbkdf2HMACSHA256DeriveBatchN — the multi-block primitive, since a
// keychain record needs the full 128-byte table (eight 16-byte keys,
// encdvPBKDF2OutputLen), four SHA-256 blocks. The MD5 form ($encdv$) is not
// PBKDF2 at all and is not accelerated here.
type pbkdf2EncDataVaultLaneHasher struct {
	rec *encdvRecord
}

// newPBKDF2EncDataVaultLaneHasher parses targetHash via the same
// parseENCDataVault verifyENCDataVault uses, returning nil (caller falls
// back to the scalar path) for the MD5 form or anything that does not
// parse.
func newPBKDF2EncDataVaultLaneHasher(targetHash string) *pbkdf2EncDataVaultLaneHasher {
	rec, err := parseENCDataVault(targetHash)
	if err != nil || !rec.pbkdf2 {
		return nil
	}
	return &pbkdf2EncDataVaultLaneHasher{rec: rec}
}

// Run mirrors pbkdf2AnsibleLaneHasher.Run's shape exactly, another
// multi-block-primitive user.
func (h *pbkdf2EncDataVaultLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatchN(&lanes, h.rec.salt, h.rec.iterations, encdvPBKDF2OutputLen(h.rec))
		for k := 0; k < n; k++ {
			ok, err := encdvMatches(h.rec, derived[k])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
