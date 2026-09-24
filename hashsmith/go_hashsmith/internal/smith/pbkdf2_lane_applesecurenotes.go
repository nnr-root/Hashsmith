package smith

// pbkdf2AppleSecureNotesLaneHasher implements laneHasher for Apple Secure
// Notes records (crack_hashcat_more_records.go), batching pbkdf2Sha256Lanes
// candidate passwords through the shared pbkdf2HMACSHA256DeriveBatch
// primitive. The stored KEK is only 16 bytes (aes.BlockSize), well inside
// one PBKDF2 block, so the batch primitive's full 32-byte output is simply
// truncated per lane — see pbkdf2ASPNetIdentityLaneHasher.Run's own comment
// for why that is correct.
type pbkdf2AppleSecureNotesLaneHasher struct {
	rec appleSecureNotesRecord
}

// newPBKDF2AppleSecureNotesLaneHasher parses targetHash via the same
// parseAppleSecureNotes verifyAppleSecureNotes uses, returning nil (caller
// falls back to the scalar path) for anything that does not parse.
func newPBKDF2AppleSecureNotesLaneHasher(targetHash string) *pbkdf2AppleSecureNotesLaneHasher {
	rec, err := parseAppleSecureNotes(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2AppleSecureNotesLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2AppleSecureNotesLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iterations)
		for k := 0; k < n; k++ {
			ok, err := appleSecureNotesUnwraps(&h.rec, derived[k][:16])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
