package smith

// pbkdf2MozillaLaneHasher implements laneHasher for Mozilla key4.db
// records (crack_mozilla.go), batching pbkdf2Sha256Lanes candidates
// through the shared pbkdf2HMACSHA256DeriveBatch primitive. key3.db's
// hand-rolled HMAC-SHA1 construction is not PBKDF2 at all and is not
// accelerated here — parseMozillaAES refuses it, so it falls back to the
// scalar path.
//
// Like MS-AzureSync, PBKDF2's password is not the candidate itself but
// mozillaEntryKey(globalSalt, candidate) — SHA-1 of the shared global salt
// and the candidate, run once per lane before the batch call, exactly
// where the scalar verifyMozilla already runs it inline.
type pbkdf2MozillaLaneHasher struct {
	rec *mozillaRecord
}

// newPBKDF2MozillaLaneHasher parses targetHash via the same parseMozillaAES
// verifyMozilla's key4.db case reaches, returning nil (caller falls back to
// the scalar path) for a key3.db record or anything else that does not
// parse.
func newPBKDF2MozillaLaneHasher(targetHash string) *pbkdf2MozillaLaneHasher {
	rec, err := parseMozillaAES(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2MozillaLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape, with the per-lane
// entry-key transform run before batching.
func (h *pbkdf2MozillaLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = mozillaEntryKey(h.rec.globalSalt, string(pw[i+k]))
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.entrySalt, h.rec.rounds)
		for k := 0; k < n; k++ {
			ok, err := mozillaAESMatches(h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
