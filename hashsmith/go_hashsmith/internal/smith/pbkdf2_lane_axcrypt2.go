package smith

// pbkdf2AxCrypt2LaneHasher implements laneHasher for AxCrypt 2 records
// (crack_axcrypt_wrap.go, both the AES-128 and AES-256 cipher widths —
// "axcrypt2-128"/"axcrypt2-256" — since the PBKDF2 call itself is
// identical either way, only the post-processing keyLen differs), batching
// pbkdf2Sha512Lanes candidate passwords through the shared
// pbkdf2HMACSHA512DeriveBatch primitive. AxCrypt 1's bare-SHA-1 KEK is a
// different format entirely and is not accelerated here.
type pbkdf2AxCrypt2LaneHasher struct {
	rec        *axcryptRecord
	keyLen     int
	wrappedLen int
}

// newPBKDF2AxCrypt2LaneHasher parses targetHash via the same parseAxCrypt
// verifyAxCrypt2 uses, for the given cipher width, returning nil (caller
// falls back to the scalar path) for an AxCrypt 1 record, a record too
// short for this cipher width, or anything else that does not parse.
func newPBKDF2AxCrypt2LaneHasher(targetHash string, keyLen int) *pbkdf2AxCrypt2LaneHasher {
	a, err := parseAxCrypt(targetHash)
	if err != nil || a.version != 2 {
		return nil
	}
	wrappedLen := 40
	if keyLen == 32 {
		wrappedLen = 56
	}
	if len(a.wrapped) < wrappedLen {
		return nil
	}
	return &pbkdf2AxCrypt2LaneHasher{rec: a, keyLen: keyLen, wrappedLen: wrappedLen}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2AxCrypt2LaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha512Lanes {
			n = pbkdf2Sha512Lanes
		}
		var lanes [pbkdf2Sha512Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha512Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.rec.kdfSalt, h.rec.kdfRounds)
		for k := 0; k < n; k++ {
			ok, err := axcrypt2Matches(h.rec, derived[k][:], h.keyLen, h.wrappedLen)
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
