package smith

// pbkdf2GELILaneHasher implements laneHasher for FreeBSD GELI records
// (crack_geli.go), batching pbkdf2Sha512Lanes candidate passwords through
// the shared pbkdf2HMACSHA512DeriveBatch primitive — GELI's own derived
// key is exactly 64 bytes, one SHA-512 block.
type pbkdf2GELILaneHasher struct {
	rec geliRecord
}

// newPBKDF2GELILaneHasher parses targetHash via the same geliFields
// verifyGELI uses, returning nil (caller falls back to the scalar path)
// for anything that does not parse.
func newPBKDF2GELILaneHasher(targetHash string) *pbkdf2GELILaneHasher {
	rec, err := geliFields(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2GELILaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2GELILaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.rec.salt, h.rec.iterations)
		for k := 0; k < n; k++ {
			ok, err := geliMatches(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
