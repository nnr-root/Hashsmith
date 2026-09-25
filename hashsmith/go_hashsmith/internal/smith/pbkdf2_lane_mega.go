package smith

// pbkdf2MegaLaneHasher implements laneHasher for mega.nz protected links
// (crack_mega.go), batching pbkdf2Sha512Lanes candidate passwords through
// the shared pbkdf2HMACSHA512DeriveBatch primitive — MEGA's own derived
// key is exactly 64 bytes, one SHA-512 block, so no multi-block support is
// needed here the way some SHA-256 formats needed.
type pbkdf2MegaLaneHasher struct {
	link *megaLink
}

// newPBKDF2MegaLaneHasher parses targetHash via the same parseMegaLink
// verifyMegaLink uses, returning nil (caller falls back to the scalar
// path) for anything that does not parse.
func newPBKDF2MegaLaneHasher(targetHash string) *pbkdf2MegaLaneHasher {
	link, err := parseMegaLink(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2MegaLaneHasher{link: link}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2MegaLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.link.salt, megaIterations)
		for k := 0; k < n; k++ {
			out[i+k] = megaLinkMatches(h.link, derived[k][:])
		}
		i += n
	}
}
