package smith

// pbkdf2GRUB2LaneHasher implements laneHasher for GRUB2 password hashes
// (crack_grub.go), batching pbkdf2Sha512Lanes candidate passwords through
// the shared pbkdf2HMACSHA512DeriveBatch primitive. GRUB2's digest length
// is a record field, not fixed by the format, and can be up to 128 bytes;
// only records whose digest fits in one SHA-512 block (<=64 bytes — the
// overwhelming majority, since GRUB2's own tooling defaults to exactly 64)
// are accelerated. A longer digest falls back to the scalar path.
type pbkdf2GRUB2LaneHasher struct {
	salt   []byte
	iter   int
	digest []byte
}

// newPBKDF2GRUB2LaneHasher parses targetHash via the same parseGRUB2Hash
// verifyGRUB2 uses, returning nil (caller falls back to the scalar path)
// for a digest longer than 64 bytes or anything that does not parse.
func newPBKDF2GRUB2LaneHasher(targetHash string) *pbkdf2GRUB2LaneHasher {
	parsed, err := parseGRUB2Hash(targetHash)
	if err != nil || len(parsed.digest) > 64 {
		return nil
	}
	return &pbkdf2GRUB2LaneHasher{salt: parsed.salt, iter: parsed.iterations, digest: parsed.digest}
}

// Run mirrors pbkdf2Cisco8LaneHasher.Run's shape exactly.
func (h *pbkdf2GRUB2LaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.salt, h.iter)
		for k := 0; k < n; k++ {
			out[i+k] = grub2Matches(derived[k][:len(h.digest)], h.digest)
		}
		i += n
	}
}
