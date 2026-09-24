package smith

// pbkdf2VirtualBoxLaneHasher implements laneHasher for VirtualBox's
// two-stage $vbox$ records (crack_hashcat_containers.go). Unlike every
// other format wired so far, this one genuinely CHAINS two batched PBKDF2
// calls rather than batching one call and running a cheap scalar tail:
// both iter1 and iter2 can be substantial, so both are worth accelerating.
//
// Only the AES-128-XTS variant (keyWords==8, a 32-byte first-stage key)
// fits a single PBKDF2 block. AES-256-XTS needs a 64-byte first-stage key
// (two AES-256 XTS half-keys), which needs multi-block PBKDF2 the batch
// primitive does not compute, so it falls back to the scalar path.
//
// Stage two's PBKDF2 password is the per-lane XTS-decrypted plaintext from
// stage one — different for every lane, the same shape AzureSync and
// Mozilla's per-lane transforms already use, except here the transform
// itself depends on a BATCHED result (stage one's derived key) rather than
// only on the candidate.
type pbkdf2VirtualBoxLaneHasher struct {
	rec virtualBoxRecord
}

// newPBKDF2VirtualBoxLaneHasher parses targetHash via the same
// parseVirtualBox verifyVirtualBox uses, returning nil (caller falls back
// to the scalar path) for anything that does not parse as this algo's
// record, or whose key is the AES-256-XTS width.
func newPBKDF2VirtualBoxLaneHasher(targetHash, algo string) *pbkdf2VirtualBoxLaneHasher {
	rec, err := parseVirtualBox(targetHash, algo)
	if err != nil || rec.keyWords != 8 {
		return nil
	}
	return &pbkdf2VirtualBoxLaneHasher{rec: rec}
}

// Run derives the first-stage key for a batch of candidates, XTS-decrypts
// the stored encrypted password per lane with it, then derives the
// second-stage key for that batch of (per-lane-different) results and
// compares each against the stored checksum.
func (h *pbkdf2VirtualBoxLaneHasher) Run(pw [][]byte, out []bool) {
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
		stage1 := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt1, h.rec.iter1)

		var stage2Lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < pbkdf2Sha256Lanes; k++ {
			// decryptXTSZeroTweak can only fail on a key/ciphertext length
			// it does not recognise; stage1[k] is always exactly 32 bytes
			// and h.rec.enc is always exactly 32 bytes (keyWords==8,
			// checked in newPBKDF2VirtualBoxLaneHasher), so this never
			// takes the error path.
			plain, err := decryptXTSZeroTweak(stage1[k][:], h.rec.enc)
			if err != nil {
				plain = make([]byte, 32)
			}
			stage2Lanes[k] = plain
		}
		stage2 := pbkdf2HMACSHA256DeriveBatch(&stage2Lanes, h.rec.salt2, h.rec.iter2)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(stage2[k][:], h.rec.want)
		}
		i += n
	}
}
