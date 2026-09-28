package smith

// pbkdf2DiskCryptorLaneHasher implements laneHasher for DiskCryptor volume
// headers (crack_diskcryptor.go). The password transform (UTF-16LE, since
// DiskCryptor is a Windows tool) is a cheap, deterministic per-candidate
// function applied before the batch call — the same shape AzureSync and
// Mozilla's per-lane transforms already use — and maxCiphers*64 can exceed
// one SHA-512 block (up to 192 bytes for the three-cipher cascade mode),
// which is why this is the first wired user of
// pbkdf2HMACSHA512DeriveBatchN rather than the single-block primitive.
type pbkdf2DiskCryptorLaneHasher struct {
	salt       []byte // header[:dcrpSaltLen], the PBKDF2 salt
	sigBlock   []byte // header[dcrpSigOffset:dcrpSigOffset+16], the encrypted signature block
	maxCiphers int
}

// newPBKDF2DiskCryptorLaneHasher parses targetHash via the same
// parseDiskCryptor verifyDiskCryptor uses, returning nil only when the
// record itself does not parse (maxCiphers is a mode parameter fixed by
// the caller, not something the record can make invalid).
func newPBKDF2DiskCryptorLaneHasher(targetHash string, maxCiphers int) *pbkdf2DiskCryptorLaneHasher {
	header, err := parseDiskCryptor(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2DiskCryptorLaneHasher{
		salt:       header[:dcrpSaltLen],
		sigBlock:   header[dcrpSigOffset : dcrpSigOffset+16],
		maxCiphers: maxCiphers,
	}
}

// Run mirrors pbkdf2Sha512LaneHasher.Run, with two differences: each
// candidate is UTF-16LE-encoded before entering the batch (DiskCryptor's
// own password encoding), and the derived key can span multiple SHA-512
// blocks, so the batch goes through pbkdf2HMACSHA512DeriveBatchN rather
// than the single-block primitive.
func (h *pbkdf2DiskCryptorLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha512Lanes {
			n = pbkdf2Sha512Lanes
		}
		var lanes [pbkdf2Sha512Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = utf16leBytes(string(pw[i+k]))
		}
		for k := n; k < pbkdf2Sha512Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		keys := pbkdf2HMACSHA512DeriveBatchN(&lanes, h.salt, dcrpIter, h.maxCiphers*64)
		for k := 0; k < n; k++ {
			out[i+k] = dcrpHeaderValid(keys[k], h.sigBlock, h.maxCiphers)
		}
		i += n
	}
}
