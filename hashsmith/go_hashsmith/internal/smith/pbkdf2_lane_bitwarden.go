package smith

import "strings"

// pbkdf2BitwardenLaneHasher implements laneHasher for the "bitwarden" type
// (crack_bitwarden.go), covering both of verifyBitwarden's own record
// shapes — mirroring its dispatch, the same approach
// pbkdf2LastPassRecordsLaneHasher uses for "lastpass"'s two spellings.
//
// The "0" (encrypted-key) shape is an ordinary single-round, shared-salt
// PBKDF2 call and batches through pbkdf2HMACSHA256DeriveBatch exactly like
// any other format here. The "2" (master-password hash) shape genuinely
// needs the per-lane-salt primitive for its SECOND round: the master key
// (this batch's per-lane password for round two) is salted by each
// candidate's own password, not by anything shared across the batch — the
// first format wired needing pbkdf2HMACSHA256DeriveBatchNPerLaneSalt.
type pbkdf2BitwardenLaneHasher struct {
	type0 bool
	rec0  bitwardenType0Record
	rec2  bitwardenType2Record
}

// newPBKDF2BitwardenLaneHasher parses targetHash exactly as verifyBitwarden
// does, returning nil (caller falls back to the scalar path) for anything
// that does not parse as either record shape.
func newPBKDF2BitwardenLaneHasher(targetHash string) *pbkdf2BitwardenLaneHasher {
	if !strings.HasPrefix(targetHash, "$bitwarden$") {
		return nil
	}
	f := strings.Split(targetHash[len("$bitwarden$"):], "*")
	if len(f) < 4 {
		return nil
	}
	if f[0] == "0" {
		rec, err := parseBitwardenType0(f)
		if err != nil {
			return nil
		}
		return &pbkdf2BitwardenLaneHasher{type0: true, rec0: rec}
	}
	if f[0] != "2" {
		return nil
	}
	rec, err := parseBitwardenType2(f)
	if err != nil {
		return nil
	}
	return &pbkdf2BitwardenLaneHasher{rec2: rec}
}

// Run dispatches to whichever record shape this hasher was built for.
func (h *pbkdf2BitwardenLaneHasher) Run(pw [][]byte, out []bool) {
	if h.type0 {
		h.runType0(pw, out)
		return
	}
	h.runType2(pw, out)
}

// runType0 mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly — one
// shared-salt batch, one cheap per-lane decrypt-and-check tail.
func (h *pbkdf2BitwardenLaneHasher) runType0(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, []byte(h.rec0.email), h.rec0.iter)
		for k := 0; k < n; k++ {
			ok, err := bitwardenType0Decrypts(&h.rec0, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}

// runType2 chains two batches: the master key (shared salt = email), then
// the stored hash (per-lane salt = each lane's own candidate password).
func (h *pbkdf2BitwardenLaneHasher) runType2(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes, saltLanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		masterKeys := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec2.email, h.rec2.iter)

		var masterKeyLanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < pbkdf2Sha256Lanes; k++ {
			masterKeyLanes[k] = masterKeys[k][:]
			saltLanes[k] = lanes[k]
		}
		got := pbkdf2HMACSHA256DeriveBatchNPerLaneSalt(&masterKeyLanes, &saltLanes, h.rec2.hashIter, 32)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(got[k], h.rec2.want)
		}
		i += n
	}
}
