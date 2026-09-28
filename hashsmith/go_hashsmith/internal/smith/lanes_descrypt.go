package smith

// ── Interleaved descrypt ─────────────────────────────────────────────────────
//
// descrypt's inner loop is twenty-five DES encryptions of the zero block, each
// sixteen rounds, each round depending on the one before it. After the table
// work in descrypt_fast.go that loop is not throughput-bound — the round
// function is twelve indexed loads and a dozen ALU ops, well inside what the
// core can issue — it is LATENCY-bound on its own dependency chain. Every
// round waits for the previous round's result before its first load can even
// be addressed.
//
// The fix is the one bcryptlane already uses for bcrypt: run several
// passwords' chains at once. They are independent, so round j of password 0
// can issue while round j-1 of password 1 is still resolving, and the loads
// keep the machine busy instead of stalling it.
//
// Measured on an idle M2, each lane count timed separately with repeats
// (measuring them in one invocation gave misleading numbers, which is why they
// were not):
//
//	lanes=1   142 kH/s
//	lanes=2   221 kH/s   1.56x
//	lanes=3   288 kH/s   2.03x
//	lanes=4   325 kH/s   2.29x  <- peak
//	lanes=6   250 kH/s          register pressure; the arrays start spilling
//	lanes=8   214 kH/s
//
// Four, which is also bcryptlane.Lanes, and for the same reason: past it the
// working set no longer fits the registers and the spills cost more than the
// overlap wins.
//
// This is what a bitsliced implementation would have been competing against,
// and it needs no gate networks and no assembly. See descrypt_bitslice_test.go
// for why bitslicing was measured and declined.

// descryptLanes is how many descrypt computations advance together.
const descryptLanes = 4

// descryptLaneHasher verifies candidates against ONE descrypt record,
// descryptLanes at a time. It carries reusable scratch and belongs to one
// goroutine, exactly like bcryptlane.Hasher.
type descryptLaneHasher struct {
	target   string   // the full 13-character record
	want     [11]byte // the record's hash half, for an allocation-free compare
	saltMask uint64
	ks       [descryptLanes][16]uint64
	packBuf  [11]byte
}

// newDescryptLaneHasher returns a hasher for this record, or nil when the
// record is not a descrypt one.
func newDescryptLaneHasher(targetHash string) *descryptLaneHasher {
	if !looksLikeDescrypt(targetHash) {
		return nil
	}
	s0, ok0 := descryptSaltChar(targetHash[0])
	s1, ok1 := descryptSaltChar(targetHash[1])
	if !ok0 || !ok1 {
		return nil
	}
	h := &descryptLaneHasher{
		target:   targetHash,
		saltMask: descryptSaltMask(s0 | (s1 << 6)),
	}
	copy(h.want[:], targetHash[2:])
	return h
}

// descryptKeyFromPassword builds the 64-bit DES key: each of the first eight
// password characters occupies the high seven bits of a key byte, absent ones
// left zero. Longer passwords are truncated, which is descrypt's own
// behaviour and the reason two passwords differing only past the eighth
// character hash identically.
func descryptKeyFromPassword(pw []byte) uint64 {
	var key uint64
	for i := 0; i < 8; i++ {
		var b byte
		if i < len(pw) {
			b = pw[i] << 1
		}
		key = (key << 8) | uint64(b)
	}
	return key
}

// Run verifies up to len(pw) candidates, writing each verdict to out. The
// signature matches bcryptlane.Hasher.Run so both can sit behind one
// interface.
func (h *descryptLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > descryptLanes {
			n = descryptLanes
		}
		for k := 0; k < n; k++ {
			h.ks[k] = desSubkeysFast(descryptKeyFromPassword(pw[i+k]))
		}
		// A partial group repeats the last key rather than leaving a stale
		// schedule in the unused lanes: the result of those lanes is never
		// read, but hashing a schedule left over from a previous call would
		// make this function's cost depend on its history.
		for k := n; k < descryptLanes; k++ {
			h.ks[k] = h.ks[n-1]
		}
		blocks := descryptIterateLanes(&h.ks, h.saltMask)
		for k := 0; k < n; k++ {
			// Compare the packed bytes directly. The salt half is fixed by
			// construction — it is where saltMask came from — so only the
			// hash half can differ, and building a string to say so would
			// allocate three times per candidate.
			descryptPackInto(blocks[k], &h.packBuf)
			out[i+k] = h.packBuf == h.want
		}
		i += n
	}
}

// descryptIterateLanes runs descryptLanes independent descrypt inner loops
// together. It is desIterateZeroBlock with the lane index threaded through;
// TestDescryptLanesMatchScalar holds it to that function's output.
func descryptIterateLanes(ks *[descryptLanes][16]uint64, saltMask uint64) [descryptLanes]uint64 {
	var st [descryptLanes]uint64 // IP(0) == 0
	for i := 0; i < 25; i++ {
		var l, r [descryptLanes]uint64
		for k := 0; k < descryptLanes; k++ {
			l[k] = (st[k] >> 32) & 0xffffffff
			r[k] = st[k] & 0xffffffff
		}
		for j := 0; j < 16; j++ {
			for k := 0; k < descryptLanes; k++ {
				nl := r[k]
				r[k] = l[k] ^ desFeistelFast(r[k], ks[k][j], saltMask)
				l[k] = nl
			}
		}
		for k := 0; k < descryptLanes; k++ {
			st[k] = (r[k] << 32) | l[k]
		}
	}
	var out [descryptLanes]uint64
	for k := 0; k < descryptLanes; k++ {
		out[k] = permute(st[k], desFP[:], 64)
	}
	return out
}
