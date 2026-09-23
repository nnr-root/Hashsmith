package smith

// OpenVMS SYSUAF password hashes.
//
//	$V$<26 characters>
//
// DEC's LGI$HPWD is the oldest password function in this catalogue that is
// still a password function rather than a checksum, and it is built out of
// number theory rather than out of a cipher. The password and username are
// folded into a single 64-bit value, and that value is fed through a
// polynomial evaluated modulo 2^64 − 59, the largest prime that fits in a
// quadword. Purdy proposed the construction in 1974: the polynomial's
// exponents are chosen so that inverting it means extracting roots modulo a
// prime, which is hard, while evaluating it is a handful of multiplications.
//
// There are three variants and the record says which. Every vector in
// circulation is Purdy_S, which is what VMS has written since v5.4 — so the
// other two are implemented from the source and not confirmed by a published
// digest, and that is worth saying rather than leaving to be assumed. Purdy (1) pads the
// username to twelve characters with spaces; Purdy_V (2) trims it; Purdy_S
// (3), which VMS calls Hickory, additionally seeds the fold with the password
// LENGTH and rotates the accumulator every eighth byte — the last of which is
// the only thing in the family that makes the fold order-dependent.
//
// Two things about it have aged badly and both are visible in the record. The
// output is sixty-four bits, so collisions are findable by birthday attack
// alone. And unless the PWDMIX flag is set the password is UPPER-CASED before
// hashing, which is why VMS passwords are case-insensitive and why the
// keyspace is smaller than it looks.

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"
)

const openVMSPrefix = "$V$"

// openVMSEncSet is the sixty-four characters a SYSUAF record is written in.
// The order is not alphabetical and the transpositions are deliberate — "QRTS"
// and "cedf" are what DEC wrote, and reading them as "QRST" and "cdef"
// decodes every record to the wrong bytes.
const openVMSEncSet = "-ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789abcedfghijklmnopqrstuvwxyz+"

// openVMSRad50Set is the forty characters a username is packed into, three to
// a sixteen-bit word.
const openVMSRad50Set = " ABCDEFGHIJKLMNOPQRSTUVWXYZ$._0123456789"

// The prime the polynomial is evaluated modulo: 2^64 - 59.
const openVMSPrimeGap = 59

var openVMSPrime = ^uint64(0) - openVMSPrimeGap + 1

// The polynomial's five coefficients, each written in the source as a small
// negative number — which modulo 2^64 is what they are.
var openVMSCoeff = [5]uint64{
	^uint64(0) - 83 + 1,
	^uint64(0) - 179 + 1,
	^uint64(0) - 257 + 1,
	^uint64(0) - 323 + 1,
	^uint64(0) - 363 + 1,
}

type openVMSRecord struct {
	hash     uint64
	alg      int
	salt     uint16
	username string
	mixCase  bool
}

// openVMSDecode reads the six-bit encoding, which packs bits least
// significant first and lets fields straddle character boundaries.
func openVMSDecode(encoded string) (openVMSRecord, error) {
	var r openVMSRecord
	pos, accum, apos := 0, uint32(0), 0
	read := func(bitsWanted, argBytes int) ([]byte, error) {
		out := make([]byte, 0, argBytes)
		remaining := argBytes
		for fs := bitsWanted; fs > 0; fs -= 8 {
			for apos < 8 && pos < len(encoded) {
				i := strings.IndexByte(openVMSEncSet, encoded[pos])
				if i < 0 {
					return nil, errors.New("a SYSUAF record uses DEC's own sixty-four characters")
				}
				pos++
				accum |= uint32(i) << uint(apos)
				apos += 6
			}
			if remaining > 0 {
				out = append(out, byte(accum))
				remaining--
				accum >>= 8
				if apos < 8 {
					apos = 0
				} else {
					apos -= 8
				}
			}
		}
		for remaining > 0 && apos > 0 {
			out = append(out, byte(accum))
			remaining--
			accum >>= 8
			if apos < 8 {
				apos = 0
			} else {
				apos -= 8
			}
		}
		for remaining > 0 {
			out = append(out, 0)
			remaining--
		}
		return out, nil
	}

	hash, err := read(64, 8)
	if err != nil {
		return r, err
	}
	alg, err := read(8, 1)
	if err != nil {
		return r, err
	}
	salt, err := read(16, 2)
	if err != nil {
		return r, err
	}
	name, err := read(64, 8)
	if err != nil {
		return r, err
	}
	opt, err := read(4, 1)
	if err != nil {
		return r, err
	}

	r.hash = binary.LittleEndian.Uint64(hash)
	r.alg = int(alg[0])
	r.salt = binary.LittleEndian.Uint16(salt)
	r.mixCase = opt[0]&1 != 0

	var sb strings.Builder
	for i := 0; i < 4; i++ {
		a := binary.LittleEndian.Uint16(name[2*i:])
		c0 := a % 40
		a /= 40
		c1 := a % 40
		c2 := a / 40
		if c2 > 39 {
			return r, errors.New("a SYSUAF username does not decode")
		}
		sb.WriteByte(openVMSRad50Set[c0])
		sb.WriteByte(openVMSRad50Set[c1])
		sb.WriteByte(openVMSRad50Set[c2])
	}
	r.username = strings.TrimRight(sb.String(), " ")
	if r.alg < 1 || r.alg > 3 {
		return r, errors.New("a SYSUAF record names a hashing method Hashsmith does not run")
	}
	return r, nil
}

// openVMSCollapse folds a string into the eight-byte accumulator. The index
// counts DOWN from the string's length, so the same characters in a different
// position land in different bytes — and under Purdy_S the accumulator is
// rotated every time byte seven is touched, which is the only part of the
// fold that depends on order.
func openVMSCollapse(acc *[8]byte, s string, purdyS bool) {
	for i := 0; i < len(s); i++ {
		idx := (len(s) - i) & 7
		acc[idx] += s[i]
		if purdyS && idx == 7 {
			lo := binary.LittleEndian.Uint32(acc[0:])
			hi := binary.LittleEndian.Uint32(acc[4:])
			binary.LittleEndian.PutUint32(acc[0:], bits.RotateLeft32(lo, 1))
			binary.LittleEndian.PutUint32(acc[4:], bits.RotateLeft32(hi, 1))
		}
	}
}

// pqAdd is addition modulo 2^64 - 59.
func pqAdd(u, y uint64) uint64 {
	sum, carry := bits.Add64(u, y, 0)
	if carry != 0 {
		return sum + openVMSPrimeGap
	}
	if sum >= openVMSPrime {
		return sum - openVMSPrime
	}
	return sum
}

// pqMod reduces a value already below 2^64 into the field.
func pqMod(x uint64) uint64 {
	if x < openVMSPrime {
		return x
	}
	return x + openVMSPrimeGap
}

// pqShift is multiplication by 2^32 modulo the prime, done as the original
// does it: the high half times 59, plus the low half moved up.
func pqShift(u uint64) uint64 {
	prod := (u >> 32) * openVMSPrimeGap
	return pqAdd(u<<32, prod)
}

// pqMulAdd is (u*y + x) mod P, assembled from four 32-bit products because
// the VAX had an instruction for exactly that and nothing wider.
func pqMulAdd(u, y, x uint64, addX bool) uint64 {
	uh, ul := u>>32, u&0xFFFFFFFF
	yh, yl := y>>32, y&0xFFFFFFFF

	acc := pqShift(pqMod(uh * yh))
	acc = pqAdd(acc, pqAdd(pqMod(uh*yl), pqMod(ul*yh)))
	acc = pqShift(acc)

	low := pqMod(ul * yl)
	if addX {
		low = pqAdd(low, x)
	}
	return pqAdd(acc, low)
}

// pqExp raises u to the given exponent, with the squarings shared between two
// exponents as the original shares them.
func pqExp(u uint64, highbit int, n0, n1 uint32) (uint64, uint64) {
	squares := make([]uint64, highbit)
	squares[0] = u
	for k := 1; k < highbit; k++ {
		squares[k] = pqMulAdd(squares[k-1], squares[k-1], 0, false)
	}
	pow := func(n uint32) uint64 {
		var r uint64
		first := true
		for k := 0; n != 0; k++ {
			if n%2 == 1 {
				if first {
					r, first = squares[k], false
				} else {
					r = pqMulAdd(r, squares[k], 0, false)
				}
			}
			n /= 2
		}
		return r
	}
	return pow(n0), pow(n1)
}

// openVMSPurdy evaluates the polynomial.
func openVMSPurdy(u uint64) uint64 {
	const (
		n0 = 16777213 // 2^24 - 3
		n1 = 16777153 // 2^24 - 63
		na = 37449
		nb = 448
	)
	x := u
	if x >= openVMSPrime {
		x += openVMSPrimeGap
	}

	xn0mn1, xna := pqExp(x, 16, n0-n1, na)
	part1 := pqAdd(xn0mn1, openVMSCoeff[0])

	xnanb, _ := pqExp(xna, 9, nb, 0)
	xn1 := pqMulAdd(xnanb, x, 0, false)

	part2 := pqMulAdd(x, openVMSCoeff[1], openVMSCoeff[2], true)
	part2 = pqMulAdd(x, part2, openVMSCoeff[3], true)
	part2 = pqMulAdd(x, part2, openVMSCoeff[4], true)

	return pqMulAdd(part1, xn1, part2, true)
}

// openVMSHash reproduces LGI$HPWD.
func openVMSHash(password, username string, alg int, salt uint16) uint64 {
	if password == "" {
		return 0
	}
	purdyS := alg == 3

	var acc [8]byte
	if purdyS {
		binary.LittleEndian.PutUint32(acc[0:], uint32(len(password)))
	}
	if alg == 1 {
		// Purdy pads the username to twelve with spaces, in place, without a
		// terminator — so a short name is followed by the spaces that were
		// already there.
		name := []byte("            ")
		copy(name, username)
		username = string(name)
	} else {
		username = strings.TrimRight(username, " ")
	}

	openVMSCollapse(&acc, password, purdyS)

	// The salt goes into bytes three and four, with the carry done by hand.
	acc[4] += byte(salt >> 8)
	if int(acc[3])+int(salt&0xFF) > 255 {
		acc[4]++
	}
	acc[3] += byte(salt & 0xFF)

	openVMSCollapse(&acc, username, purdyS)
	return openVMSPurdy(binary.LittleEndian.Uint64(acc[:]))
}

func openVMSFields(target string) (openVMSRecord, error) {
	t := strings.TrimSpace(target)
	if len(t) < len(openVMSPrefix) || !strings.EqualFold(t[:len(openVMSPrefix)], openVMSPrefix) {
		return openVMSRecord{}, errors.New("not a SYSUAF record")
	}
	body := t[len(openVMSPrefix):]
	if len(body) != 26 {
		return openVMSRecord{}, errors.New("a SYSUAF record is twenty-six encoded characters")
	}
	return openVMSDecode(body)
}

func verifyOpenVMS(target, candidate string) (bool, error) {
	r, err := openVMSFields(target)
	if err != nil {
		return false, err
	}
	pw := candidate
	if len(pw) > 32 {
		pw = pw[:32]
	}
	if !r.mixCase {
		// VMS passwords are case-insensitive unless the account is flagged
		// otherwise, so the keyspace is smaller than the character set.
		pw = strings.ToUpper(pw)
	}
	return openVMSHash(pw, r.username, r.alg, r.salt) == r.hash, nil
}

func isOpenVMS(target string) bool {
	_, err := openVMSFields(target)
	return err == nil
}
