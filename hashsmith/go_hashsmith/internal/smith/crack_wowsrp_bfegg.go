package smith

// Two more formats an earlier bounded search recorded as unreproduced, and
// what each turned out to be.
//
//	<user>:$WoWSRP$<verifier>$<salt>   World of Warcraft's SRP-6 verifier
//	+<12 crypt-base64 chars>           Eggdrop's IRC bot password
//
// Neither is a hash of the password in any arrangement, which is why no sweep
// over orderings and separators found them. WoWSRP hashes twice and then does
// modular exponentiation — the stored value is g^x mod N, not a digest.
// Eggdrop runs Blowfish keyed on the password and encrypts a fixed block, so
// the password is the KEY and the "hash" is a ciphertext.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/blowfish"
)

// ── World of Warcraft SRP-6 ───────────────────────────────────────────────────
//
// The verifier is v = g^x mod N with x = SHA-1(salt || SHA-1(USER ":" PASS)),
// the inner digest read as a big-endian integer.
//
// The account name is part of x, so it is part of the record: a verifier
// cannot be checked without it, and John writes it in two places depending on
// where the record came from — in front, as a username field, or after the
// salt and a star. Both spellings are read; neither may be missing.
//
// The group is the one the authentication server uses, a 256-bit prime with a
// generator of 47. It is small by modern standards — 256 bits of modulus is
// far below what a discrete log needs to be safe — but that does not help an
// attacker here, because recovering x is not the same as recovering the
// password that produced it.
const wowSRPMarker = "$WoWSRP$"

var (
	wowSRPModulus, _ = new(big.Int).SetString(
		"112624315653284427036559548610503669920632123929604336254260115573677366691719", 10)
	wowSRPGenerator = big.NewInt(47)
)

type wowSRPRecord struct {
	user     string
	salt     []byte
	verifier *big.Int
}

func wowSRPFields(target string) (wowSRPRecord, error) {
	var r wowSRPRecord
	t := strings.TrimSpace(target)
	i := strings.Index(t, wowSRPMarker)
	if i < 0 {
		return r, errors.New("not a WoWSRP record")
	}
	body := t[i+len(wowSRPMarker):]
	if i > 0 {
		r.user = strings.TrimSuffix(t[:i], ":")
	}
	// The other spelling puts the account after the salt, behind a star.
	if rest, user, ok := strings.Cut(body, "*"); ok {
		if r.user != "" && r.user != user {
			return r, errors.New("this WoWSRP record names two different accounts")
		}
		body, r.user = rest, user
	}
	if r.user == "" || strings.ContainsAny(r.user, ":*") {
		return r, errors.New("a WoWSRP verifier cannot be checked without the account name, which belongs either in front of the record or after the salt")
	}
	v, saltHex, ok := strings.Cut(body, "$")
	if !ok || strings.Contains(saltHex, "$") {
		return r, errors.New("a WoWSRP record is <account>:$WoWSRP$<verifier>$<salt>, or $WoWSRP$<verifier>$<salt>*<account>")
	}
	if len(v) == 0 || len(v) > 128 || !isHex(v) {
		return r, errors.New("a WoWSRP verifier is hex")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 || len(salt) > 64 {
		return r, errors.New("a WoWSRP salt is hex")
	}
	r.salt = salt
	r.verifier, ok = new(big.Int).SetString(v, 16)
	if !ok {
		return r, errors.New("a WoWSRP verifier is hex")
	}
	return r, nil
}

func verifyWoWSRP(target, candidate string) (bool, error) {
	r, err := wowSRPFields(target)
	if err != nil {
		return false, err
	}
	inner := sha1.Sum([]byte(r.user + ":" + candidate))
	outer := sha1.New()
	_, _ = outer.Write(r.salt)
	_, _ = outer.Write(inner[:])
	x := new(big.Int).SetBytes(outer.Sum(nil))
	got := new(big.Int).Exp(wowSRPGenerator, x, wowSRPModulus)
	return got.Cmp(r.verifier) == 0, nil
}

func isWoWSRP(target string) bool {
	_, err := wowSRPFields(target)
	return err == nil
}

// ── Eggdrop ───────────────────────────────────────────────────────────────────
//
// Eggdrop stores "+" followed by twelve characters of base64. Behind them is
// one Blowfish encryption of the fixed 64-bit block 0xdeadd061_23f6b095,
// keyed on the password — no salt, no iteration. The cipher is ordinary
// Blowfish; the only thing unusual is the encoding.
//
// The encoding loses a byte. Each 32-bit half is written six bits at a time,
// least significant first, in six characters — thirty-six bits of room for
// thirty-two bits of value — but only the first five and a half characters of
// the second half are kept, so one byte of the left half never reaches the
// record. That is why fifty-six bits are compared and not sixty-four, and it
// is Eggdrop's own bug, preserved here because the records in the world carry
// it.
const bfEggPrefix = "+"

// bfEggAlphabet is Eggdrop's own base64, which is crypt(3)'s sixty-four
// characters in a different order: lower case before upper, where crypt puts
// upper first. Using crypt's ordering decodes every record to the wrong
// bytes and nothing ever matches.
const bfEggAlphabet = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const (
	bfEggSalt1 = 0xdeadd061
	bfEggSalt2 = 0x23f6b095
)

// bfEggBinary decodes a record into the seven bytes John compares.
func bfEggBinary(target string) ([]byte, error) {
	t := strings.TrimSpace(target)
	if len(t) != 13 || !strings.HasPrefix(t, bfEggPrefix) {
		return nil, errors.New("an Eggdrop record is a plus and twelve characters")
	}
	v := t[1:]
	idx := make([]uint32, 12)
	for i := 0; i < 12; i++ {
		j := strings.IndexByte(bfEggAlphabet, v[i])
		if j < 0 {
			return nil, errors.New("an Eggdrop record is crypt(3) characters")
		}
		idx[i] = uint32(j)
	}
	out := make([]byte, 7)
	first := idx[0] | idx[1]<<6 | idx[2]<<12 | idx[3]<<18
	out[0], out[1], out[2] = byte(first), byte(first>>8), byte(first>>16)
	out[3] = byte(idx[4] | idx[5]<<6)
	second := idx[6] | idx[7]<<6 | idx[8]<<12 | idx[9]<<18
	out[4], out[5], out[6] = byte(second), byte(second>>8), byte(second>>16)
	return out, nil
}

func verifyBFEgg(target, candidate string) (bool, error) {
	want, err := bfEggBinary(target)
	if err != nil {
		return false, err
	}
	if candidate == "" {
		return false, nil
	}
	c, err := blowfish.NewCipher([]byte(candidate))
	if err != nil {
		return false, nil
	}
	var in, out [8]byte
	binary.BigEndian.PutUint32(in[0:], bfEggSalt1)
	binary.BigEndian.PutUint32(in[4:], bfEggSalt2)
	c.Encrypt(out[:], in[:])
	left := binary.BigEndian.Uint32(out[0:])
	right := binary.BigEndian.Uint32(out[4:])

	// Eggdrop writes the RIGHT half first, and only three bytes of the left.
	got := make([]byte, 7)
	binary.LittleEndian.PutUint32(got[0:], right)
	got[4], got[5], got[6] = byte(left), byte(left>>8), byte(left>>16)
	return hmac.Equal(got, want), nil
}
func isBFEgg(target string) bool { _, err := bfEggBinary(target); return err == nil }
