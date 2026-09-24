package smith

// ENCsecurity Datavault — Hashcat 29910, 29920, 29930 and 29940.
//
//	$encdv$<version>$<n>$<iv>$<ct>[$<keychain>]
//	$encdv-pbkdf2$<version>$<n>$<iv>$<ct>$<saltlen>$<salt>$<iterations>[$<keychain>]
//
// Two key derivations and one verifier. The MD5 forms iterate MD5 999 times
// and XOR every intermediate together, then XOR that with a fixed table baked
// into the product — not a salt in any useful sense, since it is identical in
// every installation, but it has to be reproduced exactly. The PBKDF2 forms
// are an ordinary PBKDF2-HMAC-SHA256 and use their output as the AES-128 key
// directly, with no table involved.
//
// The check is a counter-mode keystream against eight bytes of known header.
// Datavault's container begins with the libpcap magic written backwards
// (d2 c3 b4 a1) followed by three zero bytes, which is 56 bits of known
// plaintext: enough on its own, and the only structure the format offers.
//
// One deliberate oddity, flagged in Hashcat's kernel as "not a bug": the
// keystream is taken from bytes 4..12 of the AES output rather than 0..8, so
// the first four bytes of every counter block are discarded.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// encdvDefaultSalts is the table ENCsecurity ships and XORs into the derived
// key. Eight blocks of four words; only the first is used when a vault has no
// keychain.
var encdvDefaultSalts = [32]uint32{
	0x0fc9e7d0, 0x8be424f6, 0x569d4e72, 0xedbc2c5c,
	0xdd7974f3, 0x3d8300c2, 0x9bd293d5, 0x7f9d9b8c,
	0x60850c47, 0x5846e296, 0x2d995d5e, 0xf1d06a28,
	0xe23f3d6b, 0x99614ba9, 0xc4edc5dd, 0xd8253ce1,
	0x2ca45989, 0x1d7852db, 0x3031d09f, 0x9f348835,
	0xdb1bb527, 0xe8214f79, 0xa0b2cb32, 0x42d9f20a,
	0xaea8b68e, 0xd07b62a1, 0x400e17c6, 0xad6420c8,
	0xeae3f44e, 0xaf4a8f84, 0xf1fab308, 0x8569bef8,
}

const (
	// 999, not 1000: Hashcat's init kernel seeds the chain with MD5(password)
	// and does not count that as a round, so the loop runs salt_iter times and
	// salt_iter is 999.
	encdvMD5Iterations = 999
	// The container header: the libpcap magic byte-reversed, then three zeros.
	encdvKeystreamSkip = 4
	encdvMaxKeys       = 8
	encdvKeychainSize  = 128
	encdvBlockSize     = 16
)

var encdvHeaderMagic = []byte{0xd2, 0xc3, 0xb4, 0xa1}

type encdvRecord struct {
	pbkdf2     bool
	version    int
	nbKeys     int
	iv         []byte
	ct         []byte
	salt       []byte
	iterations int
	keychain   []byte // 128 bytes when the vault has one, nil otherwise
}

func parseENCDataVault(target string) (*encdvRecord, error) {
	t := strings.TrimSpace(target)
	var body string
	e := &encdvRecord{}
	switch {
	case strings.HasPrefix(t, "$encdv-pbkdf2$"):
		e.pbkdf2 = true
		body = strings.TrimPrefix(t, "$encdv-pbkdf2$")
	case strings.HasPrefix(t, "$encdv$"):
		body = strings.TrimPrefix(t, "$encdv$")
	default:
		return nil, errors.New("not an ENCsecurity Datavault record")
	}
	p := strings.Split(body, "$")
	need := 4
	if e.pbkdf2 {
		need = 7
	}
	if len(p) < need {
		return nil, errors.New("ENCsecurity Datavault record is missing fields")
	}
	var err error
	if e.version, err = strconv.Atoi(p[0]); err != nil {
		return nil, errors.New("ENCsecurity Datavault version must be a number")
	}
	if e.nbKeys, err = strconv.Atoi(p[1]); err != nil || e.nbKeys < 1 || e.nbKeys > encdvMaxKeys {
		return nil, errors.New("ENCsecurity Datavault key count is out of range")
	}
	if e.iv, err = hex.DecodeString(p[2]); err != nil || len(e.iv) != 8 {
		return nil, errors.New("ENCsecurity Datavault IV must be 8 hex-encoded bytes")
	}
	if e.ct, err = hex.DecodeString(p[3]); err != nil || len(e.ct) != 8 {
		return nil, errors.New("ENCsecurity Datavault ciphertext must be 8 hex-encoded bytes")
	}
	if e.pbkdf2 {
		saltLen, err := strconv.Atoi(p[4])
		if err != nil || saltLen < 1 {
			return nil, errors.New("ENCsecurity Datavault salt length must be a positive integer")
		}
		if e.salt, err = hex.DecodeString(p[5]); err != nil || len(e.salt) != saltLen {
			return nil, errors.New("ENCsecurity Datavault salt does not match its declared length")
		}
		if e.iterations, err = strconv.Atoi(p[6]); err != nil || e.iterations < 1 {
			return nil, errors.New("ENCsecurity Datavault iterations must be a positive integer")
		}
	}
	// A vault with a keychain carries one more field. Its presence is what
	// decides, not the version number, but the two must agree — a record
	// claiming one and carrying the other is malformed, not something to
	// interpret generously.
	if len(p) > need {
		if e.keychain, err = hex.DecodeString(p[need]); err != nil || len(e.keychain) != encdvKeychainSize {
			return nil, errors.New("ENCsecurity Datavault keychain must be 128 hex-encoded bytes")
		}
	}
	return e, nil
}

// encdvIteratedMD5 is the MD5 derivation: hash the password, then hash the
// digest a thousand times over, XORing every intermediate into the result.
// Only the accumulator survives — the chain itself is discarded.
func encdvIteratedMD5(candidate string) []byte {
	d := md5.Sum([]byte(candidate))
	out := make([]byte, md5.Size)
	for i := 0; i < encdvMD5Iterations; i++ {
		d = md5.Sum(d[:])
		for j := range out {
			out[j] ^= d[j]
		}
	}
	return out
}

// encdvKeyMaterial returns the i-th 16-byte block of derived material, which
// is where both the AES key and the extra per-key IVs come from.
//
// The two derivations expose it differently: PBKDF2 simply produces enough
// output to slice, while the MD5 form has only 16 bytes of accumulator and
// makes each block by XORing it with a different slice of the shipped table.
func (e *encdvRecord) encdvKeyMaterial(derived []byte, i int) []byte {
	out := make([]byte, encdvBlockSize)
	if e.pbkdf2 {
		copy(out, derived[i*encdvBlockSize:])
		return out
	}
	for w := 0; w < 4; w++ {
		v := binary.BigEndian.Uint32(derived[w*4:]) ^ encdvDefaultSalts[i*4+w]
		binary.BigEndian.PutUint32(out[w*4:], v)
	}
	return out
}

// encdvCounterBlock is one AES-CTR keystream block under a set of IVs: the
// product XORs one encryption per key rather than using a single stream.
func encdvCounterBlock(block cipher.Block, ivs [][]byte, counter uint32) []byte {
	sum := make([]byte, encdvBlockSize)
	var in, out [encdvBlockSize]byte
	for _, iv := range ivs {
		for i := range in {
			in[i] = 0
		}
		copy(in[:8], iv)
		binary.BigEndian.PutUint32(in[12:], counter)
		block.Encrypt(out[:], in[:])
		for i := range sum {
			sum[i] ^= out[i]
		}
	}
	return sum
}

// encdvPBKDF2OutputLen is how many bytes of PBKDF2 output a PBKDF2-form
// record needs: enough to cover every block the record will ask for, one
// per key, or the full table when a keychain has to be unwrapped. Shared
// between the scalar path and the lane hasher (pbkdf2_lane_encdatavault.go)
// so the two never drift.
func encdvPBKDF2OutputLen(e *encdvRecord) int {
	if e.keychain != nil {
		return encdvMaxKeys * encdvBlockSize
	}
	return e.nbKeys * encdvBlockSize
}

func verifyENCDataVault(target, candidate string) (bool, error) {
	e, err := parseENCDataVault(target)
	if err != nil {
		return false, err
	}
	var derived []byte
	if e.pbkdf2 {
		derived = pbkdf2.Key([]byte(candidate), e.salt, e.iterations, encdvPBKDF2OutputLen(e), sha256.New)
	} else {
		derived = encdvIteratedMD5(candidate)
	}
	return encdvMatches(e, derived)
}

// encdvMatches is the shared "does this derived key material open the
// vault" check, given either the MD5 form's fixed accumulator or the
// PBKDF2 form's derived output. Used by verifyENCDataVault for its single
// derived value and by the lane hasher for each of a PBKDF2 batch's.
func encdvMatches(e *encdvRecord, derived []byte) (bool, error) {
	key := e.encdvKeyMaterial(derived, 0)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}

	// With a keychain, the derived key does not open the container — it opens
	// the keychain, and the container key is the first block of THAT. The IVs
	// for this stage walk the derived blocks backwards from the last, and the
	// counter starts at 0 here where it starts at 1 for the container.
	if e.keychain != nil {
		ivs := make([][]byte, encdvMaxKeys)
		ivs[0] = make([]byte, 8)
		for i := 1; i < encdvMaxKeys; i++ {
			ivs[i] = e.encdvKeyMaterial(derived, encdvMaxKeys-i)[:8]
		}
		plain := make([]byte, encdvKeychainSize)
		for i := 0; i < encdvKeychainSize/encdvBlockSize; i++ {
			ks := encdvCounterBlock(block, ivs, uint32(i))
			for j := 0; j < encdvBlockSize; j++ {
				plain[i*encdvBlockSize+j] = ks[j] ^ e.keychain[i*encdvBlockSize+j]
			}
		}
		derived = plain
		// From here the keychain plaintext plays the role the derived material
		// played before, and it is already laid out in 16-byte blocks.
		e = &encdvRecord{pbkdf2: true, nbKeys: e.nbKeys, iv: e.iv, ct: e.ct}
		key = e.encdvKeyMaterial(derived, 0)
		if block, err = aes.NewCipher(key); err != nil {
			return false, err
		}
	}

	ivs := make([][]byte, e.nbKeys)
	ivs[0] = e.iv
	for i := 1; i < e.nbKeys; i++ {
		mat := e.encdvKeyMaterial(derived, i)
		iv := make([]byte, 8)
		for j := range iv {
			iv[j] = e.iv[j] ^ mat[j]
		}
		ivs[i] = iv
	}
	ks := encdvCounterBlock(block, ivs, 1)

	plain := make([]byte, 8)
	for i := range plain {
		plain[i] = e.ct[i] ^ ks[encdvKeystreamSkip+i]
	}
	return string(plain[:4]) == string(encdvHeaderMagic) &&
		plain[4] == 0 && plain[5] == 0 && plain[6] == 0, nil
}
