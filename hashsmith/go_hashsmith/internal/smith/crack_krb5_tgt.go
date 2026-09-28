package smith

// A Kerberos 5 TGT encrypted under a 3DES key, etype 16.
//
//	$krb5$<user>$<realm>$<encrypted ticket>
//
// The record is a captured ticket and there is no digest in it. A password is
// right when the decrypted ticket contains the word "krbtgt" — which it does
// because the ticket names the service it is for, and the ticket-granting
// service is called krbtgt.
//
// The derivation is RFC 3961's, and it is the one place in Kerberos where the
// design shows its age most clearly. The password, realm and username are
// concatenated and "n-folded" — a construction that rotates the string right
// thirteen bits at a time and adds the rotations together with end-around
// carry, which mixes a short string into a fixed width without a hash
// function, because in 1993 a hash was not assumed. The folded bits become a
// 3DES key by having a parity bit inserted after every seventh, and that key
// is then put through the DK function twice: once with the literal string
// "kerberos" and once with the constant 00 00 00 03 AA, which is what tells a
// key derived for encryption apart from one derived for signing.

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"errors"
	"strings"
)

const krb5TGTPrefix = "$krb5$"

// krb5DeriveConstant is the usage constant RFC 3961 assigns to this key.
var krb5DeriveConstant = []byte{0x00, 0x00, 0x00, 0x03, 0xAA}

// krb5NFold spreads len(in) bytes over size bytes by repeated rotation and
// end-around addition. It is not a hash: it is reversible in principle and
// exists only to change a length.
func krb5NFold(in []byte, size int) []byte {
	out := make([]byte, size)
	if len(in) == 0 || size == 0 {
		return out
	}
	maxlen := 2 * size
	if 2*len(in) > maxlen {
		maxlen = 2 * len(in)
	}
	tmp := make([]byte, maxlen)
	buf := append([]byte(nil), in...)
	l := 0
	for {
		copy(tmp[l:], buf)
		l += len(buf)
		krb5RotateRight13(buf, len(buf)*8)
		for l >= size {
			krb5AddWithCarry(out, tmp[:size])
			l -= size
			if l == 0 {
				break
			}
			copy(tmp, tmp[size:size+l])
		}
		if l == 0 {
			break
		}
	}
	return out
}

// krb5RotateRight13 rotates a bit string right by thirteen places, in place.
func krb5RotateRight13(buf []byte, lenBits int) {
	if lenBits == 0 {
		return
	}
	bytesLen := (lenBits + 7) / 8
	tmp := make([]byte, bytesLen)
	copy(tmp, buf[:bytesLen])
	if lbit := lenBits % 8; lbit != 0 {
		tmp[bytesLen-1] &= byte(0xff) << uint(8-lbit)
		for i := lbit; i < 8; i += lenBits {
			tmp[bytesLen-1] |= buf[0] >> uint(i)
		}
	}
	for i := 0; i < bytesLen; i++ {
		bits := 13 % lenBits
		bb := 8*i - bits
		for bb < 0 {
			bb += lenBits
		}
		b1, s1 := bb/8, bb%8
		var s2 int
		if bb+8 > bytesLen*8 {
			s2 = (lenBits + 8 - s1) % 8
		} else {
			s2 = 8 - s1
		}
		b2 := (b1 + 1) % bytesLen
		buf[i] = tmp[b1]<<uint(s1) | tmp[b2]>>uint(s2)
	}
}

// krb5AddWithCarry adds b into a as big-endian numbers, carrying round the end
// rather than off it.
func krb5AddWithCarry(a, b []byte) {
	carry := 0
	for i := len(a) - 1; i >= 0; i-- {
		x := int(a[i]) + int(b[i]) + carry
		carry = x >> 8
		a[i] = byte(x)
	}
	for i := len(a) - 1; carry != 0 && i >= 0; i-- {
		x := int(a[i]) + carry
		carry = x >> 8
		a[i] = byte(x)
	}
}

// krb5DES3Postproc turns 21 bytes of folded material into a 24-byte 3DES key:
// seven bits of each byte, with the eighth carrying the parity bits gathered
// from the seven before it.
func krb5DES3Postproc(k []byte) []byte {
	out := make([]byte, 24)
	for i := 0; i < 3; i++ {
		for j := 0; j < 7; j++ {
			out[8*i+j] = k[7*i+j]
		}
		var foo byte
		for j := 6; j >= 0; j-- {
			foo |= k[7*i+j] & 1
			foo <<= 1
		}
		out[8*i+7] = foo
	}
	desSetOddParity(out[0:8])
	desSetOddParity(out[8:16])
	desSetOddParity(out[16:24])
	return out
}

// krb5DeriveKey is RFC 3961's DK: fold the constant to one block, then run it
// through 3DES in CBC with the current key, chaining until there are enough
// bits, and turn the result back into a key.
func krb5DeriveKey(key, constant []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	const nblocks = 3
	k := make([]byte, nblocks*des.BlockSize)
	copy(k, krb5NFold(constant, des.BlockSize))
	for i := 0; i < nblocks; i++ {
		if i > 0 {
			copy(k[i*des.BlockSize:], k[(i-1)*des.BlockSize:i*des.BlockSize])
		}
		// Each block is encrypted with a zero IV, which makes this ECB in
		// everything but name; the chaining is the copy above.
		block.Encrypt(k[i*des.BlockSize:(i+1)*des.BlockSize], k[i*des.BlockSize:(i+1)*des.BlockSize])
	}
	return krb5DES3Postproc(k), nil
}

// krb5StringToKey3DES is the whole derivation, password through to ticket key.
func krb5StringToKey3DES(user, realm, password string) ([]byte, error) {
	folded := krb5NFold([]byte(password+realm+user), 21)
	key := krb5DES3Postproc(folded)
	key, err := krb5DeriveKey(key, []byte("kerberos"))
	if err != nil {
		return nil, err
	}
	return krb5DeriveKey(key, krb5DeriveConstant)
}

func krb5TGTFields(target string) (user, realm string, ticket []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, krb5TGTPrefix) {
		return "", "", nil, errors.New("not a Kerberos 5 TGT record")
	}
	f := strings.Split(t[len(krb5TGTPrefix):], "$")
	if len(f) != 3 || f[0] == "" || f[1] == "" {
		return "", "", nil, errors.New("a $krb5$ record is <user>$<realm>$<ticket>")
	}
	if ticket, err = hex.DecodeString(f[2]); err != nil {
		return "", "", nil, errors.New("a Kerberos ticket is hex")
	}
	// A captured ticket is not padded to the cipher's block — the record
	// carries whatever was on the wire, and the last few bytes are usually a
	// partial block. Everything up to the last whole block is what the search
	// below reads, which is ample for a six-character marker.
	if len(ticket) < 2*des.BlockSize {
		return "", "", nil, errors.New("a Kerberos 5 ticket is longer than two DES blocks")
	}
	return f[0], f[1], ticket, nil
}

func verifyKrb5TGT(target, candidate string) (bool, error) {
	user, realm, ticket, err := krb5TGTFields(target)
	if err != nil {
		return false, err
	}
	key, err := krb5StringToKey3DES(user, realm, candidate)
	if err != nil {
		return false, err
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ticket))
	iv := make([]byte, des.BlockSize)
	prev := iv
	for off := 0; off+des.BlockSize <= len(ticket); off += des.BlockSize {
		block.Decrypt(plain[off:off+des.BlockSize], ticket[off:off+des.BlockSize])
		for i := 0; i < des.BlockSize; i++ {
			plain[off+i] ^= prev[i]
		}
		prev = ticket[off : off+des.BlockSize]
	}
	return bytes.Contains(plain, []byte("krbtgt")), nil
}

func isKrb5TGT(target string) bool {
	_, _, _, err := krb5TGTFields(target)
	return err == nil
}
