package main

// MultiBit Classic and Bisq wallets — Hashcat 27700 and 29800.
//
//	$multibit$3*<N>*<r>*<p>*<salt>*<iv || ciphertext>
//	$bisq$3*<N>*<r>*<p>*<salt>*<iv || ciphertext>
//
// scrypt to a 256-bit key, then one AES-256-CBC block. The two differ only in
// the prefix and in the work factors their tools choose — Bisq's example uses
// p=6 where MultiBit's uses p=1 — so one implementation reads both.
//
// The check is that the block decrypts to sixteen bytes of 0x10: PKCS#7
// padding for a message that ended exactly on a block boundary, the same
// tell SecureZIP leaves. That is 2^-128 and needs no plaintext.
//
// scrypt does not see the password's bytes. Both wallets are Java programs and
// hand it String.getBytes("UTF-16BE"), so an ASCII passphrase arrives with a
// zero byte before every character. Passing the raw bytes derives a key that
// is wrong in a way nothing reports.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// multibitMaxMemory caps what a record may ask scrypt to allocate. The
// parameters come from the file being cracked, so a hostile record could
// otherwise name 4 GiB and take the process down; 1 GiB is far above any
// wallet in the wild and far below trouble.
const multibitMaxMemory = 1 << 30

func verifyMultiBit(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	var body string
	switch {
	case strings.HasPrefix(t, "$multibit$"):
		body = strings.TrimPrefix(t, "$multibit$")
	case strings.HasPrefix(t, "$bisq$"):
		body = strings.TrimPrefix(t, "$bisq$")
	default:
		return false, errors.New("not a MultiBit or Bisq wallet record")
	}
	p := strings.Split(body, "*")
	if len(p) != 6 || p[0] != "3" {
		return false, errors.New("unsupported MultiBit/Bisq record version")
	}
	num := func(s string) (int, error) {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			return 0, errors.New("MultiBit/Bisq scrypt parameter must be a positive integer")
		}
		return v, nil
	}
	n, err := num(p[1])
	if err != nil {
		return false, err
	}
	r, err := num(p[2])
	if err != nil {
		return false, err
	}
	par, err := num(p[3])
	if err != nil {
		return false, err
	}
	if n&(n-1) != 0 {
		return false, errors.New("MultiBit/Bisq scrypt N must be a power of two")
	}
	if int64(n)*int64(r)*128 > multibitMaxMemory {
		return false, errors.New("MultiBit/Bisq scrypt parameters ask for an implausible amount of memory")
	}
	salt, err := hex.DecodeString(p[4])
	if err != nil || len(salt) == 0 {
		return false, errors.New("MultiBit/Bisq salt is not hex")
	}
	data, err := hex.DecodeString(p[5])
	if err != nil || len(data) != 2*aes.BlockSize {
		return false, errors.New("MultiBit/Bisq payload must be 32 hex-encoded bytes")
	}

	key, err := scrypt.Key(utf16be(candidate), salt, n, r, par, 32)
	if err != nil {
		return false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(block, data[:aes.BlockSize]).CryptBlocks(plain, data[aes.BlockSize:])
	return bytes.Equal(plain, secureZIPPadBlock), nil
}

// MultiBit HD — Hashcat 22700.
//
//	$multibit$2*<iv>*<block one>*<block two>
//
// HD hardcodes what Classic stores: the scrypt salt and work factors are baked
// into the wallet software, so the record carries only ciphertext. It also
// carries two candidate blocks, encrypted under two different IVs — one from
// the record and one also hardcoded — because the wallet file has two places
// the header can sit and neither is marked. Hashcat tries both and so does
// this; either matching is a match.
//
// The plaintext test is bitcoinj's serialisation header rather than padding:
// a 0x0a tag, a length byte, the literal "org.", and then eight characters
// drawn only from lower case and '.'. On a correct guess the example record
// decrypts to "\n\x16org.bitcoin.pr" — the start of "org.bitcoin.production".

var (
	// multibitHDSalt is the wallet's fixed scrypt salt.
	multibitHDSalt = []byte{0x35, 0x51, 0x03, 0x80, 0x75, 0xa3, 0xb0, 0xc5}
	// multibitHDIV is the fixed CBC IV used for the second candidate block.
	multibitHDIV = []byte{
		0xa3, 0x44, 0x39, 0x1f, 0x53, 0x83, 0x11, 0xb3,
		0x29, 0x54, 0x86, 0x16, 0xc4, 0x89, 0x72, 0x3e,
	}
)

const (
	multibitHDN = 16384
	multibitHDR = 8
	multibitHDP = 1
)

// bitcoinjHeaderValid reports whether a decrypted block looks like the start of
// a bitcoinj wallet: tag, length, "org.", then a package name.
func bitcoinjHeaderValid(p []byte) bool {
	if len(p) < 14 || p[0] != 0x0a || p[1] > 0x7f {
		return false
	}
	if string(p[2:6]) != "org." {
		return false
	}
	for _, c := range p[6:14] {
		if c != '.' && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func verifyMultiBitHD(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$multibit$2*") {
		return false, errors.New("not a MultiBit HD record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$multibit$"), "*")
	if len(p) != 4 {
		return false, errors.New("MultiBit HD record must be $multibit$2*<iv>*<block>*<block>")
	}
	fields := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		b, err := hex.DecodeString(p[i+1])
		if err != nil || len(b) != aes.BlockSize {
			return false, errors.New("MultiBit HD fields must each be 16 hex-encoded bytes")
		}
		fields[i] = b
	}

	key, err := scrypt.Key(utf16be(candidate), multibitHDSalt, multibitHDN, multibitHDR, multibitHDP, 32)
	if err != nil {
		return false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	for _, c := range [][2][]byte{{fields[1], fields[0]}, {fields[2], multibitHDIV}} {
		plain := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, c[1]).CryptBlocks(plain, c[0])
		if bitcoinjHeaderValid(plain) {
			return true, nil
		}
	}
	return false, nil
}
