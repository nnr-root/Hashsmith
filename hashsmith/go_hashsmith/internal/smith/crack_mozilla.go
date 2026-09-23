package smith

// Mozilla key3.db and key4.db — Hashcat 26000 and 26100, alongside John's own
// serialisation of key3.db, which crack_john_extended.go already read.
//
// Firefox and Thunderbird keep saved logins under a key wrapped by the master
// password. Both database generations wrap the same 16-byte plaintext, and
// that constant is what makes a guess checkable:
//
//	"password-check" + 0x02 0x02
//
// which is the ASCII string with PKCS#7 padding to one block. Fourteen fixed
// bytes plus two padding bytes is a 2^-128 check, so no further structure is
// needed and none is available.
//
//	key3.db (3DES)  $mozilla$*3DES*<globalSalt>*<entrySalt>*<ciphertext>
//	key4.db (AES)   $mozilla$*AES*<globalSalt>*<entrySalt>*<rounds>*<iv>*<ciphertext>
//	key3.db (John)  $mozilla$*3*20*1*<entrySalt>*11*<oid>*16*<verifier>*20*<globalSalt>
//
// The first and third are the same format written down two ways, so they are
// one type here rather than two. verifyMozilla picks the shape by field count
// and hands John's to the reader that already existed.
//
// The two derivations have nothing in common beyond that check. key4.db is an
// ordinary PBKDF2. key3.db is the older hand-rolled construction: three
// HMAC-SHA1 calls under one key, whose outputs are concatenated into 40 bytes
// and then read as a 24-byte 3DES key and an 8-byte IV — with the middle 8
// bytes of that 40 discarded, which is not a mistake here but what the format
// does.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// mozillaPasswordCheck is the plaintext both generations wrap.
var mozillaPasswordCheck = []byte("password-check\x02\x02")

type mozillaRecord struct {
	aes        bool
	globalSalt []byte
	entrySalt  []byte
	rounds     int
	iv         []byte
	ct         []byte
}

func parseMozilla(target string) (*mozillaRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$mozilla$*") {
		return nil, errors.New("not a Mozilla key3.db/key4.db record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$mozilla$*"), "*")
	m := &mozillaRecord{}
	var err error
	unhex := func(s string, want int) ([]byte, error) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("Mozilla record field is not hex")
		}
		if want > 0 && len(b) != want {
			return nil, errors.New("Mozilla record field has the wrong length")
		}
		return b, nil
	}
	switch {
	case len(p) == 4 && p[0] == "3DES":
		if m.globalSalt, err = unhex(p[1], 0); err != nil {
			return nil, err
		}
		if m.entrySalt, err = unhex(p[2], 0); err != nil {
			return nil, err
		}
		// One 3DES block pair: the check plaintext and nothing else.
		if m.ct, err = unhex(p[3], 16); err != nil {
			return nil, err
		}
	case len(p) == 6 && p[0] == "AES":
		m.aes = true
		if m.globalSalt, err = unhex(p[1], 0); err != nil {
			return nil, err
		}
		if m.entrySalt, err = unhex(p[2], 0); err != nil {
			return nil, err
		}
		if m.rounds, err = strconv.Atoi(p[3]); err != nil || m.rounds < 1 {
			return nil, errors.New("Mozilla key4.db rounds must be a positive integer")
		}
		if m.iv, err = unhex(p[4], aes.BlockSize); err != nil {
			return nil, err
		}
		if m.ct, err = unhex(p[5], aes.BlockSize); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unrecognised Mozilla record shape")
	}
	if len(m.globalSalt) == 0 || len(m.entrySalt) == 0 {
		return nil, errors.New("Mozilla record has an empty salt")
	}
	return m, nil
}

// mozillaEntryKey is SHA1(globalSalt || password), the value both generations
// start from.
func mozillaEntryKey(globalSalt []byte, candidate string) []byte {
	h := sha1.New()
	_, _ = h.Write(globalSalt)
	_, _ = h.Write([]byte(candidate))
	return h.Sum(nil)
}

// mozillaKey3Key reproduces key3.db's key schedule: one HMAC-SHA1 key, three
// messages, 40 bytes of output.
func mozillaKey3Key(m *mozillaRecord, candidate string) []byte {
	hp := mozillaEntryKey(m.globalSalt, candidate)

	chpH := sha1.New()
	_, _ = chpH.Write(hp)
	_, _ = chpH.Write(m.entrySalt)
	chp := chpH.Sum(nil)

	// pes is the entry salt in a fixed 20-byte field, zero-padded. The format
	// hashes the padding, so a shorter salt is not the same as a longer one
	// carrying zeros.
	pes := make([]byte, sha1.Size)
	copy(pes, m.entrySalt)

	mac := func(parts ...[]byte) []byte {
		h := hmac.New(sha1.New, chp)
		for _, p := range parts {
			_, _ = h.Write(p)
		}
		return h.Sum(nil)
	}
	k1 := mac(pes, m.entrySalt)
	tk := mac(pes)
	k2 := mac(tk, m.entrySalt)
	return append(k1, k2...)
}

func verifyMozilla(target, candidate string) (bool, error) {
	// John writes key3.db as eleven fields with a literal "3" where Hashcat
	// writes the cipher name. Telling them apart on that is enough, and it
	// keeps one type reading both rather than inventing a second name for an
	// algorithm that already has one.
	if p := strings.Split(strings.TrimSpace(target), "*"); len(p) == 11 && p[0] == "$mozilla$" && p[1] == "3" {
		return verifyMozillaNSS(target, candidate)
	}
	m, err := parseMozilla(target)
	if err != nil {
		return false, err
	}
	var block cipher.Block
	var iv []byte
	if m.aes {
		ek := mozillaEntryKey(m.globalSalt, candidate)
		key := pbkdf2.Key(ek, m.entrySalt, m.rounds, 32, sha256.New)
		if block, err = aes.NewCipher(key); err != nil {
			return false, err
		}
		iv = m.iv
	} else {
		k := mozillaKey3Key(m, candidate)
		if block, err = des.NewTripleDESCipher(k[:24]); err != nil {
			return false, err
		}
		iv = k[32:40]
	}
	plain := make([]byte, len(m.ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, m.ct)
	return bytes.Equal(plain, mozillaPasswordCheck), nil
}
