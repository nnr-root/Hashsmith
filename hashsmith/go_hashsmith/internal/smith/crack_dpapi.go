package smith

// DPAPI masterkey file — Hashcat 15300, 15310, 15900, 15910.
//
//	$DPAPImk$<version>*<context>*<SID>*<cipher>*<hash>*<rounds>*<IV>*<len>*<blob>
//
// Windows wraps each user's DPAPI master key with a key derived from their
// password. Recovering the password means deriving that key, decrypting the
// blob, and checking its embedded HMAC.
//
// Two things about this format cost more to discover than the rest combined.
//
// FIRST: the key derivation is not PBKDF2, though it looks like it. RFC 2898
// hashes the previous block and XORs the result into an accumulator:
//
//	U(n+1) = PRF(U(n));  out ^= U(n+1)
//
// DPAPI feeds the ACCUMULATOR back instead:
//
//	out = out ^ PRF(out)
//
// Every implementation that unlocks real masterkey files reproduces this,
// because it is what Windows does. Using a correct PBKDF2 here produces a key
// that is wrong for every input, with nothing to indicate which stage failed —
// the reason an earlier attempt at this format burned through a couple of
// hundred blind parameter combinations without converging. The answer was in
// hashcat's loop kernel, one identifier wide.
//
// SECOND: the SID is hashed as UTF-16LE, and how many trailing NUL bytes it
// carries depends on the context, inconsistently:
//
//	context 1, 2   HMAC-SHA1 over the SID plus ONE NUL character (two bytes)
//	context 3      PBKDF2-SHA256 over the BARE SID, no NUL at all, then
//	               HMAC-SHA1 over the SID plus one NUL character
//
// hashcat encodes that difference as `SID_len` in two stages and `SID_len + 2`
// in the third. It is not a rule that can be guessed from the format's shape.
//
// Contexts are how the password reaches the derivation at all:
//
//	1  local account        SHA-1 of the UTF-16LE password
//	2  domain account       MD4 of the UTF-16LE password (the NTLM hash)
//	3  Windows 10 1607+     NTLM, then PBKDF2-SHA256 twice — 10000 rounds to
//	                        32 bytes, then 1 round to 16

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"crypto/sha256"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

const (
	dpapiPrefix = "$DPAPImk$"
	// Context 3's two fixed PBKDF2-SHA256 stages. Windows hard-codes both.
	dpapiContext3Rounds1 = 10000
	dpapiContext3Len1    = 32
	dpapiContext3Rounds2 = 1
	dpapiContext3Len2    = 16
	dpapiMasterKeyLen    = 64
	dpapiHMACSaltLen     = 16
	dpapiCompareLen      = 16
	dpapiMaxRounds       = 50_000_000
)

// dpapiDeriveKey is DPAPI's PBKDF2 variant: each round hashes the running
// accumulator rather than the previous block. See the note above.
func dpapiDeriveKey(key, salt []byte, rounds, keyLen int, newHash func() hash.Hash) []byte {
	out := make([]byte, 0, keyLen+newHash().Size())
	for block := 1; len(out) < keyLen; block++ {
		ctr := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		h := hmac.New(newHash, key)
		_, _ = h.Write(salt)
		_, _ = h.Write(ctr)
		derived := h.Sum(nil)
		for r := 1; r < rounds; r++ {
			a := hmac.New(newHash, key)
			_, _ = a.Write(derived)
			actual := a.Sum(nil)
			for i := range derived {
				derived[i] ^= actual[i]
			}
		}
		out = append(out, derived...)
	}
	return out[:keyLen]
}

// dpapiUserKey turns the password into the key the blob's derivation uses.
func dpapiUserKey(candidate, sid string, context int) ([]byte, error) {
	wide := utf16leBytes(sid)
	// One NUL *character*, so two bytes.
	withNUL := append(append([]byte{}, wide...), 0, 0)
	pw := utf16leBytes(candidate)

	var pre []byte
	switch context {
	case 1:
		sum := sha1.Sum(pw)
		pre = sum[:]
	case 2:
		h := md4.New()
		_, _ = h.Write(pw)
		pre = h.Sum(nil)
	case 3:
		h := md4.New()
		_, _ = h.Write(pw)
		ntlm := h.Sum(nil)
		// Note the BARE SID here — no NUL — where the HMAC below uses one.
		stage1 := pbkdf2.Key(ntlm, wide, dpapiContext3Rounds1, dpapiContext3Len1, sha256.New)
		pre = pbkdf2.Key(stage1, wide, dpapiContext3Rounds2, dpapiContext3Len2, sha256.New)
	default:
		return nil, errors.New("unsupported DPAPI context " + strconv.Itoa(context))
	}
	mac := hmac.New(sha1.New, pre)
	_, _ = mac.Write(withNUL)
	return mac.Sum(nil), nil
}

func verifyDPAPIMasterKey(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, dpapiPrefix) {
		return false, errors.New("not a DPAPI masterkey record")
	}
	f := strings.Split(strings.TrimPrefix(t, dpapiPrefix), "*")
	if len(f) != 9 {
		return false, errors.New("DPAPI masterkey record must have 9 fields")
	}
	version, err := strconv.Atoi(f[0])
	if err != nil || (version != 1 && version != 2) {
		return false, errors.New("DPAPI masterkey version must be 1 or 2")
	}
	context, err := strconv.Atoi(f[1])
	if err != nil || context < 1 || context > 3 {
		return false, errors.New("DPAPI context must be 1, 2 or 3")
	}
	sid := f[2]
	if sid == "" {
		return false, errors.New("DPAPI record carries no SID")
	}
	cipherName, hashName := f[3], f[4]
	rounds, err := strconv.Atoi(f[5])
	if err != nil || rounds < 1 || rounds > dpapiMaxRounds {
		return false, errors.New("DPAPI round count is out of range")
	}
	iv, err := hex.DecodeString(f[6])
	if err != nil || len(iv) != 16 {
		return false, errors.New("DPAPI IV must be 16 hex-encoded bytes")
	}
	blob, err := hex.DecodeString(f[8])
	if err != nil {
		return false, errors.New("DPAPI blob must be hex")
	}

	// The cipher and hash fields decide the sizes; the version must agree.
	var (
		newHash  func() hash.Hash
		keyLen   int
		ivLen    int
		makeAES  bool
		blockLen int
	)
	switch {
	case version == 1 && cipherName == "des3" && hashName == "sha1":
		newHash, keyLen, ivLen, blockLen = sha1.New, 24, 8, des.BlockSize
	case version == 2 && cipherName == "aes256" && hashName == "sha512":
		newHash, keyLen, ivLen, makeAES, blockLen = sha512.New, 32, 16, true, aes.BlockSize
	default:
		return false, errors.New("unsupported DPAPI cipher/hash combination " + cipherName + "/" + hashName)
	}
	if len(blob) < dpapiHMACSaltLen+dpapiCompareLen+dpapiMasterKeyLen || len(blob)%blockLen != 0 {
		return false, errors.New("DPAPI blob is not a whole number of cipher blocks")
	}

	userKey, err := dpapiUserKey(candidate, sid, context)
	if err != nil {
		return false, err
	}
	derived := dpapiDeriveKey(userKey, iv, rounds, keyLen+ivLen, newHash)

	var block cipher.Block
	if makeAES {
		block, err = aes.NewCipher(derived[:keyLen])
	} else {
		block, err = des.NewTripleDESCipher(derived[:keyLen])
	}
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(blob))
	cipher.NewCBCDecrypter(block, derived[keyLen:keyLen+ivLen]).CryptBlocks(plain, blob)

	hmacSalt := plain[:dpapiHMACSaltLen]
	expected := plain[dpapiHMACSaltLen : dpapiHMACSaltLen+dpapiCompareLen]
	masterKey := plain[len(plain)-dpapiMasterKeyLen:]

	inner := hmac.New(newHash, userKey)
	_, _ = inner.Write(hmacSalt)
	outer := hmac.New(newHash, inner.Sum(nil))
	_, _ = outer.Write(masterKey)
	return hmac.Equal(outer.Sum(nil)[:dpapiCompareLen], expected), nil
}
