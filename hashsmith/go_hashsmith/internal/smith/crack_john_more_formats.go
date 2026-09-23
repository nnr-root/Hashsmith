package smith

// Three more of John's formats, each read from its own source rather than
// guessed at.
//
//	$siemens-s7$  HMAC-SHA1 under sha1(password), over a captured challenge
//	$BitShares$   AES-256-CBC under sha512(password), checked on its padding
//	$palshop$     MD5 over the hex of an MD5 and a SHA-1, spliced
//
// Palshop is worth a word. An earlier pass through these formats put it
// through a bounded sweep of the obvious constructions and found nothing,
// and that is recorded where it was written. This is why that result meant
// only what it said: the construction is a fifty-one-byte string assembled
// from the hex of half an MD5 and most of a SHA-1, starting at a NIBBLE
// boundary and with its last character overwritten. No sweep of orderings and
// separators reaches a thing like that. Reading the source does.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

// ── Siemens S7 ────────────────────────────────────────────────────────────────

// "$siemens-s7$<type>$<20-byte challenge>$<20-byte response>"
//
// The S7 protocol authenticates with HMAC-SHA1 over a challenge, keyed on the
// SHA-1 of the password rather than on the password itself. That is the whole
// of it: one HMAC per candidate, and the challenge is visible to anyone who
// can see the link to the PLC.
const siemensS7Prefix = "$siemens-s7$"

func siemensS7Fields(target string) (challenge, response []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, siemensS7Prefix) {
		return nil, nil, errors.New("not a Siemens S7 record")
	}
	f := strings.Split(t[len(siemensS7Prefix):], "$")
	if len(f) != 3 {
		return nil, nil, errors.New("an S7 record is <type>$<challenge>$<response>")
	}
	if challenge, err = decodeExactHex(f[1], sha1.Size, "S7 challenge"); err != nil {
		return nil, nil, err
	}
	if response, err = decodeExactHex(f[2], sha1.Size, "S7 response"); err != nil {
		return nil, nil, err
	}
	return challenge, response, nil
}

func verifySiemensS7(target, candidate string) (bool, error) {
	challenge, response, err := siemensS7Fields(target)
	if err != nil {
		return false, err
	}
	key := sha1.Sum([]byte(candidate))
	mac := hmac.New(sha1.New, key[:])
	_, _ = mac.Write(challenge)
	return hmac.Equal(mac.Sum(nil), response), nil
}

func isSiemensS7(target string) bool {
	_, _, err := siemensS7Fields(target)
	return err == nil
}

// ── BitShares ─────────────────────────────────────────────────────────────────

// "$BitShares$<type>*<ciphertext>"
//
// Type 0 is the wallet file's own encryption: AES-256-CBC with the key taken
// straight from SHA-512 of the password and the IV stored in front of the
// ciphertext. There is no iteration count and no salt, so a candidate costs
// one SHA-512 and one AES block — as cheap as an unsalted digest, on a wallet.
//
// What identifies a correct password is the padding. The plaintext's last
// block is sixteen bytes of 0x10, PKCS#7's encoding of a full block of
// padding, so decrypting one block and reading it is the whole check. Sixteen
// bytes have to agree, which is a stronger test than most verifiers get.
//
// The block to decrypt is the LAST one, with the one before it as its CBC
// initialisation vector — not the first two, which is what a reading of the
// record as "IV then ciphertext" suggests and what John's own type-0 branch
// looks like it does. Decrypting the first block of this format's published
// vector gives 4c1900745ecfb143..., and the last gives sixteen 0x10 bytes.
// The padding is at the end of a message, so the end is where to look.
//
// Type 1 wraps a secp256k1 private key and needs curve arithmetic to check;
// it is declined by name rather than answered wrongly.
const bitsharesPrefix = "$BitShares$"

func bitsharesFields(target string) (kind int, ct []byte, err error) {
	t := strings.TrimSpace(target)
	if len(t) < len(bitsharesPrefix) || !strings.EqualFold(t[:len(bitsharesPrefix)], bitsharesPrefix) {
		return 0, nil, errors.New("not a BitShares record")
	}
	k, body, ok := strings.Cut(t[len(bitsharesPrefix):], "*")
	if !ok {
		return 0, nil, errors.New("a BitShares record is <type>*<ciphertext>")
	}
	switch k {
	case "0":
		kind = 0
	case "1":
		return 0, nil, errors.New("this BitShares record wraps a secp256k1 key, which Hashsmith does not check")
	default:
		return 0, nil, errors.New("unknown BitShares record type")
	}
	if ct, err = hex.DecodeString(body); err != nil || len(ct) < 32 || len(ct)%16 != 0 {
		return 0, nil, errors.New("a BitShares ciphertext is whole AES blocks, an IV and at least one more")
	}
	return kind, ct, nil
}

func verifyBitShares(target, candidate string) (bool, error) {
	_, ct, err := bitsharesFields(target)
	if err != nil {
		return false, err
	}
	key := sha512.Sum512([]byte(candidate))
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return false, err
	}
	var out [16]byte
	n := len(ct)
	cipher.NewCBCDecrypter(block, ct[n-32:n-16]).CryptBlocks(out[:], ct[n-16:])
	for _, b := range out {
		if b != 0x10 {
			return false, nil
		}
	}
	return true, nil
}

func isBitShares(target string) bool {
	_, _, err := bitsharesFields(target)
	return err == nil
}

// ── Palshop ───────────────────────────────────────────────────────────────────

// Fifty-one hex characters, with or without a "$palshop$" in front. The odd
// length is the giveaway: no digest is fifty-one hex characters, because no
// digest is twenty-five and a half bytes.
//
// It is odd because the record is a hex string spliced out of the middle of
// two others. MD5 and SHA-1 of the password are laid end to end; the hex of
// bytes 5 through 30 of that is taken, starting from the LOW nibble of byte 5
// so the string begins mid-byte; and the final character is replaced with the
// high nibble of the first MD5 byte. Those fifty-one characters are then run
// through MD5 again.
//
// Only ten bytes of that second digest are stored, which is why the record is
// checked on its characters 1 to 20 and the rest is along for the ride.
const palshopPrefix = "$palshop$"

const palshopRecordLen = 51

func palshopPayload(target string) (string, bool) {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(t, palshopPrefix)
	if len(t) != palshopRecordLen || !isHex(t) {
		return "", false
	}
	return strings.ToLower(t), true
}

func verifyPalshop(target, candidate string) (bool, error) {
	rec, ok := palshopPayload(target)
	if !ok {
		return false, errors.New("a Palshop record is fifty-one hex characters")
	}
	want, err := hex.DecodeString(rec[1:21])
	if err != nil {
		return false, errors.New("a Palshop record is fifty-one hex characters")
	}

	m := md5.Sum([]byte(candidate))
	s := sha1.Sum([]byte(candidate))
	var joined [md5.Size + sha1.Size]byte
	copy(joined[:], m[:])
	copy(joined[md5.Size:], s[:])

	const hexDigits = "0123456789abcdef"
	spliced := make([]byte, 0, palshopRecordLen)
	spliced = append(spliced, hexDigits[joined[5]&0xF])
	for i := 6; i < 31; i++ {
		spliced = append(spliced, hexDigits[joined[i]>>4], hexDigits[joined[i]&0xF])
	}
	spliced[len(spliced)-1] = hexDigits[joined[0]>>4]

	second := md5.Sum(spliced)
	return hmac.Equal(second[6:16], want), nil
}

func isPalshop(target string) bool { _, ok := palshopPayload(target); return ok }
