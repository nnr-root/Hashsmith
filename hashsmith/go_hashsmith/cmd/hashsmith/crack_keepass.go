package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"hashsmith-go/internal/argon2d"
)

// ── KeePass database (KDBX 1 & 2, AES-KDF) ─────────────────────────────────────
//
// Cracks the $keepass$ hash produced by keepass2smith for AES-KDF databases
// (KDBX4's Argon2 KDF is not covered here).
//
//   KDBX1: $keepass$*1*<rounds>*<algo>*<masterSeed>*<transformSeed>*<encIV>*
//          <contentsHash>*<inline>*<dataSize>*<encData>
//   KDBX2: $keepass$*2*<rounds>*<?>*<masterSeed>*<transformSeed>*<encIV>*
//          <expectedStartBytes>*<firstEncryptedBytes>
//
// Verified against known KeePass KDBX example hashes.

func verifyKeePass(targetHash, candidate string) (bool, error) {
	return verifyKeePassMode(targetHash, candidate, false)
}

// verifyKeePassKeyfile is the keyfile-only variant (Hashcat 29700), where the
// credential being recovered is the keyfile's own 32-byte key rather than a
// password.
//
// The candidate is the key's HEXADECIMAL spelling and is decoded to bytes
// before hashing — hashcat marks this mode's plaintext as hex, and the
// composite is SHA256 of the raw key, not of the 64 characters that spell it.
// Confirmed against hashcat's own example record: hashing the hex text, or
// double-hashing either form, all decrypt to the wrong stream-start bytes,
// and only SHA256 of the decoded key reproduces them.
//
// A candidate that is not valid hex simply cannot be this credential, so it is
// rejected rather than raised as an error — a wordlist is expected to contain
// entries that do not fit.
func verifyKeePassKeyfile(targetHash, candidate string) (bool, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(candidate))
	if err != nil {
		return false, nil
	}
	return verifyKeePassMode(targetHash, string(raw), true)
}

func verifyKeePassMode(targetHash, candidate string, keyfileOnly bool) (bool, error) {
	p := strings.Split(targetHash, "*")
	if len(p) < 8 || p[0] != "$keepass$" {
		return false, errors.New("invalid keepass hash format")
	}
	switch p[1] {
	case "1":
		return verifyKeePass1(p, candidate)
	case "2":
		return verifyKeePass2(p, candidate, keyfileOnly)
	case "4":
		return verifyKeePass4(p, candidate)
	}
	return false, errors.New("unsupported keepass version (want 1, 2 or 4)")
}

// keepassComposite builds the KDBX composite key, which is what the AES-KDF
// then transforms.
//
// KeePass composes its key from the credentials actually present, and the
// composition CHANGES shape depending on which are there. Getting this wrong
// costs nothing at parse time and everything at verification time: the KDF
// still runs to completion and simply produces the wrong master key, so the
// correct password is reported as not found.
//
//   - password only      SHA256(SHA256(password))
//   - password + keyfile SHA256(SHA256(password) || keyfileKey)   — note that
//     the outer wrap of the password-only form is NOT applied as well; the
//     keyfile concatenation replaces it
//   - keyfile only       SHA256(keyfileKey)
//
// Taken from hashcat's m13400-pure.cl and m29700-pure.cl, whose init kernels
// branch on keyfile_len in exactly this way.
func keepassComposite(candidate string, keyfile []byte, keyfileOnly bool) []byte {
	inner := sha256.Sum256([]byte(candidate))
	if keyfileOnly {
		return inner[:]
	}
	if len(keyfile) > 0 {
		h := sha256.New()
		h.Write(inner[:])
		h.Write(keyfile)
		return h.Sum(nil)
	}
	outer := sha256.Sum256(inner[:])
	return outer[:]
}

// keepassKeyfileFromRecord reads the optional inline keyfile a KDBX 2/3 record
// may carry after its verification fields: *<inline flag>*<hex length>*<hex>.
func keepassKeyfileFromRecord(p []string) ([]byte, error) {
	if len(p) < 12 {
		return nil, nil
	}
	if p[9] != "1" {
		return nil, nil // not an inline keyfile
	}
	kf, err := hex.DecodeString(p[11])
	if err != nil {
		return nil, errors.New("invalid keepass inline keyfile")
	}
	return kf, nil
}

// keepassMasterKey performs the AES-KDF: transform the composite key with
// transformSeed for `rounds`, hash it, then combine with the master seed.
func keepassMasterKey(composite, transformSeed, masterSeed []byte, rounds int) ([]byte, error) {
	block, err := aes.NewCipher(transformSeed)
	if err != nil {
		return nil, errors.New("invalid keepass transform seed")
	}
	transformed := make([]byte, len(composite))
	copy(transformed, composite)
	// AES-ECB encrypt both 16-byte halves, `rounds` times.
	for i := 0; i < rounds; i++ {
		block.Encrypt(transformed[0:16], transformed[0:16])
		block.Encrypt(transformed[16:32], transformed[16:32])
	}
	th := sha256.Sum256(transformed)

	h := sha256.New()
	h.Write(masterSeed)
	h.Write(th[:])
	return h.Sum(nil), nil
}

// verifyKeePass1 decrypts the payload and compares SHA-256 of the plaintext to
// the stored contents hash.
func verifyKeePass1(p []string, candidate string) (bool, error) {
	// $keepass$*1*rounds*algo*masterSeed*transformSeed*encIV*contentsHash*inline*size*data
	if len(p) < 11 {
		return false, errors.New("invalid keepass1 hash format")
	}
	rounds := atoiDefault(p[2], 0)
	// The cipher selector is only ever 0 (AES) or 1 (Twofish); John puts 124
	// there — the size of a KDB1 header — and its own parser reads anything
	// that is not 1 as AES. Following that exactly costs nothing: the check
	// below compares all 32 bytes of a SHA-256, so a mis-read cipher can only
	// fail to crack, never name a wrong password.
	if atoiDefault(p[3], 0) == 1 {
		return false, errors.New("keepass1: only AES is supported, and this record names Twofish")
	}
	masterSeed, e1 := hex.DecodeString(p[4])
	transformSeed, e2 := hex.DecodeString(p[5])
	encIV, e3 := hex.DecodeString(p[6])
	contentsHash, e4 := hex.DecodeString(p[7])
	encData, e5 := hex.DecodeString(p[10])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return false, errors.New("invalid keepass1 hex fields")
	}
	if len(encData) == 0 || len(encData)%16 != 0 || len(encIV) < 16 {
		return false, errors.New("keepass1 encrypted data not block-aligned")
	}

	// KDBX1 password-only composite key = SHA256(password).
	pw := sha256.Sum256([]byte(candidate))
	master, err := keepassMasterKey(pw[:], transformSeed, masterSeed, rounds)
	if err != nil {
		return false, err
	}

	block, err := aes.NewCipher(master)
	if err != nil {
		return false, err
	}
	pt := make([]byte, len(encData))
	cipher.NewCBCDecrypter(block, encIV[:16]).CryptBlocks(pt, encData)

	// Strip PKCS#7 padding, then SHA-256 the content.
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > 16 || pad > len(pt) {
		return false, nil
	}
	content := pt[:len(pt)-pad]
	sum := sha256.Sum256(content)
	return equalConst(sum[:], contentsHash), nil
}

// verifyKeePass4 derives the Argon2 transformed key and checks the KDBX4 header
// HMAC — no payload decryption required.
// keepass4Params reads the Argon2 parameters out of a KDBX4 record.
//
// There are two serialisations in circulation and they are NOT compatible:
// keepass2smith names the variant in a letter and puts parallelism before the
// Argon2 version, while Hashcat's 34300 writes the iteration count first,
// identifies the variant by the KDBX KDF UUID, and puts the version before
// parallelism. Both are eleven fields, so length cannot tell them apart.
//
// What can is field 2: a letter in one, a number in the other. Reading the
// wrong layout is silent — the KDF still completes and simply yields the wrong
// master key, so a correct password is reported as not found — which is why
// the two are separated here rather than guessed at.
//
// The UUIDs are KeePass's own: Argon2d is EF636DDF-8C29-444B-91F7-A9A403E30A0C
// and Argon2id is 9E298B19-56DB-4773-B23D-FC3EC6F0A1E6, and Hashcat writes the
// first four bytes of whichever applies.
//
// The two also disagree about the last thing anyone would check: Hashcat
// writes the MASTER SEED first and the Argon2 salt second, keepass2smith the
// other way round. Both are 32 bytes of hex, so nothing about the record
// betrays the swap — it shows up only as a password that will not verify.
type keepass4Layout struct {
	argon            string
	t, memBytes, par int
	saltIdx, seedIdx int
}

func keepass4Params(p []string) (keepass4Layout, error) {
	switch p[2] {
	case "d", "id":
		return keepass4Layout{
			argon: p[2], t: atoiDefault(p[3], 0), memBytes: atoiDefault(p[4], 0),
			par: atoiDefault(p[5], 0), saltIdx: 7, seedIdx: 8,
		}, nil
	}
	var argon string
	switch strings.ToLower(p[3]) {
	case "ef636ddf":
		argon = "d"
	case "9e298b19":
		argon = "id"
	default:
		return keepass4Layout{}, errors.New("unrecognised keepass4 KDF identifier")
	}
	return keepass4Layout{
		argon: argon, t: atoiDefault(p[2], 0), memBytes: atoiDefault(p[4], 0),
		par: atoiDefault(p[6], 0), saltIdx: 8, seedIdx: 7,
	}, nil
}

func verifyKeePass4(p []string, candidate string) (bool, error) {
	// keepass2smith: $keepass$*4*<argon>*<t>*<m_bytes>*<p>*<v>*<salt>*<masterSeed>*<header>*<headerHMAC>
	// Hashcat 34300: $keepass$*4*<t>*<kdf uuid>*<m_bytes>*<v>*<p>*<salt>*<masterSeed>*<header>*<headerHMAC>
	if len(p) < 11 {
		return false, errors.New("invalid keepass4 hash format")
	}
	lay, err := keepass4Params(p)
	if err != nil {
		return false, err
	}
	argon, t, memBytes, par := lay.argon, lay.t, lay.memBytes, lay.par
	salt, e1 := hex.DecodeString(p[lay.saltIdx])
	masterSeed, e2 := hex.DecodeString(p[lay.seedIdx])
	header, e3 := hex.DecodeString(p[9])
	headerHMAC, e4 := hex.DecodeString(p[10])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return false, errors.New("invalid keepass4 hex fields")
	}
	if t < 1 || memBytes < 1024 || par < 1 {
		return false, errors.New("invalid keepass4 KDF parameters")
	}

	// composite key = SHA256(SHA256(password))
	inner := sha256.Sum256([]byte(candidate))
	composite := sha256.Sum256(inner[:])

	memKiB := uint32(memBytes / 1024)
	var transformed []byte
	switch argon {
	case "d":
		transformed = argon2d.DKey(composite[:], salt, uint32(t), memKiB, uint8(par), 32)
	case "id":
		transformed = argon2d.IDKey(composite[:], salt, uint32(t), memKiB, uint8(par), 32)
	default:
		return false, errors.New("unsupported keepass4 argon variant")
	}

	// HMAC base key = SHA512(masterSeed || transformedKey || 0x01)
	hb := sha512.New()
	hb.Write(masterSeed)
	hb.Write(transformed)
	hb.Write([]byte{0x01})
	hmacBase := hb.Sum(nil)

	// Header block key = SHA512(LE64(0xFFFFFFFFFFFFFFFF) || hmacBase)
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], 0xFFFFFFFFFFFFFFFF)
	bk := sha512.New()
	bk.Write(idx[:])
	bk.Write(hmacBase)
	blockKey := bk.Sum(nil)

	mac := hmac.New(sha256.New, blockKey)
	mac.Write(header)
	return hmac.Equal(mac.Sum(nil), headerHMAC), nil
}

// verifyKeePass2 decrypts the first block and compares it to the expected
// stream-start bytes.
func verifyKeePass2(p []string, candidate string, keyfileOnly bool) (bool, error) {
	// $keepass$*2*rounds*?*masterSeed*transformSeed*encIV*expectedStart*firstEnc
	//           [*<inline>*<len>*<keyfile hex>]
	if len(p) < 9 {
		return false, errors.New("invalid keepass2 hash format")
	}
	rounds := atoiDefault(p[2], 0)
	masterSeed, e1 := hex.DecodeString(p[4])
	transformSeed, e2 := hex.DecodeString(p[5])
	encIV, e3 := hex.DecodeString(p[6])
	expectedStart, e4 := hex.DecodeString(p[7])
	firstEnc, e5 := hex.DecodeString(p[8])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return false, errors.New("invalid keepass2 hex fields")
	}
	if len(firstEnc) < 16 || len(firstEnc)%16 != 0 || len(encIV) < 16 {
		return false, errors.New("keepass2 first block not aligned")
	}

	keyfile, err := keepassKeyfileFromRecord(p)
	if err != nil {
		return false, err
	}
	composite := keepassComposite(candidate, keyfile, keyfileOnly)
	master, err := keepassMasterKey(composite, transformSeed, masterSeed, rounds)
	if err != nil {
		return false, err
	}

	block, err := aes.NewCipher(master)
	if err != nil {
		return false, err
	}
	n := len(expectedStart)
	if n > len(firstEnc) {
		n = len(firstEnc)
	}
	// Round down to a whole number of blocks.
	n -= n % 16
	if n == 0 {
		return false, errors.New("keepass2 expected-start too short")
	}
	pt := make([]byte, n)
	cipher.NewCBCDecrypter(block, encIV[:16]).CryptBlocks(pt, firstEnc[:n])
	return equalConst(pt, expectedStart[:n]), nil
}
