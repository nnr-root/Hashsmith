package main

// LUKS v1 volume cracking.
//
// For each active keyslot: PBKDF2 the passphrase into a slot key, decrypt the
// keyslot's anti-forensic key material with the volume cipher, AF-merge it into
// a candidate master key, then PBKDF2 that master key and compare against the
// header's master-key digest.
//
// Covered ciphers/hashes: AES, Serpent and Twofish in xts-plain64 /
// cbc-essiv / cbc-plain64, with SHA-1/SHA-256/SHA-512/RIPEMD-160/Whirlpool.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xts"
)

// luksParams carries everything the cracker needs from a LUKS header + keyslot.
type luksParams struct {
	hashSpec    string // "sha1" | "sha256" | "sha512" | "ripemd160" | "whirlpool"
	cipherName  string // "aes" | "serpent" | "twofish"
	cipherMode  string // "xts-plain64" | "cbc-essiv:sha256" | "cbc-plain64"
	keyBytes    int    // master-key length
	mkDigest    []byte // 20 bytes
	mkSalt      []byte // 32 bytes
	mkIter      int
	slotIter    int
	slotSalt    []byte // 32 bytes
	stripes     int
	keyMaterial []byte // keyBytes * stripes bytes
}

type luksModeSpec struct {
	hashSpec   string
	cipherName string
}

// luksModeSpecs gives Hashcat's split LUKS v1 modes distinct type tokens. The
// compact $luks$ record still comes from luks2smith, but selecting one of these
// types also proves that the record has the KDF/cipher pair named by the mode.
var luksModeSpecs = map[string]luksModeSpec{
	"luks-sha1-aes":          {"sha1", "aes"},
	"luks-sha1-serpent":      {"sha1", "serpent"},
	"luks-sha1-twofish":      {"sha1", "twofish"},
	"luks-sha256-aes":        {"sha256", "aes"},
	"luks-sha256-serpent":    {"sha256", "serpent"},
	"luks-sha256-twofish":    {"sha256", "twofish"},
	"luks-sha512-aes":        {"sha512", "aes"},
	"luks-sha512-serpent":    {"sha512", "serpent"},
	"luks-sha512-twofish":    {"sha512", "twofish"},
	"luks-ripemd160-aes":     {"ripemd160", "aes"},
	"luks-ripemd160-serpent": {"ripemd160", "serpent"},
	"luks-ripemd160-twofish": {"ripemd160", "twofish"},
}

// The $luks$ format packs a LUKS header and one active keyslot into a single
// crackable line:
//
//	$luks$1$<hash>$<cipher>$<mode>$<keyBytes>$<mkDigest>$<mkSalt>$<mkIter>$
//	       <slotIter>$<slotSalt>$<stripes>$<keyMaterial>
//
// verifyLUKS parses that and runs the crack pipeline.
func verifyLUKS(targetHash, candidate string) (bool, error) {
	p, err := parseLUKSHash(targetHash)
	if err != nil {
		return false, err
	}
	return verifyLUKSParams(p, candidate)
}

func verifyLUKSMode(targetHash, candidate string, mode luksModeSpec) (bool, error) {
	p, err := parseLUKSHash(targetHash)
	if err != nil {
		return false, err
	}
	if p.hashSpec != mode.hashSpec || p.cipherName != mode.cipherName {
		return false, errors.New("LUKS record does not match selected hash/cipher mode")
	}
	return verifyLUKSParams(p, candidate)
}

func parseLUKSHash(target string) (*luksParams, error) {
	if !strings.HasPrefix(target, "$luks$1$") {
		return nil, errors.New("invalid LUKS hash (missing $luks$1$ prefix)")
	}
	f := strings.Split(target[len("$luks$"):], "$")
	// f: [1, hash, cipher, mode, keyBytes, mkDigest, mkSalt, mkIter, slotIter, slotSalt, stripes, keyMaterial]
	if len(f) != 12 {
		return nil, errors.New("invalid LUKS hash (need 12 fields)")
	}
	atoi := func(name, s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, errors.New("invalid LUKS " + name)
		}
		return n, nil
	}
	dec := func(name, s string) ([]byte, error) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("invalid LUKS " + name)
		}
		return b, nil
	}
	keyBytes, err := atoi("key size", f[4])
	if err != nil {
		return nil, err
	}
	mkDigest, err := dec("master-key digest", f[5])
	if err != nil {
		return nil, err
	}
	mkSalt, err := dec("master-key salt", f[6])
	if err != nil {
		return nil, err
	}
	mkIter, err := atoi("master-key iteration count", f[7])
	if err != nil {
		return nil, err
	}
	slotIter, err := atoi("keyslot iteration count", f[8])
	if err != nil {
		return nil, err
	}
	slotSalt, err := dec("keyslot salt", f[9])
	if err != nil {
		return nil, err
	}
	stripes, err := atoi("stripe count", f[10])
	if err != nil {
		return nil, err
	}
	keyMaterial, err := dec("key material", f[11])
	if err != nil {
		return nil, err
	}
	p := &luksParams{
		hashSpec:    f[1],
		cipherName:  f[2],
		cipherMode:  f[3],
		keyBytes:    keyBytes,
		mkDigest:    mkDigest,
		mkSalt:      mkSalt,
		mkIter:      mkIter,
		slotIter:    slotIter,
		slotSalt:    slotSalt,
		stripes:     stripes,
		keyMaterial: keyMaterial,
	}
	if p.keyBytes <= 0 || p.stripes <= 0 || p.mkIter <= 0 || p.slotIter <= 0 ||
		len(p.mkDigest) != 20 || len(p.mkSalt) != 32 || len(p.slotSalt) != 32 {
		return nil, errors.New("invalid LUKS hash fields")
	}
	maxInt := int(^uint(0) >> 1)
	if p.stripes > maxInt/p.keyBytes || len(p.keyMaterial) != p.keyBytes*p.stripes {
		return nil, errors.New("LUKS key material size mismatch")
	}
	return p, nil
}

func luksHasher(spec string) (func() hash.Hash, bool) {
	switch spec {
	case "sha1":
		return sha1.New, true
	case "sha256":
		return sha256.New, true
	case "sha512":
		return sha512.New, true
	case "ripemd160":
		return ripemd160.New, true
	case "whirlpool":
		return newWhirlpool, true
	}
	return nil, false
}

// verifyLUKSParams runs the crack pipeline for one candidate against parsed
// LUKS parameters.
func verifyLUKSParams(p *luksParams, candidate string) (bool, error) {
	newHash, ok := luksHasher(p.hashSpec)
	if !ok {
		return false, errors.New("unsupported LUKS hash " + p.hashSpec)
	}
	if len(p.keyMaterial) != p.keyBytes*p.stripes {
		return false, errors.New("LUKS key material size mismatch")
	}

	// 1. Slot key from the passphrase.
	slotKey := pbkdf2.Key([]byte(candidate), p.slotSalt, p.slotIter, p.keyBytes, newHash)

	// 2. Decrypt the keyslot's key material.
	decrypted, err := luksDecrypt(p, slotKey)
	if err != nil {
		return false, err
	}

	// 3. AF-merge into a candidate master key.
	masterKey := afMerge(decrypted, p.keyBytes, p.stripes, newHash)

	// 4. Digest the candidate master key and compare (LUKS digest is 20 bytes).
	got := pbkdf2.Key(masterKey, p.mkSalt, p.mkIter, len(p.mkDigest), newHash)
	return bytesEqualCT(got, p.mkDigest), nil
}

// luksDecrypt decrypts the key material sector-by-sector (512-byte sectors) with
// the volume cipher/mode.
func luksDecrypt(p *luksParams, key []byte) ([]byte, error) {
	blockFn := func(k []byte) (cipher.Block, error) {
		switch p.cipherName {
		case "aes":
			return aes.NewCipher(k)
		case "twofish":
			return twofish.NewCipher(k)
		case "serpent":
			return newSerpentCipher(k)
		}
		return nil, errors.New("unsupported LUKS cipher " + p.cipherName)
	}

	const sector = 512
	out := make([]byte, len(p.keyMaterial))

	switch p.cipherMode {
	case "xts-plain64":
		c, err := xts.NewCipher(blockFn, key)
		if err != nil {
			return nil, err
		}
		for s := 0; s*sector < len(p.keyMaterial); s++ {
			lo, hi := s*sector, (s+1)*sector
			if hi > len(p.keyMaterial) {
				hi = len(p.keyMaterial)
			}
			c.Decrypt(out[lo:hi], p.keyMaterial[lo:hi], uint64(s))
		}
		return out, nil

	case "cbc-plain64", "cbc-essiv:sha256":
		block, err := blockFn(key)
		if err != nil {
			return nil, err
		}
		var essiv cipher.Block
		if p.cipherMode == "cbc-essiv:sha256" {
			salted := sha256.Sum256(key)
			essiv, err = blockFn(salted[:])
			if err != nil {
				return nil, err
			}
		}
		for s := 0; s*sector < len(p.keyMaterial); s++ {
			lo, hi := s*sector, (s+1)*sector
			if hi > len(p.keyMaterial) {
				hi = len(p.keyMaterial)
			}
			iv := luksSectorIV(s, block.BlockSize(), essiv)
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(out[lo:hi], p.keyMaterial[lo:hi])
		}
		return out, nil
	}
	return nil, errors.New("unsupported LUKS cipher mode " + p.cipherMode)
}

// luksSectorIV builds the per-sector IV. plain64 = little-endian sector number;
// essiv = AES_essiv(plain64 sector number).
func luksSectorIV(sectorNum, blockSize int, essiv cipher.Block) []byte {
	iv := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(iv[:8], uint64(sectorNum))
	if essiv != nil {
		enc := make([]byte, blockSize)
		essiv.Encrypt(enc, iv)
		return enc
	}
	return iv
}

// afMerge reverses the anti-forensic split, recovering the master key from the
// stripes of key material.
func afMerge(material []byte, blockSize, stripes int, newHash func() hash.Hash) []byte {
	d := make([]byte, blockSize)
	for i := 0; i < stripes-1; i++ {
		block := material[i*blockSize : (i+1)*blockSize]
		for j := 0; j < blockSize; j++ {
			d[j] ^= block[j]
		}
		d = afDiffuse(d, newHash)
	}
	last := material[(stripes-1)*blockSize : stripes*blockSize]
	for j := 0; j < blockSize; j++ {
		d[j] ^= last[j]
	}
	return d
}

// afDiffuse applies the LUKS AF diffuse function: each digest-sized chunk is
// replaced by hash(be32(index) || chunk).
func afDiffuse(src []byte, newHash func() hash.Hash) []byte {
	h := newHash()
	ds := h.Size()
	out := make([]byte, len(src))
	full := len(src) / ds
	for i := 0; i < full; i++ {
		out = afDiffuseBlock(out, src, i*ds, ds, i, newHash)
	}
	if rem := len(src) % ds; rem != 0 {
		out = afDiffuseBlock(out, src, full*ds, rem, full, newHash)
	}
	return out
}

func afDiffuseBlock(out, src []byte, off, n, index int, newHash func() hash.Hash) []byte {
	h := newHash()
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], uint32(index))
	h.Write(be[:])
	h.Write(src[off : off+n])
	sum := h.Sum(nil)
	copy(out[off:off+n], sum[:n])
	return out
}
