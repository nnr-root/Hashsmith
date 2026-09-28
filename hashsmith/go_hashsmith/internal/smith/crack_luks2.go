package smith

// LUKS v2 — Hashcat 34100.
//
//	$luks$2$<kdf>$<hash>$<cipher>$<mode>$<key bits>$<kdf options>$<salt>$<key material>$<payload>
//
// LUKS2 changed the key-derivation function and nothing else that matters here.
// Once Argon2 has turned the passphrase into a keyslot key, the rest is LUKS1:
// decrypt the key material, reverse the anti-forensic split to recover the
// master key, and check that master key against the container. So this reuses
// the existing LUKS machinery and only replaces the KDF.
//
// The check is the all-zero payload test, not hashcat's entropy heuristic.
// hashcat accepts a candidate when the decrypted payload has entropy below a
// threshold; requiring it to be exactly 512 zero bytes is a 2^-4096 false
// positive instead of a threshold, and the published record satisfies it. The
// same trade the LUKS1 hashcat-record path already makes here, for the same
// reason, with the same limitation: a container whose data area has been
// written to cannot be verified from this record at all, because the payload no
// longer decrypts to zeroes and the record carries nothing else to check.
//
// Argon2 is the reason this format needs the memory budget in
// memory_budget.go. A header asking for m=1048576 wants a gibibyte per
// candidate, which on a ten-core machine would be ten gibibytes in flight if
// the worker count were left at the CPU count.

import (
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	luks2Prefix = "$luks$2$"
	// LUKS2 headers in the wild top out far below this; the cap exists so a
	// malformed record cannot ask for an allocation that kills the process.
	luks2MaxMemoryKiB = 16 << 20 // 16 GiB
)

type luks2Params struct {
	kdf      string // "argon2id", "argon2i" or "pbkdf2"
	memKiB   uint32
	time     uint32
	lanes    uint32
	iter     int // pbkdf2 only
	hashSpec string
	cipher   string
	mode     string
	keyBytes int
	salt     []byte
	material []byte
	payload  []byte
}

func (p *luks2Params) memoryBytes() uint64 {
	if p.kdf == "pbkdf2" {
		return 0
	}
	return uint64(p.memKiB) * 1024
}

func parseLUKS2Params(target string) (*luks2Params, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, luks2Prefix) {
		return nil, errors.New("not a LUKS v2 record")
	}
	f := strings.Split(strings.TrimPrefix(t, luks2Prefix), "$")
	if len(f) != 9 {
		return nil, errors.New("LUKS v2 record must have 9 fields after $luks$2$")
	}
	p := &luks2Params{
		kdf:      f[0],
		hashSpec: f[1],
		cipher:   f[2],
		mode:     f[3],
	}
	keyBits, err := strconv.Atoi(f[4])
	if err != nil || keyBits <= 0 || keyBits%8 != 0 {
		return nil, errors.New("invalid LUKS v2 key size " + f[4])
	}
	p.keyBytes = keyBits / 8

	switch p.kdf {
	case "argon2id", "argon2i":
		m, tcost, lanes, err := parseKDFOptions(f[5])
		if err != nil {
			return nil, err
		}
		if m > luks2MaxMemoryKiB {
			return nil, errors.New("LUKS v2 header asks for more memory than Hashsmith will allocate")
		}
		p.memKiB, p.time, p.lanes = m, tcost, lanes
	case "pbkdf2":
		iter, err := strconv.Atoi(f[5])
		if err != nil || iter <= 0 {
			return nil, errors.New("invalid LUKS v2 PBKDF2 iteration count " + f[5])
		}
		p.iter = iter
	default:
		return nil, errors.New("unsupported LUKS v2 KDF " + p.kdf)
	}

	if p.salt, err = decodeHexField(f[6], "LUKS v2 salt"); err != nil {
		return nil, err
	}
	if p.material, err = decodeHexField(f[7], "LUKS v2 key material"); err != nil {
		return nil, err
	}
	if p.payload, err = decodeHexField(f[8], "LUKS v2 payload"); err != nil {
		return nil, err
	}
	if len(p.material) == 0 || len(p.material)%p.keyBytes != 0 {
		return nil, errors.New("LUKS v2 key material is not a whole number of stripes")
	}
	if len(p.payload) == 0 {
		return nil, errors.New("LUKS v2 record carries no payload to verify against")
	}
	return p, nil
}

// luks2SlotKey derives the keyslot key from the passphrase.
func luks2SlotKey(p *luks2Params, candidate string, newHash func() hash.Hash) []byte {
	pw := []byte(candidate)
	switch p.kdf {
	case "argon2id":
		return argon2.IDKey(pw, p.salt, p.time, p.memKiB, uint8(p.lanes), uint32(p.keyBytes))
	case "argon2i":
		return argon2.Key(pw, p.salt, p.time, p.memKiB, uint8(p.lanes), uint32(p.keyBytes))
	default:
		return pbkdf2.Key(pw, p.salt, p.iter, p.keyBytes, newHash)
	}
}

func verifyLUKS2(target, candidate string) (bool, error) {
	p, err := parseLUKS2Params(target)
	if err != nil {
		return false, err
	}
	newHash, ok := luksHasher(p.hashSpec)
	if !ok {
		return false, errors.New("unsupported LUKS v2 hash " + p.hashSpec)
	}
	// Reuse the LUKS1 structures: past the KDF the formats are identical.
	inner := &luksParams{
		hashSpec:    p.hashSpec,
		cipherName:  p.cipher,
		cipherMode:  p.mode,
		keyBytes:    p.keyBytes,
		stripes:     len(p.material) / p.keyBytes,
		keyMaterial: p.material,
		payload:     p.payload,
	}
	slotKey := luks2SlotKey(p, candidate, newHash)
	split, err := luksDecrypt(inner, slotKey)
	if err != nil {
		return false, err
	}
	masterKey := afMerge(split, inner.keyBytes, inner.stripes, newHash)
	return verifyLUKSPayload(inner, masterKey)
}

// decodeHexField decodes a hex field, naming it in any error.
func decodeHexField(s, what string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New(what + " must be hex")
	}
	return b, nil
}
