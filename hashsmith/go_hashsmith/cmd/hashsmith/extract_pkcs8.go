package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ── PKCS#8 encrypted private keys (PBES2) ──────────────────────────────────────
//
// "-----BEGIN ENCRYPTED PRIVATE KEY-----" — the default output of modern OpenSSL
// (`openssl genpkey`, `openssl pkcs8`). Encryption is PBES2: PBKDF2 (with an
// HMAC PRF) deriving a key for an AES-CBC or 3DES-CBC scheme.
//
// Hashsmith format:
//   $pkcs8$<prf>$<iter>$<keylen>$<enc>$<salt_hex>$<iv_hex>$<ct_hex>
// where <prf> is sha1|sha224|sha256|sha384|sha512 and <enc> is the cipher name.

// Relevant OIDs.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3   = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// ASN.1 shapes for EncryptedPrivateKeyInfo / PBES2 / PBKDF2.
type encryptedPrivateKeyInfo struct {
	Algo pkix.AlgorithmIdentifier
	Data []byte
}

type pbes2Params struct {
	KDF       pkix.AlgorithmIdentifier
	EncScheme pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt      []byte
	Iter      int
	KeyLength int                      `asn1:"optional"`
	PRF       pkix.AlgorithmIdentifier `asn1:"optional"`
}

func extractPKCS8Key(text, path string) (*zipHashResult, error) {
	der, err := decodePEMBody(text, "ENCRYPTED PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("cannot parse PKCS#8 structure: %w", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("unsupported PKCS#8 encryption (only PBES2)")
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("cannot parse PBES2 params: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("unsupported PKCS#8 KDF (only PBKDF2)")
	}

	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("cannot parse PBKDF2 params: %w", err)
	}

	prf := prfName(kdf.PRF.Algorithm)
	encName, keyLen, err := pkcs8CipherName(params.EncScheme.Algorithm)
	if err != nil {
		return nil, err
	}
	if kdf.KeyLength != 0 {
		keyLen = kdf.KeyLength
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.EncScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("cannot parse cipher IV: %w", err)
	}

	hashStr := fmt.Sprintf("$pkcs8$%s$%d$%d$%s$%s$%s$%s",
		prf, kdf.Iter, keyLen, encName,
		hex.EncodeToString(kdf.Salt), hex.EncodeToString(iv), hex.EncodeToString(epki.Data))
	return &zipHashResult{
		hashType: "pkcs8",
		hash:     hashStr,
		filename: path,
		encLabel: fmt.Sprintf("PKCS#8 PBES2 (PBKDF2-%s, %s, %d iters)", strings.ToUpper(prf), encName, kdf.Iter),
	}, nil
}

func prfName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidHMACSHA224):
		return "sha224"
	case oid.Equal(oidHMACSHA256):
		return "sha256"
	case oid.Equal(oidHMACSHA384):
		return "sha384"
	case oid.Equal(oidHMACSHA512):
		return "sha512"
	default:
		return "sha1" // PBKDF2 default PRF when absent
	}
}

func prfHash(name string) func() hash.Hash {
	switch name {
	case "sha224":
		return sha256.New224
	case "sha256":
		return sha256.New
	case "sha384":
		return sha512.New384
	case "sha512":
		return sha512.New
	default:
		return sha1.New
	}
}

func pkcs8CipherName(oid asn1.ObjectIdentifier) (name string, keyLen int, err error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return "aes-128-cbc", 16, nil
	case oid.Equal(oidAES192CBC):
		return "aes-192-cbc", 24, nil
	case oid.Equal(oidAES256CBC):
		return "aes-256-cbc", 32, nil
	case oid.Equal(oidDESEDE3):
		return "des-ede3-cbc", 24, nil
	}
	return "", 0, fmt.Errorf("unsupported PKCS#8 cipher OID %v", oid)
}

// verifyPKCS8 re-derives the PBKDF2 key, decrypts, and checks PKCS#7 padding plus
// a leading DER SEQUENCE tag.
func verifyPKCS8(targetHash, candidate string) (bool, error) {
	// $pkcs8$<prf>$<iter>$<keylen>$<enc>$<salt_hex>$<iv_hex>$<ct_hex>
	parts := strings.Split(targetHash, "$")
	if len(parts) != 9 || parts[1] != "pkcs8" {
		return false, errors.New("invalid pkcs8 hash format")
	}
	prf := parts[2]
	var iter, keyLen int
	if _, err := fmt.Sscanf(parts[3], "%d", &iter); err != nil {
		return false, errors.New("invalid pkcs8 iteration count")
	}
	if _, err := fmt.Sscanf(parts[4], "%d", &keyLen); err != nil {
		return false, errors.New("invalid pkcs8 key length")
	}
	encName := parts[5]
	salt, err := hex.DecodeString(parts[6])
	if err != nil {
		return false, errors.New("invalid pkcs8 salt")
	}
	iv, err := hex.DecodeString(parts[7])
	if err != nil {
		return false, errors.New("invalid pkcs8 iv")
	}
	ct, err := hex.DecodeString(parts[8])
	if err != nil {
		return false, errors.New("invalid pkcs8 ciphertext")
	}

	key := pbkdf2.Key([]byte(candidate), salt, iter, keyLen, prfHash(prf))

	var block cipher.Block
	switch encName {
	case "aes-128-cbc", "aes-192-cbc", "aes-256-cbc":
		block, err = aes.NewCipher(key)
	case "des-ede3-cbc":
		block, err = des.NewTripleDESCipher(key)
	default:
		return false, fmt.Errorf("unsupported pkcs8 cipher %q", encName)
	}
	if err != nil {
		return false, err
	}
	bs := block.BlockSize()
	if len(ct) == 0 || len(ct)%bs != 0 || len(iv) < bs {
		return false, errors.New("pkcs8 ciphertext not block-aligned")
	}

	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:bs]).CryptBlocks(pt, ct)

	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > bs || pad > len(pt) {
		return false, nil
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return false, nil
		}
	}
	return pt[0] == 0x30, nil
}
