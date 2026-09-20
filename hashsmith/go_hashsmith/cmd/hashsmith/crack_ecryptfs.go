package main

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

// eCryptfs passphrase signatures, Hashcat mode 12200 and John's ecryptfs.
//
// Record, as ecryptfs2john writes it:
//
//	$ecryptfs$0$1$<salt hex>$<signature hex>
//	$ecryptfs$0$<signature hex>                 (default salt)
//
// The second field is the version and the third says whether a salt follows.
// eCryptfs derives its signature by seeding SHA-512 with the salt and the
// passphrase and then re-hashing the digest 65,536 more times, keeping the
// first eight bytes. The iteration count is fixed in eCryptfs itself
// (ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS) and is not carried in the record, so
// it is a constant here rather than a parsed field.
//
// The total is 65,537 SHA-512 invocations, not 65,536: eCryptfs hashes the
// seed and then iterates. That off-by-one was settled against hashcat's own
// published vector — $ecryptfs$0$1$4207883745556753$567daa975114206c for the
// password "hashcat" — and 65,536 total produces a different signature.
const ecryptfsIterations = 65536

// ecryptfsDefaultSalt is eCryptfs's built-in salt (ECRYPTFS_DEFAULT_SALT_HEX),
// used by a record that carries none.
//
// Unlike everything else here it is NOT confirmed by a vector: hashcat's
// published example carries its own salt, so only the salted path is covered
// by a test. A record in the unsalted form that fails to crack should have
// this constant checked against the eCryptfs source before the derivation
// above is suspected.
var ecryptfsDefaultSalt = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}

func verifyECryptfs(targetHash, candidate string) (bool, error) {
	rest, ok := strings.CutPrefix(targetHash, "$ecryptfs$")
	if !ok {
		return false, errors.New("invalid ecryptfs hash format")
	}
	parts := strings.Split(rest, "$")

	var saltHex, sigHex string
	switch len(parts) {
	case 2:
		// $ecryptfs$<version>$<signature> — no salt, so the default applies.
		sigHex = parts[1]
	case 4:
		// $ecryptfs$<version>$<has-salt>$<salt>$<signature>
		if parts[1] != "1" {
			return false, errors.New("ecryptfs record has a salt field but does not declare one")
		}
		saltHex, sigHex = parts[2], parts[3]
	default:
		return false, errors.New("invalid ecryptfs field count")
	}
	if parts[0] != "0" {
		return false, errors.New("unsupported ecryptfs version " + parts[0])
	}

	salt := ecryptfsDefaultSalt
	if saltHex != "" {
		b, err := hex.DecodeString(saltHex)
		if err != nil || len(b) != 8 {
			return false, errors.New("invalid ecryptfs salt")
		}
		salt = b
	}
	want, err := hex.DecodeString(sigHex)
	if err != nil || len(want) != 8 {
		return false, errors.New("invalid ecryptfs signature")
	}

	digest := sha512.Sum512(append(append([]byte{}, salt...), candidate...))
	for i := 0; i < ecryptfsIterations; i++ {
		digest = sha512.Sum512(digest[:])
	}
	return equalConst(digest[:8], want), nil
}
