package smith

// Tezos fundraiser wallets.
//
//	$tezos$1*<iterations>*<mnemonic>*<email>*<tz1 address>*<prefix + key hash>
//
// The 2017 fundraiser handed each contributor a fifteen-word mnemonic, an
// email address and a password, and derived the wallet from all three. Only
// the password is secret: the mnemonic and the email were printed on the same
// PDF, so anyone holding that PDF holds everything except the one field this
// recovers.
//
// The derivation is BIP-39's with the fundraiser's own twist — the password
// goes into the SALT rather than the passphrase, after the literal string
// "mnemonic" and the email address:
//
//	seed    = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+email+password, 2048, 64)
//	key     = Ed25519 from the first 32 bytes of that seed
//	address = BLAKE2b-160 of the public key
//
// The record carries the address twice: once as the tz1 string a human reads,
// and once as the bytes the check compares, with the two trailing bytes of
// the tz1 prefix still attached — which is why the comparison takes the last
// twenty bytes rather than the whole field.

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	tezosPrefix      = "$tezos$"
	tezosKeyHashSize = 20
)

type tezosRecord struct {
	iterations int
	mnemonic   string
	email      string
	keyHash    []byte
}

func parseTezos(target string) (*tezosRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, tezosPrefix) {
		return nil, errors.New("not a Tezos fundraiser record")
	}
	body := t[len(tezosPrefix):]
	version, rest, ok := strings.Cut(body, "*")
	if !ok || version != "1" {
		return nil, errors.New("unsupported Tezos record version")
	}
	f := strings.Split(rest, "*")
	if len(f) != 5 {
		return nil, errors.New("a Tezos record is <iterations>*<mnemonic>*<email>*<address>*<key hash>")
	}
	r := &tezosRecord{mnemonic: f[1], email: f[2]}
	var err error
	if r.iterations, err = strconv.Atoi(f[0]); err != nil ||
		r.iterations < 1 || r.iterations > maxKDFIterations {
		return nil, errors.New("invalid Tezos iteration count")
	}
	if r.mnemonic == "" || len(r.mnemonic) > maxKDFFieldSize {
		return nil, errors.New("a Tezos record must carry its mnemonic")
	}
	raw, err := hex.DecodeString(f[4])
	if err != nil || len(raw) < tezosKeyHashSize {
		return nil, errors.New("invalid Tezos key hash")
	}
	// The leading bytes are what is left of the tz1 prefix; the hash is the
	// last twenty.
	r.keyHash = raw[len(raw)-tezosKeyHashSize:]
	return r, nil
}

// verifyTezos checks a fundraiser password.
func verifyTezos(target, candidate string) (bool, error) {
	r, err := parseTezos(target)
	if err != nil {
		return false, err
	}
	seed := pbkdf2.Key([]byte(r.mnemonic), []byte("mnemonic"+r.email+candidate),
		r.iterations, ed25519.SeedSize*2, sha512.New)
	return tezosSeedMatches(seed, r.keyHash), nil
}

func isTezos(target string) bool {
	_, err := parseTezos(target)
	return err == nil
}
