package main

// John's spellings of records Hashsmith already reads.
//
// Unlike the envelopes in crack_john_wrappers.go, which wrap a bare digest,
// these records carry the same fields as the spelling Hashsmith knows but
// written differently: a different separator, a different order, a different
// encoding. Each reader here turns one into the other and hands it to the
// verifier that already exists, so there is one implementation of each scheme
// and two ways of writing it down.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// johnSeededChecksum reads John's "$crc32$<initial>.<checksum>" — and the
// same shape under $crc32c$ — as hashcat's "<checksum>:<initial>". Both tools
// store the same two words; John puts the seed first and joins with a dot.
func johnSeededChecksum(target, prefix string) (string, bool) {
	t := strings.TrimSpace(target)
	if len(t) < len(prefix) || !strings.EqualFold(t[:len(prefix)], prefix) {
		return "", false
	}
	body := t[len(prefix):]
	dot := strings.IndexByte(body, '.')
	if dot < 0 {
		return "", false
	}
	initial, checksum := body[:dot], body[dot+1:]
	if len(initial) != 8 || len(checksum) != 8 || !isHex(initial) || !isHex(checksum) {
		return "", false
	}
	return checksum + ":" + initial, true
}

// johnChapRecord reads "$chap$<id>*<challenge>*<response>" as the
// "<response>:<challenge>:<id>" hashcat writes for the same exchange.
func johnChapRecord(target string) (string, bool) {
	const prefix = "$chap$"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", false
	}
	f := strings.Split(t[len(prefix):], "*")
	if len(f) != 3 || len(f[2]) != 32 || !isHex(f[2]) || !isHex(f[1]) || !isHex(f[0]) {
		return "", false
	}
	return f[2] + ":" + f[1] + ":" + f[0], true
}

// itoa64LE decodes crypt(3)'s base64 as scrypt's $7$ records use it: four
// characters carry three bytes, least significant first.
func itoa64LE(s string) []byte {
	out := make([]byte, 0, len(s)*3/4)
	for i := 0; i < len(s); i += 4 {
		n := len(s) - i
		if n > 4 {
			n = 4
		}
		var v uint32
		for j := n - 1; j >= 0; j-- {
			k := strings.IndexByte(itoa64, s[i+j])
			if k < 0 {
				return nil
			}
			v = v<<6 | uint32(k)
		}
		for b := 0; b < n*6/8; b++ {
			out = append(out, byte(v>>(8*b)))
		}
	}
	return out
}

// johnScryptRecord reads the two scrypt spellings John accepts and Hashsmith
// did not, and writes them as the one it does.
//
//	$7$<logN><r><p><salt>$<hash>            Colin Percival's own crypt format,
//	                                        where logN is one character and r
//	                                        and p are five each
//	$ScryptKDF.pm$<N>*<r>*<p>*<salt>*<hash> the Perl module's, base64 throughout
//
// The $7$ parameters are not hex or decimal but crypt(3) base64, little end
// first, and the salt is the remaining characters as written rather than a
// decoding of them — which is why the RFC 7914 vector's salt reads
// "SodiumChloride" in the record itself.
func johnScryptRecord(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "$7$") {
		body := t[len("$7$"):]
		cut := strings.IndexByte(body, '$')
		if cut < 12 {
			return "", false
		}
		params, hash := body[:cut], body[cut+1:]
		logN := strings.IndexByte(itoa64, params[0])
		r, p := itoa64LE(params[1:6]), itoa64LE(params[6:11])
		digest := itoa64LE(hash)
		if logN < 1 || logN > 31 || len(r) != 3 || len(p) != 3 || len(digest) == 0 {
			return "", false
		}
		salt := params[11:]
		return "scrypt$" + strconv.Itoa(1<<uint(logN)) +
			"$" + strconv.Itoa(int(r[0])|int(r[1])<<8|int(r[2])<<16) +
			"$" + strconv.Itoa(int(p[0])|int(p[1])<<8|int(p[2])<<16) +
			"$" + hex.EncodeToString([]byte(salt)) +
			"$" + hex.EncodeToString(digest), true
	}
	const perl = "$ScryptKDF.pm$"
	if strings.HasPrefix(t, perl) {
		f := strings.Split(t[len(perl):], "*")
		if len(f) != 5 {
			return "", false
		}
		for _, n := range f[:3] {
			if _, err := strconv.Atoi(n); err != nil {
				return "", false
			}
		}
		salt, err := base64.StdEncoding.DecodeString(f[3])
		if err != nil {
			return "", false
		}
		digest, err := base64.StdEncoding.DecodeString(f[4])
		if err != nil || len(digest) == 0 {
			return "", false
		}
		return "scrypt$" + f[0] + "$" + f[1] + "$" + f[2] +
			"$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(digest), true
	}
	return "", false
}

// johnMongoDBSCRAM reads John's "$scram$<user>$<iter>$<salt>$<key>", which is
// the SHA-1 MongoDB credential written without the version field that tells
// the three MongoDB mechanisms apart. Version 0 is the only one it can be.
func johnMongoDBSCRAM(target string) (string, bool) {
	const prefix = "$scram$"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", false
	}
	f := strings.Split(t[len(prefix):], "$")
	if len(f) != 4 || f[0] == "" {
		return "", false
	}
	if _, err := strconv.Atoi(f[1]); err != nil {
		return "", false
	}
	for _, field := range f[2:] {
		if _, err := base64.StdEncoding.DecodeString(field); err != nil {
			return "", false
		}
	}
	return "$mongodb-scram$0$" + strings.Join(f, "$"), true
}

// johnMongoDBLegacy reads "$mongodb$0$<user>$<md5>": MONGODB-CR, the
// challenge-response credential MongoDB used before SCRAM, which is
// md5($user.":mongo:".$pass) and nothing more.
func johnMongoDBLegacy(target string) (user, digest string, ok bool) {
	const prefix = "$mongodb$"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", "", false
	}
	f := strings.Split(t[len(prefix):], "$")
	// Version 1 is the network hash, which carries a nonce this record shape
	// has no room for; it is John's dynamic_1551 and is read there.
	if len(f) != 3 || f[0] != "0" || f[1] == "" || len(f[2]) != 32 || !isHex(f[2]) {
		return "", "", false
	}
	return f[1], f[2], true
}

// johnIKERecord reads John's "$ike$*<type>*<nine fields>" as the nine
// colon-separated fields hashcat writes for the same aggressive-mode exchange.
// The leading type field says MD5 or SHA-1, which the length of HASH_R already
// says, so it is read for validity and then not needed.
func johnIKERecord(target string) (string, bool) {
	const prefix = "$ike$*"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", false
	}
	f := strings.Split(t[len(prefix):], "*")
	if len(f) != 10 {
		return "", false
	}
	if f[0] != "0" && f[0] != "1" {
		return "", false
	}
	for _, x := range f[1:] {
		if x == "" || !isHex(x) {
			return "", false
		}
	}
	return strings.Join(f[1:], ":"), true
}

// John's $sxc$ records are NOT read here, and the reason is worth recording.
//
// The record lines up with $odf$ field for field, differing only in carrying
// two lengths where hashcat carries one, so rewriting one as the other looks
// like the whole job. It is not: rewritten that way the record does not
// verify, and a bounded sweep of the obvious variations — the checksum over
// 756, 760 or all of the decrypted bytes; Blowfish in 64-bit or 8-bit CFB;
// the PBKDF2 password as SHA-1, SHA-256 or the password itself; key lengths
// of 16, 20 and 32 — found no combination that reproduces John's own test
// vector. Something else differs, and sweeping cannot find a construction
// outside the space swept. Claiming the record and failing on it would be
// worse than leaving it alone, so it is left alone.

// johnOldOfficeRecord takes the Office record out of the line John writes it
// on, which carries the username before it — usually empty, leaving a bare
// leading colon.
//
// What follows the record is left where it is. John writes the five-byte RC4
// key there when it has one, and that field is not noise: it is the same
// "collider answer" hashcat's modes 9720 and 9820 carry, which the verifier
// checks the recovered password against. Cutting the line at the first colon
// would throw it away, and a record whose answer is never checked is one that
// will happily report a wrong password.
func johnOldOfficeRecord(target string) (string, bool) {
	const marker = "$oldoffice$"
	t := strings.TrimSpace(target)
	start := strings.Index(t, marker)
	if start <= 0 || t[start-1] != ':' {
		return "", false
	}
	rest := t[start:]
	if strings.Count(rest, "*") < 3 {
		return "", false
	}
	return rest, true
}

// johnP5K2Record reads "$p5k2$<rounds>$<salt>$<digest>", Passlib's spelling of
// PBKDF2-HMAC-SHA1. Two things in it are not what they look like: the round
// count is hex, not decimal, and the base64 is the URL-safe alphabet rather
// than the adapted one Passlib's other formats use.
func johnP5K2Record(target string) (rounds int, salt, digest []byte, ok bool) {
	const prefix = "$p5k2$"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return 0, nil, nil, false
	}
	f := strings.Split(t[len(prefix):], "$")
	if len(f) != 3 {
		return 0, nil, nil, false
	}
	n, err := strconv.ParseInt(f[0], 16, 64)
	if err != nil || n < 1 || n > maxKDFIterations {
		return 0, nil, nil, false
	}
	decode := func(s string) ([]byte, bool) {
		b, err := base64.StdEncoding.DecodeString(
			strings.NewReplacer("-", "+", "_", "/").Replace(s))
		return b, err == nil && len(b) > 0
	}
	salt, ok = decode(f[1])
	if !ok {
		return 0, nil, nil, false
	}
	digest, ok = decode(f[2])
	if !ok {
		return 0, nil, nil, false
	}
	return int(n), salt, digest, true
}

// verifyP5K2 checks that record.
func verifyP5K2(target, candidate string) (bool, error) {
	rounds, salt, digest, ok := johnP5K2Record(target)
	if !ok {
		return false, errors.New("invalid $p5k2$ PBKDF2-HMAC-SHA1 record")
	}
	return hmac.Equal(pbkdf2.Key([]byte(candidate), salt, rounds, len(digest), sha1.New), digest), nil
}
