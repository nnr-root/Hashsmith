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
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
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
