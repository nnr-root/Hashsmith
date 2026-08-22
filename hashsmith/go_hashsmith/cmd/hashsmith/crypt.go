package main

// Unix crypt(3) password hashes — the formats found in /etc/shadow.
//
//	$1$   md5crypt        (Poul-Henning Kamp)
//	$5$   sha256crypt     (Ulrich Drepper)
//	$6$   sha512crypt     (Ulrich Drepper)
//	descrypt            traditional 13-char DES crypt (see descrypt.go)
//
// bcrypt shadow entries ($2a$/$2b$/$2y$) are handled by the existing bcrypt
// verifier — see verifyCandidate. This file implements the three digest-based
// schemes and their constant-time-agnostic verification (offline cracking has
// no timing-attack surface, so a plain string compare is fine).

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"strconv"
	"strings"
)

// itoa64 is the crypt(3) base-64 alphabet, shared by every scheme here (and by
// descrypt). It is NOT standard base64 — the order and the ./ prefix matter.
const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// b64From24 appends n crypt-base64 characters encoding the 24-bit value
// (b2<<16)|(b1<<8)|b0, emitted least-significant group first.
func b64From24(dst []byte, b2, b1, b0 byte, n int) []byte {
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	for i := 0; i < n; i++ {
		dst = append(dst, itoa64[w&0x3f])
		w >>= 6
	}
	return dst
}

// ── md5crypt ($1$) ────────────────────────────────────────────────────────────

// md5cryptRaw computes the md5crypt digest+encoding for a password and salt and
// returns the full "$1$<salt>$<hash>" string. Salt is truncated to 8 bytes.
func md5cryptRaw(password, salt string) string {
	return md5cryptMagic(password, salt, "$1$")
}

// md5cryptMagic is md5crypt parameterised by the magic prefix. Apache's apr1
// ("$apr1$") uses the identical algorithm with a different magic.
func md5cryptMagic(password, salt, magic string) string {
	if len(salt) > 8 {
		salt = salt[:8]
	}
	pw := []byte(password)
	sb := []byte(salt)

	// digest B = MD5(pw || salt || pw)
	b := md5.New()
	b.Write(pw)
	b.Write(sb)
	b.Write(pw)
	bSum := b.Sum(nil)

	// digest A = MD5(pw || magic || salt || <B bytes> || password-length dance)
	a := md5.New()
	a.Write(pw)
	a.Write([]byte(magic))
	a.Write(sb)
	for i := len(pw); i > 0; i -= 16 {
		if i > 16 {
			a.Write(bSum[:16])
		} else {
			a.Write(bSum[:i])
		}
	}
	// The odd length-dependent bit dance: for each set bit add a NUL, for each
	// clear bit add the first password byte.
	for i := len(pw); i != 0; i >>= 1 {
		if i&1 != 0 {
			a.Write([]byte{0})
		} else {
			a.Write(pw[:1])
		}
	}
	final := a.Sum(nil)

	// 1000 rounds of strengthening.
	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 != 0 {
			c.Write(pw)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write(sb)
		}
		if i%7 != 0 {
			c.Write(pw)
		}
		if i&1 != 0 {
			c.Write(final)
		} else {
			c.Write(pw)
		}
		final = c.Sum(nil)
	}

	out := make([]byte, 0, 22)
	out = b64From24(out, final[0], final[6], final[12], 4)
	out = b64From24(out, final[1], final[7], final[13], 4)
	out = b64From24(out, final[2], final[8], final[14], 4)
	out = b64From24(out, final[3], final[9], final[15], 4)
	out = b64From24(out, final[4], final[10], final[5], 4)
	out = b64From24(out, 0, 0, final[11], 2)

	return magic + salt + "$" + string(out)
}

// ── sha256crypt / sha512crypt ($5$ / $6$) ──────────────────────────────────────

// shaCryptParams holds the per-scheme knobs that differ between $5$ and $6$.
type shaCryptParams struct {
	magic   string
	newHash func() hash.Hash
	size    int // digest length in bytes (32 / 64)
	perm    [][4]int
}

// sha256 and sha512 permute their C digest into the output alphabet with these
// fixed byte-index tables (Drepper's reference). Each entry is {b2,b1,b0,n}.
var sha256Params = shaCryptParams{
	magic:   "$5$",
	newHash: func() hash.Hash { return sha256.New() },
	size:    32,
	perm: [][4]int{
		{0, 10, 20, 4}, {21, 1, 11, 4}, {12, 22, 2, 4}, {3, 13, 23, 4},
		{24, 4, 14, 4}, {15, 25, 5, 4}, {6, 16, 26, 4}, {27, 7, 17, 4},
		{18, 28, 8, 4}, {9, 19, 29, 4}, {-1, 31, 30, 3},
	},
}

var sha512Params = shaCryptParams{
	magic:   "$6$",
	newHash: func() hash.Hash { return sha512.New() },
	size:    64,
	perm: [][4]int{
		{0, 21, 42, 4}, {22, 43, 1, 4}, {44, 2, 23, 4}, {3, 24, 45, 4},
		{25, 46, 4, 4}, {47, 5, 26, 4}, {6, 27, 48, 4}, {28, 49, 7, 4},
		{50, 8, 29, 4}, {9, 30, 51, 4}, {31, 52, 10, 4}, {53, 11, 32, 4},
		{12, 33, 54, 4}, {34, 55, 13, 4}, {56, 14, 35, 4}, {15, 36, 57, 4},
		{37, 58, 16, 4}, {59, 17, 38, 4}, {18, 39, 60, 4}, {40, 61, 19, 4},
		{62, 20, 41, 4}, {-1, -1, 63, 2},
	},
}

const (
	shaCryptDefaultRounds = 5000
	shaCryptMinRounds     = 1000
	shaCryptMaxRounds     = 999999999
)

// shaCryptRaw computes a $5$/$6$ hash. rounds<=0 uses the default; roundsExplicit
// controls whether the "rounds=" field is emitted in the output string (it is
// omitted for the default, matching glibc). Salt is truncated to 16 bytes.
func shaCryptRaw(p shaCryptParams, password, salt string, rounds int, roundsExplicit bool) string {
	return shaCryptRawWithSaltLimit(p, password, salt, rounds, roundsExplicit, 16)
}

// shaCryptRawWithSaltLimit is the shared SHA-crypt core. MySQL 8's
// caching_sha2_password record deliberately uses a 20-byte salt, while the
// normal crypt(3) formats cap it at 16 bytes.
func shaCryptRawWithSaltLimit(p shaCryptParams, password, salt string, rounds int, roundsExplicit bool, saltLimit int) string {
	if rounds <= 0 {
		rounds = shaCryptDefaultRounds
	}
	if rounds < shaCryptMinRounds {
		rounds = shaCryptMinRounds
	}
	if rounds > shaCryptMaxRounds {
		rounds = shaCryptMaxRounds
	}
	if saltLimit > 0 && len(salt) > saltLimit {
		salt = salt[:saltLimit]
	}
	pw := []byte(password)
	sb := []byte(salt)

	// Digest B = H(pw || salt || pw).
	b := p.newHash()
	b.Write(pw)
	b.Write(sb)
	b.Write(pw)
	bSum := b.Sum(nil)

	// Digest A.
	a := p.newHash()
	a.Write(pw)
	a.Write(sb)
	for cnt := len(pw); cnt > 0; cnt -= p.size {
		if cnt > p.size {
			a.Write(bSum)
		} else {
			a.Write(bSum[:cnt])
		}
	}
	for cnt := len(pw); cnt > 0; cnt >>= 1 {
		if cnt&1 != 0 {
			a.Write(bSum)
		} else {
			a.Write(pw)
		}
	}
	aSum := a.Sum(nil)

	// Sequence P = H(pw repeated len(pw) times), spread to len(pw) bytes.
	dp := p.newHash()
	for i := 0; i < len(pw); i++ {
		dp.Write(pw)
	}
	dpSum := dp.Sum(nil)
	seqP := spread(dpSum, len(pw), p.size)

	// Sequence S = H(salt repeated 16+A[0] times), spread to len(salt) bytes.
	ds := p.newHash()
	rep := 16 + int(aSum[0])
	for i := 0; i < rep; i++ {
		ds.Write(sb)
	}
	dsSum := ds.Sum(nil)
	seqS := spread(dsSum, len(sb), p.size)

	// Strengthening loop.
	c := aSum
	for i := 0; i < rounds; i++ {
		ctx := p.newHash()
		if i&1 != 0 {
			ctx.Write(seqP)
		} else {
			ctx.Write(c)
		}
		if i%3 != 0 {
			ctx.Write(seqS)
		}
		if i%7 != 0 {
			ctx.Write(seqP)
		}
		if i&1 != 0 {
			ctx.Write(c)
		} else {
			ctx.Write(seqP)
		}
		c = ctx.Sum(nil)
	}

	// Encode C via the permutation table.
	out := make([]byte, 0, 86)
	at := func(idx int) byte {
		if idx < 0 {
			return 0
		}
		return c[idx]
	}
	for _, e := range p.perm {
		out = b64From24(out, at(e[0]), at(e[1]), at(e[2]), e[3])
	}

	if roundsExplicit && rounds != shaCryptDefaultRounds {
		return p.magic + "rounds=" + strconv.Itoa(rounds) + "$" + salt + "$" + string(out)
	}
	return p.magic + salt + "$" + string(out)
}

// spread repeats the block digest to produce a sequence of exactly n bytes:
// full copies of the digest followed by a truncated final copy.
func spread(digest []byte, n, size int) []byte {
	out := make([]byte, 0, n)
	for cnt := n; cnt > 0; cnt -= size {
		if cnt > size {
			out = append(out, digest...)
		} else {
			out = append(out, digest[:cnt]...)
		}
	}
	return out
}

// ── Verification ───────────────────────────────────────────────────────────────

// parseShaCryptRounds extracts the salt and (optional) rounds= parameter from a
// $5$/$6$ hash body, returning salt, rounds, whether rounds was explicit.
func parseShaCryptFields(body string) (salt string, rounds int, explicit bool) {
	if strings.HasPrefix(body, "rounds=") {
		rest := body[len("rounds="):]
		i := strings.IndexByte(rest, '$')
		if i < 0 {
			return "", 0, false
		}
		if r, err := strconv.Atoi(rest[:i]); err == nil {
			rounds, explicit = r, true
		}
		body = rest[i+1:]
	}
	// body is now "<salt>$<hash>"; the salt is everything before the last '$'.
	if j := strings.LastIndexByte(body, '$'); j >= 0 {
		salt = body[:j]
	} else {
		salt = body
	}
	return salt, rounds, explicit
}

// verifyMD5Crypt checks a candidate against a "$1$salt$hash" target.
func verifyMD5Crypt(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$1$") {
		return false, errors.New("invalid md5crypt hash (missing $1$ prefix)")
	}
	body := targetHash[len("$1$"):]
	j := strings.LastIndexByte(body, '$')
	if j < 0 {
		return false, errors.New("invalid md5crypt hash (missing salt separator)")
	}
	salt := body[:j]
	return md5cryptRaw(candidate, salt) == targetHash, nil
}

// verifyAPR1 checks a candidate against an Apache "$apr1$" hash.
func verifyAPR1(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$apr1$") {
		return false, errors.New("invalid apr1 hash (missing $apr1$ prefix)")
	}
	body := targetHash[len("$apr1$"):]
	j := strings.LastIndexByte(body, '$')
	if j < 0 {
		return false, errors.New("invalid apr1 hash (missing salt separator)")
	}
	return md5cryptMagic(candidate, body[:j], "$apr1$") == targetHash, nil
}

// ── NetBSD / Juniper SHA1-crypt ($sha1$) ─────────────────────────────────────

// sha1CryptRaw implements NetBSD's HMAC-SHA1-based password hash. The initial
// message is "salt$sha1$rounds"; each remaining round HMACs the previous
// digest with the password as key. The 20-byte result is padded with one zero
// byte and emitted with crypt's little-endian Base64 alphabet.
func sha1CryptRaw(password, salt string, rounds int) string {
	key := []byte(password)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write([]byte(salt + "$sha1$" + strconv.Itoa(rounds)))
	digest := mac.Sum(nil)
	for i := 1; i < rounds; i++ {
		mac = hmac.New(sha1.New, key)
		_, _ = mac.Write(digest)
		digest = mac.Sum(nil)
	}
	out := make([]byte, 0, 28)
	for i := 0; i < 18; i += 3 {
		out = b64From24(out, digest[i], digest[i+1], digest[i+2], 4)
	}
	out = b64From24(out, digest[18], digest[19], 0, 4)
	return "$sha1$" + strconv.Itoa(rounds) + "$" + salt + "$" + string(out)
}

func verifySHA1Crypt(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "sha1" {
		return false, errors.New("invalid sha1crypt hash (need $sha1$rounds$salt$checksum)")
	}
	rounds, err := strconv.Atoi(parts[2])
	if err != nil || rounds < 1 || rounds > maxKDFIterations {
		return false, errors.New("invalid sha1crypt round count")
	}
	if len(parts[3]) > 64 || len(parts[4]) != 28 {
		return false, errors.New("invalid sha1crypt salt or checksum length")
	}
	for _, ch := range parts[3] + parts[4] {
		if !strings.ContainsRune(itoa64, ch) {
			return false, errors.New("invalid sha1crypt alphabet")
		}
	}
	return sha1CryptRaw(candidate, parts[3], rounds) == targetHash, nil
}

// verifyShaCrypt checks a candidate against a $5$/$6$ target for the given params.
func verifyShaCrypt(p shaCryptParams, targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, p.magic) {
		return false, errors.New("invalid " + p.magic + " hash prefix")
	}
	salt, rounds, explicit := parseShaCryptFields(targetHash[len(p.magic):])
	return shaCryptRaw(p, candidate, salt, rounds, explicit) == targetHash, nil
}
