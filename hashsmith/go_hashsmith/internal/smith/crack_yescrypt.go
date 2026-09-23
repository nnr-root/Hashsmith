package smith

// yescrypt, the /etc/shadow scheme of every current Linux distribution.
//
//	$y$<parameters>$<salt>$<hash>
//
// Debian 12, Ubuntu 22.04 and later, Fedora 35 and later and Kali all create
// accounts with this by default, which makes it the most consequential hash a
// shadow file can contain — and it was the one scheme this tool's own shadow
// reader had to report as unsupported.
//
// The implementation is Openwall's own Go port, by yescrypt's designer. That
// is a deliberate choice over writing another one: yescrypt is scrypt with
// pwxform in place of Salsa20/8, a ROM option and a cost encoding that packs
// N, r and flags into single characters, and a subtly wrong reimplementation
// would not fail loudly — it would quietly never crack anything. The port
// supports the parameter range libxcrypt generates, which is the range every
// distribution's shadow file is in; a record outside it is refused rather
// than answered.
//
// Note what this does NOT cover: "$gy$" is gost-yescrypt, which substitutes
// Streebog for SHA-256 inside the same construction, and gets its own answer
// rather than being read as yescrypt.

import (
	"crypto/subtle"
	"errors"
	"strings"

	yescrypt "github.com/openwall/yescrypt-go"
)

const (
	yescryptPrefix     = "$y$"
	gostYescryptPrefix = "$gy$"
)

// isYescrypt reports whether a record is a yescrypt hash: the prefix, and the
// four fields crypt(3) requires.
func isYescrypt(target string) bool {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, yescryptPrefix) {
		return false
	}
	// $y$<params>$<salt>$<hash> splits into five, the first being empty.
	f := strings.Split(t, "$")
	return len(f) == 5 && f[2] != "" && f[3] != "" && f[4] != ""
}

// verifyYescrypt checks a candidate against a yescrypt record by recomputing
// the whole encoding from it — the record is its own setting string, which is
// what crypt(3) means by one.
func verifyYescrypt(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, gostYescryptPrefix) {
		return false, errors.New("this is gost-yescrypt ($gy$), which uses Streebog in place of " +
			"SHA-256 inside the same construction and is not the same hash")
	}
	if !isYescrypt(t) {
		return false, errors.New("invalid yescrypt record (need $y$<params>$<salt>$<hash>)")
	}
	got, err := yescrypt.Hash([]byte(candidate), []byte(t))
	if err != nil {
		return false, errors.New("yescrypt: " + err.Error())
	}
	return subtle.ConstantTimeCompare(got, []byte(t)) == 1, nil
}
