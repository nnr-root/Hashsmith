package smith

// bcrypt's "$2x$" — the variant that exists to reproduce a bug.
//
// In 2011 a sign-extension mistake was found in crypt_blowfish: when the key
// schedule packed the password's bytes into 32-bit words, it read each byte as
// a SIGNED char. A byte below 0x80 is unaffected; one at or above it arrives
// as a negative number, and OR-ing that into the accumulator sets every bit
// above the byte as well. Passwords made only of ASCII hash identically either
// way — which is why the bug survived fourteen years — and passwords with any
// byte of UTF-8 above the ASCII range hash to something much weaker, because
// those set bits swamp the rest of the word.
//
// The fix introduced "$2y$" for the corrected schedule and "$2x$" for the old
// one, so that existing records could be marked rather than silently
// reinterpreted. A "$2x$" record therefore does not mean "an old hash"; it
// means "a hash that was DELIBERATELY kept buggy", and the password behind one
// is by construction more likely than average to be non-ASCII — which is the
// only reason the distinction was ever worth keeping.
//
// The bug is in how bytes become words, not in anything else, so it need not
// be implemented as a second bcrypt. The schedule reads eighteen words, four
// bytes each, cycling the key: seventy-two byte reads. Work out what the buggy
// reader would have produced for those seventy-two positions, write it down as
// a seventy-two-byte key, and an ORDINARY bcrypt over that key produces the
// "$2x$" digest exactly.
//
// The derivation, per four-byte group:
//
//	d = 0; for each byte b: d = d<<8 | signExtend(b)
//
// signExtend(b) is b for b < 0x80 and 0xFFFFFF00|b otherwise. Those extra bits
// are shifted left with everything after them, so a byte at or above 0x80
// fills every byte position BEFORE it in the group with 0xFF — and nothing
// after it. Byte k of the group therefore becomes 0xFF if any later byte in
// the same group has its high bit set, and is otherwise itself.

import (
	"errors"
	"strings"

	"hashsmith-go/internal/bcryptlane"
)

const bcryptSignExtPrefix = "$2x$"

// bcryptScheduleBytes is how many key bytes bcrypt's schedule reads: eighteen
// words of four.
const bcryptScheduleBytes = 72

// bcryptSignExtendedKey builds the key an ordinary bcrypt must be given to
// reproduce the buggy schedule for this password.
func bcryptSignExtendedKey(password string) []byte {
	// The key is the password with its terminating NUL, as every C bcrypt
	// uses it.
	key := make([]byte, len(password)+1)
	copy(key, password)

	// Lay out the seventy-two bytes the schedule will read, cycling as it
	// does.
	out := make([]byte, bcryptScheduleBytes)
	for i := range out {
		out[i] = key[i%len(key)]
	}
	// Within each four-byte group, a byte at or above 0x80 sets every earlier
	// byte of that group to 0xFF.
	for base := 0; base < bcryptScheduleBytes; base += 4 {
		fill := false
		for k := 3; k >= 0; k-- {
			if fill {
				out[base+k] = 0xFF
			}
			if out[base+k]&0x80 != 0 {
				fill = true
			}
		}
	}
	return out
}

// verifyBcryptSignExt checks a $2x$ record.
func verifyBcryptSignExt(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, bcryptSignExtPrefix) {
		return false, errors.New("not a $2x$ bcrypt record")
	}
	h, err := bcryptlane.NewHasher(t)
	if err != nil {
		return false, errors.New("invalid $2x$ bcrypt record")
	}
	return h.MatchesRawKey(bcryptSignExtendedKey(candidate)), nil
}

func isBcryptSignExt(target string) bool {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, bcryptSignExtPrefix) {
		return false
	}
	_, err := bcryptlane.NewHasher(t)
	return err == nil
}
