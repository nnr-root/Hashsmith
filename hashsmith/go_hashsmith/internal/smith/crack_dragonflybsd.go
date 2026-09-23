package smith

// DragonFly BSD's crypt(3) schemes, and the bug that made each of them two
// formats.
//
// (The file is named crack_dragonflybsd.go rather than crack_dragonfly.go
// because Go reads a trailing "_dragonfly" as a build constraint for the
// DragonFly BSD operating system and drops the file everywhere else. It does
// so silently: the build fails at the call sites with "undefined", naming
// functions that are plainly there in a file plainly in the package.)
//
//	$3$<salt>$<44 chars>   SHA-256
//	$4$<salt>$<86 chars>   SHA-512
//
// Both are a single unsalted-looking pass: the password, then the tag, then
// the salt, hashed once. No iteration count, no stretching — DragonFly took
// the shape of sha256crypt and none of its work factor.
//
// What makes each of them two formats is that the buffer holding the tag was
// not the length the code that filled it assumed. On a 32-bit build the bytes
// after "$3$\0" were whatever followed in memory and happened to be nothing;
// on a 64-bit build they were the next eight bytes of the neighbouring string
// — "sha5" for the SHA-256 scheme and "/etc" for the SHA-512 one. Those four
// characters are inside the digest. A password hashed on a 32-bit DragonFly
// does not verify on a 64-bit one and vice versa, and the record cannot say
// which it came from, so both are offered and either may answer.
//
// The digest encoding carries a second bug of the same kind. SHA-512 is 64
// bytes and DragonFly's base64 loop emits 62 of them, so the last two bytes
// of the digest are simply not in the record. Comparing all 64 fails against
// every correct password; comparing the 62 that are there is what the format
// actually stores.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strings"
)

// dragonflyTag is the byte string hashed between the password and the salt,
// for each scheme and each word size.
var dragonflyTags = map[string][]byte{
	"dragonfly3-32": []byte("$3$\x00"),
	"dragonfly3-64": []byte("$3$\x00sha5"),
	"dragonfly4-32": []byte("$4$\x00"),
	"dragonfly4-64": []byte("$4$\x00/etc"),
}

func dragonflyFields(target, tag string) (salt, digest string, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, tag) {
		return "", "", errors.New("not a DragonFly " + tag + " record")
	}
	salt, digest, ok := strings.Cut(t[len(tag):], "$")
	if !ok || salt == "" || len(salt) > 16 {
		return "", "", errors.New("a DragonFly record is <tag><salt>$<digest>")
	}
	for i := 0; i < len(salt); i++ {
		if strings.IndexByte(itoa64, salt[i]) < 0 {
			return "", "", errors.New("a DragonFly salt is crypt(3) characters")
		}
	}
	return salt, digest, nil
}

// dragonflyDecode reverses DragonFly's base64, which scatters each group of
// three digest bytes to positions i, i+off1 and i+off2 rather than writing
// them consecutively. The two offsets and the two positions the final group
// fills are given explicitly rather than derived, because they are not
// consistent between the two schemes: the SHA-256 encoding uses 11 and 21 and
// finishes at 10 and 31, the SHA-512 one uses 21 and 42 and finishes at 20 and
// 41. Deriving one from the other gets the SHA-256 case right by coincidence
// and the SHA-512 case wrong.
//
// The returned mask says which byte positions the record actually carries —
// the two the SHA-512 encoding drops are not among them.
func dragonflyDecode(s string, size, groups, off1, off2, tail1, tail2 int) (out, mask []byte, err error) {
	if len(s) != 4*(groups+1) {
		return nil, nil, errors.New("a DragonFly digest is " + itoaSmall(4*(groups+1)) + " characters")
	}
	out = make([]byte, size)
	mask = make([]byte, size)
	p := 0
	read := func() (uint32, error) {
		var v uint32
		for k := 0; k < 4; k++ {
			i := strings.IndexByte(itoa64, s[p+k])
			if i < 0 {
				return 0, errors.New("a DragonFly digest is crypt(3) characters")
			}
			v |= uint32(i) << (6 * k)
		}
		p += 4
		return v, nil
	}
	for i := 0; i < groups; i++ {
		v, err := read()
		if err != nil {
			return nil, nil, err
		}
		out[i], out[i+off1], out[i+off2] = byte(v>>16), byte(v>>8), byte(v)
		mask[i], mask[i+off1], mask[i+off2] = 1, 1, 1
	}
	v, err := read()
	if err != nil {
		return nil, nil, err
	}
	out[tail1], out[tail2] = byte(v>>16), byte(v>>8)
	mask[tail1], mask[tail2] = 1, 1
	return out, mask, nil
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func verifyDragonfly(target, candidate, typ string) (bool, error) {
	tagBytes, ok := dragonflyTags[typ]
	if !ok {
		return false, errors.New("unknown DragonFly variant")
	}
	prefix := string(tagBytes[:3])
	salt, digest, err := dragonflyFields(target, prefix)
	if err != nil {
		return false, err
	}

	var want, mask []byte
	var got []byte
	if prefix == "$3$" {
		if want, mask, err = dragonflyDecode(digest, 32, 10, 11, 21, 10, 31); err != nil {
			return false, err
		}
		h := sha256.New()
		_, _ = h.Write([]byte(candidate))
		_, _ = h.Write(tagBytes)
		_, _ = h.Write([]byte(salt))
		got = h.Sum(nil)
	} else {
		if want, mask, err = dragonflyDecode(digest, 64, 20, 21, 42, 20, 41); err != nil {
			return false, err
		}
		h := sha512.New()
		_, _ = h.Write([]byte(candidate))
		_, _ = h.Write(tagBytes)
		_, _ = h.Write([]byte(salt))
		got = h.Sum(nil)
	}
	// Only the bytes the record carries are compared. Everything else is a
	// byte DragonFly's own encoder never wrote.
	a := make([]byte, 0, len(want))
	b := make([]byte, 0, len(want))
	for i := range mask {
		if mask[i] == 1 {
			a = append(a, want[i])
			b = append(b, got[i])
		}
	}
	return hmac.Equal(a, b), nil
}

func isDragonfly3(target string) bool {
	_, d, err := dragonflyFields(target, "$3$")
	return err == nil && len(d) == 44
}

func isDragonfly4(target string) bool {
	_, d, err := dragonflyFields(target, "$4$")
	return err == nil && len(d) == 84
}
