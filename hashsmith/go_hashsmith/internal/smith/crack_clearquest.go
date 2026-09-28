package smith

// Rational ClearQuest, whose stored password verifier is a 32-bit sum.
//
//	$cq$<username>$<8 hex>
//
// The check walks the username adding table entries indexed by position plus
// character, walks the password doing the same with the username's length
// folded in, and adds one more entry indexed by the two lengths. The result is
// thirty-two bits.
//
// It is not a hash and nothing about it is one-way by design: there is no
// avalanche, the contributions commute, and a password of the right length
// can be adjusted character by character to reach any target. Its own
// reference vectors sit four to a username. A match here says the candidate is
// one of an enormous family that the server would also accept — which, for
// getting in, is all that is needed, and is exactly why storing a checksum is
// not storing a password.

import (
	"errors"
	"strconv"
	"strings"
)

const clearQuestPrefix = "$cq$"

func clearQuestFields(target string) (user string, want uint32, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, clearQuestPrefix) {
		return "", 0, errors.New("not a ClearQuest record")
	}
	body := t[len(clearQuestPrefix):]
	i := strings.LastIndexByte(body, '$')
	if i < 0 {
		return "", 0, errors.New("a ClearQuest record is $cq$<user>$<checksum>")
	}
	user = body[:i]
	sum := body[i+1:]
	if len(sum) != 8 || !isHex(sum) {
		return "", 0, errors.New("a ClearQuest checksum is eight hex characters")
	}
	n, err := strconv.ParseUint(sum, 16, 32)
	if err != nil {
		return "", 0, errors.New("a ClearQuest checksum is eight hex characters")
	}
	return user, uint32(n), nil
}

func verifyClearQuest(target, candidate string) (bool, error) {
	user, want, err := clearQuestFields(target)
	if err != nil {
		return false, err
	}
	var a uint32
	for i := 0; i < len(user); i++ {
		a += clearQuestRandomNumbers[(i+int(user[i]))&0x7ff]
	}
	for i := 0; i < len(candidate); i++ {
		a += clearQuestRandomNumbers[(i+int(candidate[i])+len(user))&0x7ff]
	}
	a += clearQuestRandomNumbers[(len(user)+len(candidate))&0x7ff]
	return a == want, nil
}

func isClearQuest(target string) bool {
	_, _, err := clearQuestFields(target)
	return err == nil
}
