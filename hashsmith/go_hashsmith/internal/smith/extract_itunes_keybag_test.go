package smith

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// iTunes backup key bags hold SEVERAL tag groups — one per protection class —
// and the fields of one group must not be paired with those of another.
//
// Taking the first SALT, the first ITER and the first WPKY found anywhere in
// the file does exactly that when the layout puts an unrelated WPKY first,
// which is legal. The result is a record that is perfectly well formed and
// cannot crack: the salt and iteration count are the backup's and the wrapped
// key is something else's, so a user runs a full attack and gets "not found"
// for the correct password.
//
// The salt, iteration count and wrapped key below are hashcat's published
// -m 14700 example taken apart, so "hashcat" is known to be the right answer
// for the group they belong to.
func TestITunesKeybagDoesNotMixGroups(t *testing.T) {
	const password = "hashcat"
	realSalt, err := hex.DecodeString("4542263740587424862267232255853830404566")
	if err != nil {
		t.Fatal(err)
	}
	realWpky, err := hex.DecodeString(
		"b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642")
	if err != nil {
		t.Fatal(err)
	}
	iter := []byte{0, 0, 0x27, 0x10} // 10000

	tlv := func(tag string, v []byte) []byte {
		out := append([]byte(tag), 0, 0, 0, 0)
		binary.BigEndian.PutUint32(out[4:], uint32(len(v)))
		return append(out, v...)
	}

	// A decoy WPKY from another protection class, far enough ahead of the
	// real group that no honest reading could pair them.
	decoy := make([]byte, 40)
	for i := range decoy {
		decoy[i] = 0xBB
	}
	blob := append([]byte("bplist00"), tlv("WPKY", decoy)...)
	blob = append(blob, make([]byte, 400)...)
	blob = append(blob, tlv("SALT", realSalt)...)
	blob = append(blob, tlv("ITER", iter)...)
	blob = append(blob, tlv("WPKY", realWpky)...)

	recs, err := extractITunesRecords(extractorFixture(t, "Manifest.plist", blob))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	ok, err := verifyCandidate(password, recs[0], "itunes", "", "")
	if err != nil {
		t.Fatalf("verifying %s: %v", recs[0], err)
	}
	if !ok {
		t.Errorf("the extracted record does not crack with the password its key bag group "+
			"belongs to, so fields were taken from different groups:\n%s", recs[0])
	}
	if ok, _ := verifyCandidate("definitely-not-it-9137", recs[0], "itunes", "", ""); ok {
		t.Error("the extracted record accepted a wrong password")
	}
}

// The ordinary single-group layout must keep working unchanged.
func TestITunesKeybagSingleGroup(t *testing.T) {
	realSalt, _ := hex.DecodeString("4542263740587424862267232255853830404566")
	realWpky, _ := hex.DecodeString(
		"b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642")
	tlv := func(tag string, v []byte) []byte {
		out := append([]byte(tag), 0, 0, 0, 0)
		binary.BigEndian.PutUint32(out[4:], uint32(len(v)))
		return append(out, v...)
	}
	blob := append([]byte("bplist00"), tlv("SALT", realSalt)...)
	blob = append(blob, tlv("ITER", []byte{0, 0, 0x27, 0x10})...)
	blob = append(blob, tlv("WPKY", realWpky)...)

	recs, err := extractITunesRecords(extractorFixture(t, "Manifest.plist", blob))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := verifyCandidate("hashcat", recs[0], "itunes", "", "")
	if err != nil || !ok {
		t.Errorf("a plain single-group key bag no longer extracts a crackable record "+
			"(ok=%v err=%v):\n%s", ok, err, recs[0])
	}
}
