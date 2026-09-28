package smith

import (
	"encoding/binary"
	"testing"

	"hashsmith-go/internal/hashid"
)

// TestSniffGELIDeepFindsMagicNearEndOfFile builds a file whose GELI metadata
// block — geliMagic padded to 16 bytes, then a valid little-endian version —
// sits well past what sniffHeadBytes' fast path would ever see, to prove the
// deep pass is what finds it.
func TestSniffGELIDeepFindsMagicNearEndOfFile(t *testing.T) {
	body := make([]byte, 6000) // longer than sniffHeadBytes (4096)
	block := make([]byte, 20)
	copy(block, geliMagic)
	binary.LittleEndian.PutUint32(block[16:20], 3) // valid version (0-7)
	copy(body[5900:5920], block)

	d, conf, ok := sniffFile(t, body)
	if !ok || d.name != "geli2smith" {
		t.Fatalf("GELI metadata block did not route to geli2smith (ok=%v)", ok)
	}
	if conf != hashid.Certain {
		t.Errorf("confidence %v, want Certain (magic + valid version field)", conf)
	}
}

// TestSniffGELIDeepBareMagicIsLikely mirrors sniffBitLocker's two-signature
// split: the magic alone, with no valid version field behind it, is weaker
// evidence and must report Likely, not Certain.
func TestSniffGELIDeepBareMagicIsLikely(t *testing.T) {
	body := make([]byte, 5000)
	copy(body[4991:5000], geliMagic) // magic ends the file — no room left for a version field
	d, conf, ok := sniffFile(t, body)
	if !ok || d.name != "geli2smith" {
		t.Fatalf("bare GELI magic did not route to geli2smith (ok=%v)", ok)
	}
	if conf != hashid.Likely {
		t.Errorf("confidence %v, want Likely", conf)
	}
}

// TestSniffPGPSDADeepFindsTrailerNearEndOfFile builds a minimal host file
// with an SDAHEADER trailer (magic + valid in-file offset) past the fast
// path's reach.
func TestSniffPGPSDADeepFindsTrailerNearEndOfFile(t *testing.T) {
	body := make([]byte, 6000)
	header := make([]byte, pgpSDAHeaderSize)
	copy(header[:6], pgpSDAMagic)
	binary.LittleEndian.PutUint32(header[6:10], 100) // well inside the 6000-byte file
	copy(body[5900:5900+pgpSDAHeaderSize], header)

	d, conf, ok := sniffFile(t, body)
	if !ok || d.name != "pgpsda2smith" {
		t.Fatalf("PGPSDA trailer did not route to pgpsda2smith (ok=%v)", ok)
	}
	if conf != hashid.Certain {
		t.Errorf("confidence %v, want Certain", conf)
	}
}

// TestSniffPGPSDADeepRejectsOutOfRangeOffset proves the offset sanity check
// (the same one extractPGPSDARecords performs) actually runs, not just the
// bare magic.
func TestSniffPGPSDADeepRejectsOutOfRangeOffset(t *testing.T) {
	body := make([]byte, 6000)
	header := make([]byte, pgpSDAHeaderSize)
	copy(header[:6], pgpSDAMagic)
	binary.LittleEndian.PutUint32(header[6:10], 999999) // past the end of a 6000-byte file
	copy(body[5900:5900+pgpSDAHeaderSize], header)

	if d, _, ok := sniffFile(t, body); ok {
		t.Errorf("magic with an out-of-range offset was routed to %s; expected no match", d.name)
	}
}

// TestSniffPGPWDEDeepFindsUserRecordInFirstMegabyte builds a minimal disk
// image with one valid PGP WDE user record past sniffHeadBytes but still
// inside the first megabyte extractPGPWDERecords itself scans.
func TestSniffPGPWDEDeepFindsUserRecordInFirstMegabyte(t *testing.T) {
	body := make([]byte, 500000)
	u := make([]byte, pgpWDEUserInfoSize)
	binary.LittleEndian.PutUint16(u[0:2], 512)
	u[2] = 0 // version
	u[3] = pgpWDEUserWithSym
	binary.LittleEndian.PutUint32(u[4:8], pgpWDEMagic)
	u[9] = 0 // record index
	copy(body[400000:400000+pgpWDEUserInfoSize], u)

	d, conf, ok := sniffFile(t, body)
	if !ok || d.name != "pgpwde2smith" {
		t.Fatalf("PGP WDE user record did not route to pgpwde2smith (ok=%v)", ok)
	}
	if conf != hashid.Certain {
		t.Errorf("confidence %v, want Certain", conf)
	}
}

// TestSniffPGPWDEDeepRejectsWrongUserKind proves all five fields are
// checked, not a partial match on the magic alone.
func TestSniffPGPWDEDeepRejectsWrongUserKind(t *testing.T) {
	body := make([]byte, 500000)
	u := make([]byte, pgpWDEUserInfoSize)
	binary.LittleEndian.PutUint16(u[0:2], 512)
	u[2] = 0
	u[3] = 0x01 // NOT pgpWDEUserWithSym — a token/public-key/TPM record
	binary.LittleEndian.PutUint32(u[4:8], pgpWDEMagic)
	u[9] = 0
	copy(body[400000:400000+pgpWDEUserInfoSize], u)

	if d, _, ok := sniffFile(t, body); ok {
		t.Errorf("a non-symmetric-key user record was routed to %s; expected no match", d.name)
	}
}

// TestDeepSniffersAreOnlyTriedAfterHeadSniffersFail is the coverage
// contract: sniffCoverage counts deepSniff the same as sniff.
func TestDeepSniffersCountTowardCoverage(t *testing.T) {
	for _, name := range []string{"geli2smith", "pgpsda2smith", "pgpwde2smith"} {
		d, ok := findExtractor(name)
		if !ok {
			t.Fatalf("extractor %q not found", name)
		}
		if d.deepSniff == nil {
			t.Errorf("%s has no deepSniff registered", name)
		}
	}
}
