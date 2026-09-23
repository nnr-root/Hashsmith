package smith

// John's LUKS spelling: the partition header, verbatim.
//
// hashcat's luks2hashcat.py and Hashsmith's own luks2smith both take the
// header apart and write out the nine or twelve fields a cracker actually
// consults. John ships the LUKS1 header as one hex blob and the keyslot's
// anti-forensic key material as base64:
//
//	$luks$1$<header length>$<header hex>$<material length>$<material base64>$<mk digest hex>
//
// Nothing new is derived from that. Every field the other two spellings name
// sits at a fixed offset inside the header, so reading it is a matter of
// following the on-disk layout: cipher and mode and hash as NUL-terminated
// strings, then the master-key digest, salt and iteration count, then eight
// 48-byte keyslot descriptors. The trailing digest repeats what the header
// already holds at offset 112, and is required to agree rather than trusted —
// a record whose two copies disagree is not one to answer for.

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
)

const (
	luksHeaderSize     = 592 // the phdr plus all eight keyslot descriptors
	luksKeySlotOffset  = 208
	luksKeySlotSize    = 48
	luksNumKeySlots    = 8
	luksKeyEnabled     = 0x00ac71f3
	luksMaxKeyBytes    = 64
	luksMaxStripes     = 4000
	luksMaxKeyMaterial = luksMaxKeyBytes * luksMaxStripes
)

var luksMagic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}

// luksCString reads one of the header's fixed-width NUL-padded strings.
func luksCString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// parseLUKSJohn reads John's spelling into the same parameters the other two
// produce. The key material covers exactly one keyslot, so the slot it belongs
// to is the first enabled one whose stripe count accounts for its length.
func parseLUKSJohn(f []string) (*luksParams, error) {
	if len(f) != 5 && len(f) != 6 {
		return nil, errors.New("invalid LUKS header record")
	}
	hdrLen, err := strconv.Atoi(f[1])
	if err != nil || hdrLen < luksHeaderSize || hdrLen > 1<<20 {
		return nil, errors.New("invalid LUKS header length")
	}
	hdr, err := hex.DecodeString(f[2])
	if err != nil || len(hdr) != hdrLen {
		return nil, errors.New("invalid LUKS header")
	}
	if !bytes.Equal(hdr[:len(luksMagic)], luksMagic) {
		return nil, errors.New("LUKS header does not start with the LUKS magic")
	}
	if v := binary.BigEndian.Uint16(hdr[6:8]); v != 1 {
		return nil, errors.New("unsupported LUKS header version " + strconv.Itoa(int(v)))
	}
	matLen, err := strconv.Atoi(f[3])
	if err != nil || matLen <= 0 || matLen > luksMaxKeyMaterial {
		return nil, errors.New("invalid LUKS key material length")
	}
	material, err := base64.StdEncoding.DecodeString(f[4])
	if err != nil || len(material) != matLen {
		return nil, errors.New("invalid LUKS key material")
	}

	keyBytes := int(binary.BigEndian.Uint32(hdr[108:112]))
	if keyBytes <= 0 || keyBytes > luksMaxKeyBytes {
		return nil, errors.New("invalid LUKS master-key size")
	}
	mkDigest := append([]byte(nil), hdr[112:132]...)
	if len(f) == 6 {
		stated, err := hex.DecodeString(f[5])
		if err != nil {
			return nil, errors.New("invalid LUKS master-key digest")
		}
		if subtle.ConstantTimeCompare(stated, mkDigest) != 1 {
			return nil, errors.New("this LUKS record's two copies of the master-key digest disagree")
		}
	}

	// One blob of key material belongs to one keyslot. Enabled slots that do
	// not account for its length are some other slot's, and are skipped.
	slot := -1
	var slotIter, stripes int
	for i := 0; i < luksNumKeySlots; i++ {
		o := luksKeySlotOffset + i*luksKeySlotSize
		if binary.BigEndian.Uint32(hdr[o:o+4]) != luksKeyEnabled {
			continue
		}
		s := int(binary.BigEndian.Uint32(hdr[o+44 : o+48]))
		if s <= 0 || s > luksMaxStripes || s*keyBytes != len(material) {
			continue
		}
		slot, slotIter, stripes = i, int(binary.BigEndian.Uint32(hdr[o+4:o+8])), s
		break
	}
	if slot < 0 {
		return nil, errors.New("this LUKS header has no enabled keyslot matching the key material")
	}
	o := luksKeySlotOffset + slot*luksKeySlotSize

	p := &luksParams{
		hashSpec:    luksCString(hdr[72:104]),
		cipherName:  luksCString(hdr[8:40]),
		cipherMode:  luksCString(hdr[40:72]),
		keyBytes:    keyBytes,
		mkDigest:    mkDigest,
		mkSalt:      append([]byte(nil), hdr[132:164]...),
		mkIter:      int(binary.BigEndian.Uint32(hdr[164:168])),
		slotIter:    slotIter,
		slotSalt:    append([]byte(nil), hdr[o+8:o+40]...),
		stripes:     stripes,
		keyMaterial: material,
	}
	if p.mkIter <= 0 || p.slotIter <= 0 {
		return nil, errors.New("invalid LUKS iteration count")
	}
	return p, nil
}
