package smith

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ── 7-Zip next-header parsing ─────────────────────────────────────────────────
//
// A 7z archive's signature header points at a "next header", which is either a
// plain Header or an EncodedHeader — a StreamsInfo describing how to decode the
// real one. Either way the structure that matters is the same: a PackInfo
// giving where the packed streams live, an UnPackInfo giving the folders and
// the coder chain inside each, and digests giving the CRC of each folder's
// output.
//
// Reaching those is what password verification needs and what a byte-grep for
// the AES codec ID cannot give: the grep finds the salt and IV, but not which
// bytes are the ciphertext, how long the plaintext is, or what it should
// checksum to. Everything is length-prefixed with 7z's own variable-width
// integers and nested, so it has to be parsed rather than searched.
//
// Reference: the 7-Zip source distribution's DOC/7zFormat.txt.

const (
	kEnd                 = 0x00
	kHeader              = 0x01
	kArchiveProperties   = 0x02
	kAdditionalStreams   = 0x03
	kMainStreamsInfo     = 0x04
	kFilesInfo           = 0x05
	kPackInfo            = 0x06
	kUnPackInfo          = 0x07
	kSubStreamsInfo      = 0x08
	kSize                = 0x09
	kCRC                 = 0x0A
	kFolder              = 0x0B
	kCodersUnPackSize    = 0x0C
	kNumUnPackStream     = 0x0D
	kEncodedHeaderMarker = 0x17
)

// sevenZipReader walks a next-header byte slice.
type sevenZipReader struct {
	b   []byte
	pos int
}

func (r *sevenZipReader) byteAt() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, errors.New("7z header: unexpected end")
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

func (r *sevenZipReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, errors.New("7z header: unexpected end")
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *sevenZipReader) uint32LE() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// number reads 7z's variable-width integer: the high bits of the first byte
// say how many more bytes follow, and the remaining low bits are the value's
// most significant part.
func (r *sevenZipReader) number() (uint64, error) {
	first, err := r.byteAt()
	if err != nil {
		return 0, err
	}
	mask := byte(0x80)
	var value uint64
	for i := 0; i < 8; i++ {
		if first&mask == 0 {
			high := uint64(first) & (uint64(mask) - 1)
			value |= high << (i * 8)
			return value, nil
		}
		b, err := r.byteAt()
		if err != nil {
			return 0, err
		}
		value |= uint64(b) << (i * 8)
		mask >>= 1
	}
	return value, nil
}

// num reads a number and range-checks it into an int, so a corrupt or hostile
// header cannot turn into an enormous allocation.
func (r *sevenZipReader) num(what string, max int) (int, error) {
	v, err := r.number()
	if err != nil {
		return 0, err
	}
	if v > uint64(max) {
		return 0, fmt.Errorf("7z header: %s is %d, past the %d limit", what, v, max)
	}
	return int(v), nil
}

// bitVector reads n bits, most significant first.
func (r *sevenZipReader) bitVector(n int) ([]bool, error) {
	out := make([]bool, n)
	var b byte
	mask := byte(0)
	for i := 0; i < n; i++ {
		if mask == 0 {
			var err error
			if b, err = r.byteAt(); err != nil {
				return nil, err
			}
			mask = 0x80
		}
		out[i] = b&mask != 0
		mask >>= 1
	}
	return out, nil
}

// boolVector reads an "all defined" byte followed by a bit vector when it is 0.
func (r *sevenZipReader) boolVector(n int) ([]bool, error) {
	all, err := r.byteAt()
	if err != nil {
		return nil, err
	}
	if all != 0 {
		out := make([]bool, n)
		for i := range out {
			out[i] = true
		}
		return out, nil
	}
	return r.bitVector(n)
}

// sevenZipCoder is one coder in a folder's chain.
type sevenZipCoder struct {
	id            []byte
	props         []byte
	numInStreams  int
	numOutStreams int
}

// sevenZipFolder is one folder: a coder chain and the sizes its streams produce.
type sevenZipFolder struct {
	coders      []sevenZipCoder
	unpackSizes []uint64
	crc         uint32
	crcDefined  bool
	// numPackedStreams is how many of the archive's packed streams this
	// folder consumes. It is usually one, but a folder whose coders take more
	// inputs than the bind pairs supply draws the rest from the packed
	// streams — and then the folders that follow start further into the pack
	// list than their index suggests.
	numPackedStreams int
}

// sevenZipStreamsInfo is the part of a header that says where the bytes are.
type sevenZipStreamsInfo struct {
	packPos   uint64
	packSizes []uint64
	folders   []sevenZipFolder
}

const (
	maxSevenZipFolders = 1 << 16
	maxSevenZipCoders  = 1 << 10
	maxSevenZipStreams = 1 << 20
	maxSevenZipProps   = 1 << 16
)

// readStreamsInfo parses a StreamsInfo block, leaving r just past its kEnd.
func (r *sevenZipReader) readStreamsInfo() (*sevenZipStreamsInfo, error) {
	info := &sevenZipStreamsInfo{}
	for {
		id, err := r.byteAt()
		if err != nil {
			return nil, err
		}
		switch id {
		case kEnd:
			return info, nil
		case kPackInfo:
			if err := r.readPackInfo(info); err != nil {
				return nil, err
			}
		case kUnPackInfo:
			if err := r.readUnPackInfo(info); err != nil {
				return nil, err
			}
		case kSubStreamsInfo:
			if err := r.readSubStreamsInfo(info); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("7z header: unexpected id 0x%02x in StreamsInfo", id)
		}
	}
}

func (r *sevenZipReader) readPackInfo(info *sevenZipStreamsInfo) error {
	var err error
	if info.packPos, err = r.number(); err != nil {
		return err
	}
	n, err := r.num("pack stream count", maxSevenZipStreams)
	if err != nil {
		return err
	}
	for {
		id, err := r.byteAt()
		if err != nil {
			return err
		}
		switch id {
		case kEnd:
			return nil
		case kSize:
			info.packSizes = make([]uint64, n)
			for i := 0; i < n; i++ {
				if info.packSizes[i], err = r.number(); err != nil {
					return err
				}
			}
		case kCRC:
			if _, err := r.readDigests(n); err != nil {
				return err
			}
		default:
			return fmt.Errorf("7z header: unexpected id 0x%02x in PackInfo", id)
		}
	}
}

func (r *sevenZipReader) readUnPackInfo(info *sevenZipStreamsInfo) error {
	id, err := r.byteAt()
	if err != nil {
		return err
	}
	if id != kFolder {
		return fmt.Errorf("7z header: expected kFolder, got 0x%02x", id)
	}
	numFolders, err := r.num("folder count", maxSevenZipFolders)
	if err != nil {
		return err
	}
	external, err := r.byteAt()
	if err != nil {
		return err
	}
	if external != 0 {
		return errors.New("7z header: folders stored externally, which is not supported")
	}
	info.folders = make([]sevenZipFolder, numFolders)
	for i := range info.folders {
		if err := r.readFolder(&info.folders[i]); err != nil {
			return err
		}
	}

	if id, err = r.byteAt(); err != nil {
		return err
	}
	if id != kCodersUnPackSize {
		return fmt.Errorf("7z header: expected kCodersUnPackSize, got 0x%02x", id)
	}
	for i := range info.folders {
		total := 0
		for _, c := range info.folders[i].coders {
			total += c.numOutStreams
		}
		info.folders[i].unpackSizes = make([]uint64, total)
		for j := 0; j < total; j++ {
			if info.folders[i].unpackSizes[j], err = r.number(); err != nil {
				return err
			}
		}
	}

	for {
		if id, err = r.byteAt(); err != nil {
			return err
		}
		switch id {
		case kEnd:
			return nil
		case kCRC:
			digests, err := r.readDigests(numFolders)
			if err != nil {
				return err
			}
			for i := range info.folders {
				info.folders[i].crc = digests[i].crc
				info.folders[i].crcDefined = digests[i].defined
			}
		default:
			return fmt.Errorf("7z header: unexpected id 0x%02x in UnPackInfo", id)
		}
	}
}

func (r *sevenZipReader) readFolder(f *sevenZipFolder) error {
	numCoders, err := r.num("coder count", maxSevenZipCoders)
	if err != nil {
		return err
	}
	totalIn, totalOut := 0, 0
	f.coders = make([]sevenZipCoder, numCoders)
	for i := range f.coders {
		flags, err := r.byteAt()
		if err != nil {
			return err
		}
		idSize := int(flags & 0x0F)
		if f.coders[i].id, err = r.bytes(idSize); err != nil {
			return err
		}
		f.coders[i].numInStreams, f.coders[i].numOutStreams = 1, 1
		if flags&0x10 != 0 { // complex coder
			if f.coders[i].numInStreams, err = r.num("coder in-streams", maxSevenZipCoders); err != nil {
				return err
			}
			if f.coders[i].numOutStreams, err = r.num("coder out-streams", maxSevenZipCoders); err != nil {
				return err
			}
		}
		if flags&0x20 != 0 { // has attributes
			n, err := r.num("coder property size", maxSevenZipProps)
			if err != nil {
				return err
			}
			if f.coders[i].props, err = r.bytes(n); err != nil {
				return err
			}
		}
		totalIn += f.coders[i].numInStreams
		totalOut += f.coders[i].numOutStreams
	}

	// Bind pairs connect one coder's output to another's input.
	for i := 0; i < totalOut-1; i++ {
		if _, err := r.number(); err != nil { // in index
			return err
		}
		if _, err := r.number(); err != nil { // out index
			return err
		}
	}
	// When more than one input is fed from the packed streams, their indices
	// follow.
	packed := totalIn - (totalOut - 1)
	if packed < 1 {
		return errors.New("7z folder consumes no packed stream")
	}
	f.numPackedStreams = packed
	if packed > 1 {
		for i := 0; i < packed; i++ {
			if _, err := r.number(); err != nil {
				return err
			}
		}
	}
	return nil
}

type sevenZipDigest struct {
	crc     uint32
	defined bool
}

func (r *sevenZipReader) readDigests(n int) ([]sevenZipDigest, error) {
	defined, err := r.boolVector(n)
	if err != nil {
		return nil, err
	}
	out := make([]sevenZipDigest, n)
	for i := 0; i < n; i++ {
		out[i].defined = defined[i]
		if defined[i] {
			if out[i].crc, err = r.uint32LE(); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// readSubStreamsInfo walks the per-file sizes and CRCs.
//
// The CRCs here are not incidental. When a folder holds exactly one file,
// 7-Zip records that file's CRC in this block INSTEAD of in the folder
// itself, so a folder that looks CRC-less at the UnPackInfo level usually
// still has one — and that CRC is the difference between a record that can
// prove a password right and one that can only fail to prove it wrong. Every
// single-substream folder therefore adopts its substream's digest.
func (r *sevenZipReader) readSubStreamsInfo(info *sevenZipStreamsInfo) error {
	numUnpack := make([]int, len(info.folders))
	for i := range numUnpack {
		numUnpack[i] = 1
	}
	id, err := r.byteAt()
	if err != nil {
		return err
	}
	if id == kNumUnPackStream {
		for i := range info.folders {
			if numUnpack[i], err = r.num("substream count", maxSevenZipStreams); err != nil {
				return err
			}
		}
		if id, err = r.byteAt(); err != nil {
			return err
		}
	}

	total := 0
	for _, n := range numUnpack {
		total += n
	}
	if id == kSize {
		// Every folder's LAST substream size is implied by the folder size.
		for i := range info.folders {
			if numUnpack[i] == 0 {
				continue
			}
			for j := 0; j < numUnpack[i]-1; j++ {
				if _, err = r.number(); err != nil {
					return err
				}
			}
		}
		if id, err = r.byteAt(); err != nil {
			return err
		}
	}

	for id != kEnd {
		switch id {
		case kCRC:
			// Digests are present only for streams without a folder CRC.
			unknown := 0
			for i := range info.folders {
				if numUnpack[i] == 1 && info.folders[i].crcDefined {
					continue
				}
				unknown += numUnpack[i]
			}
			digests, err := r.readDigests(unknown)
			if err != nil {
				return err
			}
			at := 0
			for i := range info.folders {
				if numUnpack[i] == 1 && info.folders[i].crcDefined {
					continue
				}
				if numUnpack[i] == 1 && at < len(digests) && digests[at].defined {
					info.folders[i].crc = digests[at].crc
					info.folders[i].crcDefined = true
				}
				at += numUnpack[i]
			}
		default:
			return fmt.Errorf("7z header: unexpected id 0x%02x in SubStreamsInfo", id)
		}
		if id, err = r.byteAt(); err != nil {
			return err
		}
	}
	return nil
}

// sevenZipAESCoderID is 7-Zip's AES-256 + SHA-256 codec.
var sevenZipAESCoderID = []byte{0x06, 0xF1, 0x07, 0x01}

// sevenZipAESParams are the KDF parameters carried in an AES coder's property
// block: one byte of numCyclesPower and flags, one byte of salt and IV
// lengths, then the salt and IV themselves.
type sevenZipAESParams struct {
	numCyclesPower int
	salt           []byte
	iv             []byte
}

func parseSevenZipAESProps(props []byte) (*sevenZipAESParams, error) {
	if len(props) < 2 {
		return nil, errors.New("7z AES properties too short")
	}
	p := &sevenZipAESParams{numCyclesPower: int(props[0] & 0x3F)}
	saltLen := int((props[1]>>4)&0x0F) + int(props[0]>>7&1)
	ivLen := int(props[1]&0x0F) + int(props[0]>>6&1)
	if 2+saltLen+ivLen > len(props) {
		return nil, errors.New("7z AES properties: salt and IV exceed the property block")
	}
	p.salt = props[2 : 2+saltLen]
	iv := make([]byte, 16)
	copy(iv, props[2+saltLen:2+saltLen+ivLen])
	p.iv = iv
	return p, nil
}
