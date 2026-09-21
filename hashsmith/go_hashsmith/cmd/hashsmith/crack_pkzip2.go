package main

// PKZIP / ZipCrypto archives — Hashcat 17200, 17210, 17220, 17225 and 17230.
//
//	$pkzip2$<count>*<checksum size>*<entry>[*<entry>...]*$/pkzip2$
//
// One record can describe several files from one archive, because a single
// ZipCrypto file often cannot settle a password on its own: the cheap check is
// one byte of the encryption header, and one byte is 8 bits. Entries therefore
// come in two shapes, and an entry says which it is in its first field:
//
//	1  checksum only:  <dt>*<mt>*<ct>*<dl>*<cs>*<tc>*<data>
//	2  full data:      <dt>*<mt>*<cl>*<ul>*<crc>*<of>*<ox>*<ct>*<dl>*<cs>*<tc>*<data>
//
// A checksum-only entry carries just enough bytes to test the header; a full
// entry carries the whole file, which can be decrypted, inflated and checked
// against the stored CRC-32. The five Hashcat modes are combinations of these:
// one full entry compressed (17200) or stored (17210), several entries of
// which the last is full (17220, 17225), or nothing but checksum-only entries
// (17230, eight of them, which is 64 bits of check between them).
//
// Every ZipCrypto file begins with a 12-byte encryption header whose last byte
// or two must match a value the archive already commits to — either the top of
// the CRC-32 or the top of the DOS timestamp, because different tools wrote
// different ones. Hashcat accepts either, and so does this.
//
// Not reproduced here: Hashcat's check_inflate_code1/2 early-reject heuristics,
// which sniff a deflate block header before paying for the inflate. They make
// a GPU kernel faster and cannot change an answer — skipping them can only let
// through candidates Hashcat would have dropped sooner, never reject one it
// accepts — and the checks that remain are 2^-32 or better on every mode.

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
)

const (
	pkzipHeaderLen      = 12
	pkzipDeflate        = 8
	pkzipStored         = 0
	pkzipChecksumOnly   = 1
	pkzipFullData       = 2
	pkzipMaxUncompessed = 1 << 26 // a guard on the record's own claim, not a format limit
)

type pkzip2Entry struct {
	dataType           int
	compressionType    int
	uncompressedLength int
	crc                uint32
	checksumFromCRC    uint16
	checksumFromTime   uint16
	data               []byte
}

type pkzip2Record struct {
	checksumSize int
	entries      []pkzip2Entry
}

func parsePKZIP2(target string) (*pkzip2Record, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$pkzip2$") || !strings.HasSuffix(t, "*$/pkzip2$") {
		return nil, errors.New("not a $pkzip2$ record")
	}
	f := strings.Split(strings.TrimSuffix(strings.TrimPrefix(t, "$pkzip2$"), "*$/pkzip2$"), "*")
	if len(f) < 2 {
		return nil, errors.New("$pkzip2$ record is missing its header fields")
	}
	hexInt := func(s string) (int, error) {
		v, err := strconv.ParseUint(s, 16, 32)
		return int(v), err
	}
	count, err := hexInt(f[0])
	if err != nil || count < 1 {
		return nil, errors.New("$pkzip2$ entry count is not a positive hex integer")
	}
	r := &pkzip2Record{}
	if r.checksumSize, err = hexInt(f[1]); err != nil || (r.checksumSize != 1 && r.checksumSize != 2) {
		return nil, errors.New("$pkzip2$ checksum size must be 1 or 2")
	}

	i := 2
	for n := 0; n < count; n++ {
		var e pkzip2Entry
		need := 7
		if i >= len(f) {
			return nil, errors.New("$pkzip2$ record ends before its entry count")
		}
		if e.dataType, err = hexInt(f[i]); err != nil {
			return nil, errors.New("$pkzip2$ entry type is not hex")
		}
		var csIdx, dataIdx int
		switch e.dataType {
		case pkzipChecksumOnly:
			// <dt>*<mt>*<ct>*<dl>*<cs>*<tc>*<data>
			need, csIdx, dataIdx = 7, i+4, i+6
			if i+need > len(f) {
				return nil, errors.New("$pkzip2$ checksum-only entry is truncated")
			}
			if e.compressionType, err = hexInt(f[i+2]); err != nil {
				return nil, errors.New("$pkzip2$ compression type is not hex")
			}
		case pkzipFullData:
			// <dt>*<mt>*<cl>*<ul>*<crc>*<of>*<ox>*<ct>*<dl>*<cs>*<tc>*<data>
			need, csIdx, dataIdx = 12, i+9, i+11
			if i+need > len(f) {
				return nil, errors.New("$pkzip2$ full entry is truncated")
			}
			if e.uncompressedLength, err = hexInt(f[i+3]); err != nil || e.uncompressedLength > pkzipMaxUncompessed {
				return nil, errors.New("$pkzip2$ uncompressed length is not a plausible hex integer")
			}
			crc, err := strconv.ParseUint(f[i+4], 16, 32)
			if err != nil {
				return nil, errors.New("$pkzip2$ CRC is not hex")
			}
			e.crc = uint32(crc)
			if e.compressionType, err = hexInt(f[i+7]); err != nil {
				return nil, errors.New("$pkzip2$ compression type is not hex")
			}
		default:
			return nil, errors.New("unsupported $pkzip2$ entry type " + f[i])
		}
		cs, err1 := strconv.ParseUint(f[csIdx], 16, 16)
		tc, err2 := strconv.ParseUint(f[csIdx+1], 16, 16)
		if err1 != nil || err2 != nil {
			return nil, errors.New("$pkzip2$ entry checksums are not hex")
		}
		e.checksumFromCRC, e.checksumFromTime = uint16(cs), uint16(tc)
		if e.data, err = hex.DecodeString(f[dataIdx]); err != nil {
			return nil, errors.New("$pkzip2$ entry data is not hex")
		}
		if len(e.data) < pkzipHeaderLen {
			return nil, errors.New("$pkzip2$ entry is shorter than the encryption header")
		}
		r.entries = append(r.entries, e)
		i += need
	}
	if i != len(f) {
		return nil, errors.New("$pkzip2$ record has trailing fields")
	}
	return r, nil
}

// pkzipHeaderMatches decrypts an entry's 12-byte encryption header and reports
// whether its check byte(s) agree with either value the archive commits to.
// The returned state has consumed the header and is positioned at the payload.
func (r *pkzip2Record) pkzipHeaderMatches(e *pkzip2Entry, candidate string) (zipCryptoState, bool) {
	s := newZipCryptoState(candidate)
	var plain [pkzipHeaderLen]byte
	for i := 0; i < pkzipHeaderLen; i++ {
		plain[i] = s.decryptByte(e.data[i])
	}
	if r.checksumSize == 2 {
		lo := plain[pkzipHeaderLen-2]
		if lo != byte(e.checksumFromCRC) && lo != byte(e.checksumFromTime) {
			return s, false
		}
	}
	hi := plain[pkzipHeaderLen-1]
	return s, hi == byte(e.checksumFromCRC>>8) || hi == byte(e.checksumFromTime>>8)
}

// pkzipPayloadMatches decrypts, decompresses and CRC-checks a full entry.
func (e *pkzip2Entry) pkzipPayloadMatches(s zipCryptoState) bool {
	payload := make([]byte, len(e.data)-pkzipHeaderLen)
	for i := range payload {
		payload[i] = s.decryptByte(e.data[pkzipHeaderLen+i])
	}
	var plain []byte
	switch e.compressionType {
	case pkzipStored:
		plain = payload
	case pkzipDeflate:
		// Block type 3 is not a thing; rejecting it here costs nothing and
		// saves the inflate on most wrong candidates.
		if len(payload) > 0 && payload[0]&6 == 6 {
			return false
		}
		out, err := io.ReadAll(flate.NewReader(bytes.NewReader(payload)))
		if err != nil {
			return false
		}
		plain = out
	default:
		return false
	}
	return len(plain) == e.uncompressedLength && crc32.ChecksumIEEE(plain) == e.crc
}

func verifyPKZIP2(target, candidate string) (bool, error) {
	r, err := parsePKZIP2(target)
	if err != nil {
		return false, err
	}
	// Every entry's header must agree before any of them is decompressed: the
	// header test is a few dozen operations and the inflate is thousands.
	states := make([]zipCryptoState, len(r.entries))
	for i := range r.entries {
		s, ok := r.pkzipHeaderMatches(&r.entries[i], candidate)
		if !ok {
			return false, nil
		}
		states[i] = s
	}
	for i := range r.entries {
		if r.entries[i].dataType != pkzipFullData {
			continue
		}
		if !r.entries[i].pkzipPayloadMatches(states[i]) {
			return false, nil
		}
	}
	return true, nil
}
