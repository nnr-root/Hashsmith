package smith

// A reader for the two capture container formats, shared by every extractor
// that works from a packet capture.
//
// Both formats are simple and both are written by programs that crashed
// halfway through more often than anyone would like, so every length here is
// bounds-checked against what the file actually holds rather than trusted.
//
// The link type travels WITH each frame rather than being returned once. A
// classic pcap has exactly one, but a pcapng may describe several interfaces
// and interleave their packets, so a caller that read one link type and
// applied it to everything would decode one interface's frames as another's.

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Link types this tool names. The numbers are IANA's, as recorded in
// tcpdump's LINKTYPE registry.
const (
	linkTypeEthernet      = 1
	linkTypeRawIP         = 101
	linkTypeIEEE80211     = 105
	linkTypeLinuxCooked   = 113
	linkTypePrismHeader   = 119
	linkTypeRadiotap      = 127
	linkTypeIPv4          = 228
	linkTypePPI           = 192
	linkTypeIEEE80211Avs  = 163
	linkTypeLinuxCookedV2 = 276
)

// pcapFrame is one captured frame with the link type of the interface that
// captured it.
type pcapFrame struct {
	linkType uint32
	data     []byte
}

const pcapMaxFrame = 16 << 20

// pcapFrames reads a capture in either container format.
func pcapFrames(b []byte) ([]pcapFrame, error) {
	if len(b) >= 4 && bytes.Equal(b[0:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		return pcapNGFrames(b)
	}
	return pcapClassicFrames(b)
}

// pcapClassicFrames reads the original libpcap format.
//
// Four magic numbers, not one: two byte orders crossed with two timestamp
// resolutions. The nanosecond variant differs from the microsecond one only in
// what the timestamp means, which nothing here reads, but its magic is
// different and a reader that knows only the classic pair rejects the file.
func pcapClassicFrames(b []byte) ([]pcapFrame, error) {
	if len(b) < 24 {
		return nil, errors.New("truncated pcap header")
	}
	var order binary.ByteOrder
	switch [4]byte{b[0], b[1], b[2], b[3]} {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		order = binary.LittleEndian
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		order = binary.BigEndian
	default:
		return nil, errors.New("unsupported capture: expected pcap or pcapng")
	}
	linkType := order.Uint32(b[20:24])

	var frames []pcapFrame
	for at := 24; at < len(b); {
		if at+16 > len(b) {
			return nil, errors.New("truncated pcap packet header")
		}
		captured := int(order.Uint32(b[at+8 : at+12]))
		at += 16
		if captured < 0 || captured > pcapMaxFrame || at+captured > len(b) {
			return nil, errors.New("invalid pcap packet length")
		}
		frames = append(frames, pcapFrame{linkType: linkType, data: b[at : at+captured]})
		at += captured
	}
	return frames, nil
}

// pcapNGFrames reads the block-structured format.
func pcapNGFrames(b []byte) ([]pcapFrame, error) {
	var (
		order      binary.ByteOrder
		interfaces []uint32
		frames     []pcapFrame
	)
	for at := 0; at < len(b); {
		if at+12 > len(b) {
			return nil, errors.New("truncated pcapng block")
		}
		if bytes.Equal(b[at:at+4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
			if at+28 > len(b) {
				return nil, errors.New("truncated pcapng section header")
			}
			switch [4]byte{b[at+8], b[at+9], b[at+10], b[at+11]} {
			case [4]byte{0x4d, 0x3c, 0x2b, 0x1a}:
				order = binary.LittleEndian
			case [4]byte{0x1a, 0x2b, 0x3c, 0x4d}:
				order = binary.BigEndian
			default:
				return nil, errors.New("invalid pcapng byte-order magic")
			}
			// Interface numbering restarts with every section.
			interfaces = nil
		} else if order == nil {
			return nil, errors.New("pcapng section header must be first")
		}
		blockLen := int(order.Uint32(b[at+4 : at+8]))
		if blockLen < 12 || blockLen%4 != 0 || blockLen > pcapMaxFrame ||
			at+blockLen > len(b) ||
			int(order.Uint32(b[at+blockLen-4:at+blockLen])) != blockLen {
			return nil, errors.New("invalid pcapng block length")
		}
		switch order.Uint32(b[at : at+4]) {
		case 1: // Interface Description Block
			if blockLen < 20 {
				return nil, errors.New("truncated pcapng interface description")
			}
			interfaces = append(interfaces, uint32(order.Uint16(b[at+8:at+10])))
		case 6: // Enhanced Packet Block
			if blockLen < 32 {
				return nil, errors.New("truncated pcapng enhanced packet")
			}
			interfaceID := int(order.Uint32(b[at+8 : at+12]))
			captured := int(order.Uint32(b[at+20 : at+24]))
			dataAt := at + 28
			if interfaceID < 0 || interfaceID >= len(interfaces) || captured < 0 ||
				captured > pcapMaxFrame || dataAt+captured > at+blockLen-4 {
				return nil, errors.New("invalid pcapng packet metadata")
			}
			frames = append(frames, pcapFrame{
				linkType: interfaces[interfaceID],
				data:     b[dataAt : dataAt+captured],
			})
		case 3: // Simple Packet Block — no interface id, so interface 0
			if blockLen < 16 || len(interfaces) == 0 {
				break
			}
			dataAt := at + 12
			captured := at + blockLen - 4 - dataAt
			if captured > 0 {
				frames = append(frames, pcapFrame{
					linkType: interfaces[0],
					data:     b[dataAt : dataAt+captured],
				})
			}
		}
		at += blockLen
	}
	return frames, nil
}
