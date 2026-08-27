package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

func runExtractVNCPCAP(args []string) error {
	return runFileRecordExtractor("vncpcap2smith", args, extractVNCPCAPRecords)
}

type vncPacket struct {
	src, dst     [4]byte
	sport, dport uint16
	payload      []byte
}

func extractVNCPCAPRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	packets, err := parseVNCPCAPTCP(b)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var records []string
	for i, banner := range packets {
		if !bytes.Contains(banner.payload, []byte("RFB")) {
			continue
		}
		for j := i + 1; j < len(packets); j++ {
			challenge := packets[j]
			if !sameVNCFlow(banner, challenge) || len(challenge.payload) != 16 ||
				bytes.Contains(challenge.payload, []byte("VNCAUTH_")) {
				continue
			}
			for k := j + 1; k < len(packets); k++ {
				response := packets[k]
				if !reverseVNCFlow(challenge, response) || len(response.payload) != 16 {
					continue
				}
				record := "$vnc$*" + hex.EncodeToString(challenge.payload) + "*" + hex.EncodeToString(response.payload)
				if !seen[record] {
					seen[record] = true
					records = append(records, record)
				}
				break
			}
			break
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no complete VNC Authentication exchange found in pcap")
	}
	return records, nil
}

func sameVNCFlow(a, b vncPacket) bool {
	return a.src == b.src && a.dst == b.dst && a.sport == b.sport && a.dport == b.dport
}

func reverseVNCFlow(a, b vncPacket) bool {
	return a.src == b.dst && a.dst == b.src && a.sport == b.dport && a.dport == b.sport
}

func parseVNCPCAPTCP(b []byte) ([]vncPacket, error) {
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		return parsePCAPNGTCP(b)
	}
	return parseClassicPCAPTCP(b)
}

func parseClassicPCAPTCP(b []byte) ([]vncPacket, error) {
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
	if linkType != 1 && linkType != 101 && linkType != 113 && linkType != 228 {
		return nil, fmt.Errorf("unsupported pcap link type %d", linkType)
	}
	var packets []vncPacket
	for at := 24; at < len(b); {
		if at+16 > len(b) {
			return nil, errors.New("truncated pcap packet header")
		}
		captured := int(order.Uint32(b[at+8 : at+12]))
		at += 16
		if captured < 0 || captured > 16<<20 || at+captured > len(b) {
			return nil, errors.New("invalid pcap packet length")
		}
		if packet, ok := decodeVNCIPv4TCP(b[at:at+captured], linkType); ok && len(packet.payload) > 0 {
			packets = append(packets, packet)
		}
		at += captured
	}
	return packets, nil
}

func parsePCAPNGTCP(b []byte) ([]vncPacket, error) {
	var (
		order      binary.ByteOrder
		interfaces []uint32
		packets    []vncPacket
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
			interfaces = nil
		} else if order == nil {
			return nil, errors.New("pcapng section header must be first")
		}
		blockLen := int(order.Uint32(b[at+4 : at+8]))
		if blockLen < 12 || blockLen%4 != 0 || blockLen > 16<<20 || at+blockLen > len(b) ||
			int(order.Uint32(b[at+blockLen-4:at+blockLen])) != blockLen {
			return nil, errors.New("invalid pcapng block length")
		}
		blockType := order.Uint32(b[at : at+4])
		switch blockType {
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
				captured > 16<<20 || dataAt+captured > at+blockLen-4 {
				return nil, errors.New("invalid pcapng packet metadata")
			}
			if packet, ok := decodeVNCIPv4TCP(b[dataAt:dataAt+captured], interfaces[interfaceID]); ok && len(packet.payload) > 0 {
				packets = append(packets, packet)
			}
		}
		at += blockLen
	}
	return packets, nil
}

func decodeVNCIPv4TCP(frame []byte, linkType uint32) (vncPacket, bool) {
	var zero vncPacket
	ipAt := 0
	switch linkType {
	case 1: // Ethernet
		if len(frame) < 14 {
			return zero, false
		}
		etherType := binary.BigEndian.Uint16(frame[12:14])
		ipAt = 14
		if etherType == 0x8100 || etherType == 0x88a8 {
			if len(frame) < 18 {
				return zero, false
			}
			etherType, ipAt = binary.BigEndian.Uint16(frame[16:18]), 18
		}
		if etherType != 0x0800 {
			return zero, false
		}
	case 113: // Linux cooked capture v1
		if len(frame) < 16 || binary.BigEndian.Uint16(frame[14:16]) != 0x0800 {
			return zero, false
		}
		ipAt = 16
	case 101, 228: // raw IP / IPv4
		ipAt = 0
	}
	if len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != 6 {
		return zero, false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	if ipLen < 20 || len(frame) < ipAt+ipLen+20 || binary.BigEndian.Uint16(frame[ipAt+6:ipAt+8])&0x1fff != 0 {
		return zero, false
	}
	total := int(binary.BigEndian.Uint16(frame[ipAt+2 : ipAt+4]))
	if total < ipLen+20 || ipAt+total > len(frame) {
		total = len(frame) - ipAt
	}
	tcpAt := ipAt + ipLen
	tcpLen := int(frame[tcpAt+12]>>4) * 4
	if tcpLen < 20 || tcpAt+tcpLen > ipAt+total {
		return zero, false
	}
	var packet vncPacket
	copy(packet.src[:], frame[ipAt+12:ipAt+16])
	copy(packet.dst[:], frame[ipAt+16:ipAt+20])
	packet.sport = binary.BigEndian.Uint16(frame[tcpAt : tcpAt+2])
	packet.dport = binary.BigEndian.Uint16(frame[tcpAt+2 : tcpAt+4])
	packet.payload = append([]byte(nil), frame[tcpAt+tcpLen:ipAt+total]...)
	return packet, true
}
