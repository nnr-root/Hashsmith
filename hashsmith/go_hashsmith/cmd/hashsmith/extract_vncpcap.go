package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

// parseVNCPCAPTCP decodes every IPv4/TCP payload in a capture.
//
// The container reading lives in pcap.go, shared with the other capture
// extractors; what stays here is which link types carry an IP packet at a
// known offset and how to find the TCP payload inside it.
func parseVNCPCAPTCP(b []byte) ([]vncPacket, error) {
	frames, err := pcapFrames(b)
	if err != nil {
		return nil, err
	}
	var packets []vncPacket
	for _, f := range frames {
		switch f.linkType {
		case linkTypeEthernet, linkTypeRawIP, linkTypeLinuxCooked, linkTypeIPv4:
		default:
			continue
		}
		if packet, ok := decodeVNCIPv4TCP(f.data, f.linkType); ok && len(packet.payload) > 0 {
			packets = append(packets, packet)
		}
	}
	if len(packets) == 0 && len(frames) == 0 {
		return nil, errors.New("this capture holds no packets")
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
