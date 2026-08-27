package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestVNCPCAPExtractor(t *testing.T) {
	challenge, _ := hex.DecodeString("7963F9BB7BA6A42A085763808156F570")
	response, _ := hex.DecodeString("475B10D05648E4110D77F03916106F98")
	frames := [][]byte{
		vncEthernetTCP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 5900, 40000, []byte("RFB 003.008\n")),
		vncEthernetTCP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 5900, 40000, challenge),
		vncEthernetTCP([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 40000, 5900, response),
	}
	pcap := make([]byte, 24)
	copy(pcap[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(pcap[4:6], 2)
	binary.LittleEndian.PutUint16(pcap[6:8], 4)
	binary.LittleEndian.PutUint32(pcap[16:20], 65535)
	binary.LittleEndian.PutUint32(pcap[20:24], 1)
	for _, frame := range frames {
		pcap = appendPCAPPacket(pcap, frame)
	}
	pcapng := vncPCAPNG(frames)
	want := "$vnc$*7963f9bb7ba6a42a085763808156f570*475b10d05648e4110d77f03916106f98"
	for name, capture := range map[string][]byte{"pcap": pcap, "pcapng": pcapng} {
		t.Run(name, func(t *testing.T) {
			records, err := extractVNCPCAPRecords(extractorFixture(t, "vnc."+name, capture))
			if err != nil || len(records) != 1 || records[0] != want {
				t.Fatalf("records=%v err=%v, want %q", records, err, want)
			}
			ok, err := verifyCandidate("123", records[0], "vnc", "", "prefix")
			if err != nil || !ok {
				t.Fatalf("extracted VNC record did not verify: ok=%v err=%v", ok, err)
			}
		})
	}
}

func vncPCAPNG(frames [][]byte) []byte {
	section := make([]byte, 28)
	copy(section[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a})
	binary.LittleEndian.PutUint32(section[4:8], 28)
	copy(section[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a})
	binary.LittleEndian.PutUint16(section[12:14], 1)
	for i := 16; i < 24; i++ {
		section[i] = 0xff
	}
	binary.LittleEndian.PutUint32(section[24:28], 28)
	interfaceBlock := make([]byte, 20)
	binary.LittleEndian.PutUint32(interfaceBlock[:4], 1)
	binary.LittleEndian.PutUint32(interfaceBlock[4:8], 20)
	binary.LittleEndian.PutUint16(interfaceBlock[8:10], 1)
	binary.LittleEndian.PutUint32(interfaceBlock[12:16], 65535)
	binary.LittleEndian.PutUint32(interfaceBlock[16:20], 20)
	out := append(section, interfaceBlock...)
	for _, frame := range frames {
		padded := (len(frame) + 3) &^ 3
		blockLen := 28 + padded + 4
		block := make([]byte, blockLen)
		binary.LittleEndian.PutUint32(block[:4], 6)
		binary.LittleEndian.PutUint32(block[4:8], uint32(blockLen))
		binary.LittleEndian.PutUint32(block[20:24], uint32(len(frame)))
		binary.LittleEndian.PutUint32(block[24:28], uint32(len(frame)))
		copy(block[28:], frame)
		binary.LittleEndian.PutUint32(block[blockLen-4:], uint32(blockLen))
		out = append(out, block...)
	}
	return out
}

func appendPCAPPacket(pcap, packet []byte) []byte {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(packet)))
	return append(append(pcap, header...), packet...)
}

func vncEthernetTCP(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	frame := make([]byte, 14+20+20+len(payload))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4
	copy(tcp[20:], payload)
	return frame
}
