// Package argon2d provides the Argon2d and Argon2id key-derivation functions.
//
// It is a lightly-adapted copy of golang.org/x/crypto/argon2 (BSD-licensed,
// © The Go Authors). The upstream package only exports Argon2i (Key) and
// Argon2id (IDKey); KeePass KDBX 4 databases default to Argon2d, so this vendored
// copy exposes DKey as well. Only the portable (generic) block permutation is
// included, so it builds and runs identically on every architecture.
package argon2d

import (
	"encoding/binary"
	"hash"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// Version is the Argon2 version implemented by this package.
const Version = 0x13

const (
	argon2d = iota
	argon2i
	argon2id
)

// DKey derives a key using Argon2d (data-dependent addressing) — the KDF used by
// default in KeePass KDBX 4 databases.
func DKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2d, password, salt, nil, nil, time, memory, threads, keyLen)
}

// IDKey derives a key using Argon2id.
func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2id, password, salt, nil, nil, time, memory, threads, keyLen)
}

// Key derives a key using Argon2i.
func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2i, password, salt, nil, nil, time, memory, threads, keyLen)
}

func deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if time < 1 {
		panic("argon2: number of rounds too small")
	}
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	h0 := initHash(password, salt, secret, data, time, memory, uint32(threads), keyLen, mode)

	memory = memory / (syncPoints * uint32(threads)) * (syncPoints * uint32(threads))
	if memory < 2*syncPoints*uint32(threads) {
		memory = 2 * syncPoints * uint32(threads)
	}
	B := initBlocks(&h0, memory, uint32(threads))
	processBlocks(B, time, memory, uint32(threads), mode)
	return extractKey(B, memory, uint32(threads), keyLen)
}

const (
	blockLength = 128
	syncPoints  = 4
)

type block [blockLength]uint64

func initHash(password, salt, key, data []byte, time, memory, threads, keyLen uint32, mode int) [blake2b.Size + 8]byte {
	var (
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)

	b2, _ := blake2b.New512(nil)
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memory)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], uint32(Version))
	binary.LittleEndian.PutUint32(params[20:24], uint32(mode))
	b2.Write(params[:])
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(password)))
	b2.Write(tmp[:])
	b2.Write(password)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(salt)))
	b2.Write(tmp[:])
	b2.Write(salt)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(key)))
	b2.Write(tmp[:])
	b2.Write(key)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	b2.Write(tmp[:])
	b2.Write(data)
	b2.Sum(h0[:0])
	return h0
}

func initBlocks(h0 *[blake2b.Size + 8]byte, memory, threads uint32) []block {
	var block0 [1024]byte
	B := make([]block, memory)
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
	return B
}

func processBlocks(B []block, time, memory, threads uint32, mode int) {
	lanes := memory / threads
	segments := lanes / syncPoints

	processSegment := func(n, slice, lane uint32, wg *sync.WaitGroup) {
		var addresses, in, zero block
		if mode == argon2i || (mode == argon2id && n == 0 && slice < syncPoints/2) {
			in[0] = uint64(n)
			in[1] = uint64(lane)
			in[2] = uint64(slice)
			in[3] = uint64(memory)
			in[4] = uint64(time)
			in[5] = uint64(mode)
		}

		index := uint32(0)
		if n == 0 && slice == 0 {
			index = 2 // we have already generated the first two blocks
			if mode == argon2i || mode == argon2id {
				in[6]++
				processBlock(&addresses, &in, &zero)
				processBlock(&addresses, &addresses, &zero)
			}
		}

		offset := lane*lanes + slice*segments + index
		var random uint64
		for index < segments {
			prev := offset - 1
			if index == 0 && slice == 0 {
				prev += lanes // last block in lane
			}
			if mode == argon2i || (mode == argon2id && n == 0 && slice < syncPoints/2) {
				if index%blockLength == 0 {
					in[6]++
					processBlock(&addresses, &in, &zero)
					processBlock(&addresses, &addresses, &zero)
				}
				random = addresses[index%blockLength]
			} else {
				random = B[prev][0]
			}
			newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
			processBlockXOR(&B[offset], &B[prev], &B[newOffset])
			index, offset = index+1, offset+1
		}
		wg.Done()
	}

	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < threads; lane++ {
				wg.Add(1)
				go processSegment(n, slice, lane, &wg)
			}
			wg.Wait()
		}
	}
}

func extractKey(B []block, memory, threads, keyLen uint32) []byte {
	lanes := memory / threads
	for lane := uint32(0); lane < threads-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}

	var block [1024]byte
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake2bHash(key, block[:])
	return key
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%syncPoints)*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}

// ── blake2b long-hash (from x/crypto/argon2/blake2b.go) ─────────────────────────

func blake2bHash(out []byte, in []byte) {
	var b2 hash.Hash
	if n := len(out); n < blake2b.Size {
		b2, _ = blake2b.New(n, nil)
	} else {
		b2, _ = blake2b.New512(nil)
	}

	var buffer [blake2b.Size]byte
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(out)))
	b2.Write(buffer[:4])
	b2.Write(in)

	if len(out) <= blake2b.Size {
		b2.Sum(out[:0])
		return
	}

	outLen := len(out)
	b2.Sum(buffer[:0])
	b2.Reset()
	copy(out, buffer[:32])
	out = out[32:]
	for len(out) > blake2b.Size {
		b2.Write(buffer[:])
		b2.Sum(buffer[:0])
		copy(out, buffer[:32])
		out = out[32:]
		b2.Reset()
	}

	if outLen%blake2b.Size > 0 { // outLen > 64
		r := ((outLen + 31) / 32) - 2 // ⌈τ /32⌉-2
		b2, _ = blake2b.New(outLen-32*r, nil)
	}
	b2.Write(buffer[:])
	b2.Sum(out[:0])
}

// ── generic block permutation (from x/crypto/argon2/blamka_generic.go) ──────────

func processBlock(out, in1, in2 *block)    { processBlockGeneric(out, in1, in2, false) }
func processBlockXOR(out, in1, in2 *block) { processBlockGeneric(out, in1, in2, true) }

func processBlockGeneric(out, in1, in2 *block, xor bool) {
	var t block
	for i := range t {
		t[i] = in1[i] ^ in2[i]
	}
	for i := 0; i < blockLength; i += 16 {
		blamkaGeneric(
			&t[i+0], &t[i+1], &t[i+2], &t[i+3],
			&t[i+4], &t[i+5], &t[i+6], &t[i+7],
			&t[i+8], &t[i+9], &t[i+10], &t[i+11],
			&t[i+12], &t[i+13], &t[i+14], &t[i+15],
		)
	}
	for i := 0; i < blockLength/8; i += 2 {
		blamkaGeneric(
			&t[i], &t[i+1], &t[16+i], &t[16+i+1],
			&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
			&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
			&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
		)
	}
	if xor {
		for i := range t {
			out[i] ^= in1[i] ^ in2[i] ^ t[i]
		}
	} else {
		for i := range t {
			out[i] = in1[i] ^ in2[i] ^ t[i]
		}
	}
}

func blamkaGeneric(t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15 *uint64) {
	v00, v01, v02, v03 := *t00, *t01, *t02, *t03
	v04, v05, v06, v07 := *t04, *t05, *t06, *t07
	v08, v09, v10, v11 := *t08, *t09, *t10, *t11
	v12, v13, v14, v15 := *t12, *t13, *t14, *t15

	v00 += v04 + 2*uint64(uint32(v00))*uint64(uint32(v04))
	v12 ^= v00
	v12 = v12>>32 | v12<<32
	v08 += v12 + 2*uint64(uint32(v08))*uint64(uint32(v12))
	v04 ^= v08
	v04 = v04>>24 | v04<<40

	v00 += v04 + 2*uint64(uint32(v00))*uint64(uint32(v04))
	v12 ^= v00
	v12 = v12>>16 | v12<<48
	v08 += v12 + 2*uint64(uint32(v08))*uint64(uint32(v12))
	v04 ^= v08
	v04 = v04>>63 | v04<<1

	v01 += v05 + 2*uint64(uint32(v01))*uint64(uint32(v05))
	v13 ^= v01
	v13 = v13>>32 | v13<<32
	v09 += v13 + 2*uint64(uint32(v09))*uint64(uint32(v13))
	v05 ^= v09
	v05 = v05>>24 | v05<<40

	v01 += v05 + 2*uint64(uint32(v01))*uint64(uint32(v05))
	v13 ^= v01
	v13 = v13>>16 | v13<<48
	v09 += v13 + 2*uint64(uint32(v09))*uint64(uint32(v13))
	v05 ^= v09
	v05 = v05>>63 | v05<<1

	v02 += v06 + 2*uint64(uint32(v02))*uint64(uint32(v06))
	v14 ^= v02
	v14 = v14>>32 | v14<<32
	v10 += v14 + 2*uint64(uint32(v10))*uint64(uint32(v14))
	v06 ^= v10
	v06 = v06>>24 | v06<<40

	v02 += v06 + 2*uint64(uint32(v02))*uint64(uint32(v06))
	v14 ^= v02
	v14 = v14>>16 | v14<<48
	v10 += v14 + 2*uint64(uint32(v10))*uint64(uint32(v14))
	v06 ^= v10
	v06 = v06>>63 | v06<<1

	v03 += v07 + 2*uint64(uint32(v03))*uint64(uint32(v07))
	v15 ^= v03
	v15 = v15>>32 | v15<<32
	v11 += v15 + 2*uint64(uint32(v11))*uint64(uint32(v15))
	v07 ^= v11
	v07 = v07>>24 | v07<<40

	v03 += v07 + 2*uint64(uint32(v03))*uint64(uint32(v07))
	v15 ^= v03
	v15 = v15>>16 | v15<<48
	v11 += v15 + 2*uint64(uint32(v11))*uint64(uint32(v15))
	v07 ^= v11
	v07 = v07>>63 | v07<<1

	v00 += v05 + 2*uint64(uint32(v00))*uint64(uint32(v05))
	v15 ^= v00
	v15 = v15>>32 | v15<<32
	v10 += v15 + 2*uint64(uint32(v10))*uint64(uint32(v15))
	v05 ^= v10
	v05 = v05>>24 | v05<<40

	v00 += v05 + 2*uint64(uint32(v00))*uint64(uint32(v05))
	v15 ^= v00
	v15 = v15>>16 | v15<<48
	v10 += v15 + 2*uint64(uint32(v10))*uint64(uint32(v15))
	v05 ^= v10
	v05 = v05>>63 | v05<<1

	v01 += v06 + 2*uint64(uint32(v01))*uint64(uint32(v06))
	v12 ^= v01
	v12 = v12>>32 | v12<<32
	v11 += v12 + 2*uint64(uint32(v11))*uint64(uint32(v12))
	v06 ^= v11
	v06 = v06>>24 | v06<<40

	v01 += v06 + 2*uint64(uint32(v01))*uint64(uint32(v06))
	v12 ^= v01
	v12 = v12>>16 | v12<<48
	v11 += v12 + 2*uint64(uint32(v11))*uint64(uint32(v12))
	v06 ^= v11
	v06 = v06>>63 | v06<<1

	v02 += v07 + 2*uint64(uint32(v02))*uint64(uint32(v07))
	v13 ^= v02
	v13 = v13>>32 | v13<<32
	v08 += v13 + 2*uint64(uint32(v08))*uint64(uint32(v13))
	v07 ^= v08
	v07 = v07>>24 | v07<<40

	v02 += v07 + 2*uint64(uint32(v02))*uint64(uint32(v07))
	v13 ^= v02
	v13 = v13>>16 | v13<<48
	v08 += v13 + 2*uint64(uint32(v08))*uint64(uint32(v13))
	v07 ^= v08
	v07 = v07>>63 | v07<<1

	v03 += v04 + 2*uint64(uint32(v03))*uint64(uint32(v04))
	v14 ^= v03
	v14 = v14>>32 | v14<<32
	v09 += v14 + 2*uint64(uint32(v09))*uint64(uint32(v14))
	v04 ^= v09
	v04 = v04>>24 | v04<<40

	v03 += v04 + 2*uint64(uint32(v03))*uint64(uint32(v04))
	v14 ^= v03
	v14 = v14>>16 | v14<<48
	v09 += v14 + 2*uint64(uint32(v09))*uint64(uint32(v14))
	v04 ^= v09
	v04 = v04>>63 | v04<<1

	*t00, *t01, *t02, *t03 = v00, v01, v02, v03
	*t04, *t05, *t06, *t07 = v04, v05, v06, v07
	*t08, *t09, *t10, *t11 = v08, v09, v10, v11
	*t12, *t13, *t14, *t15 = v12, v13, v14, v15
}
