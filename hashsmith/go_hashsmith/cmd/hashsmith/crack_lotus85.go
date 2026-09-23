package main

// Lotus Notes 8.5 — John's "lotus85", the user.id file rather than the
// directory entry.
//
// Domino 5, 6 and 8 (crack_domino.go) are the hash the SERVER stores. This is
// the other half: the blob inside the user.id file a Notes client carries, RC2
// encrypted under a key the password derives. Nothing in the record is a
// digest, so there is no hash to compare against — the record IS the
// ciphertext, and a password is right when the decrypted blob's last five
// bytes equal a checksum computed over the rest of it.
//
// Three things about the derivation are worth writing down, because all three
// look like mistakes and only one is.
//
// First: IBM's own hash, the one behind Domino 5, is used here too, in a
// different arrangement. The Domino digest absorbs a block and folds it into a
// checksum; this one keeps the same 48-byte mixing permutation but runs it
// over its own 18-pass schedule with the running byte carried between passes,
// and keeps a SEPARATE 16-byte accumulator chained through the substitution
// table. The shared part is the table (lotusMagicTable, the ebits_to_num of
// the C sources) — which is why it is not duplicated here.
//
// Second: the derivation computes SHA-1 of a fixed string plus the password,
// stores it at key[16:36], and then never uses it. compute_key_mac reads
// sixteen bytes and the key is thirty-six, so the SHA-1 is dead weight: the
// entire RC2 key comes from the proprietary hash alone. This is transcribed
// faithfully rather than optimised away, because dropping it would be right
// only as long as nobody ever writes a variant that reads the other twenty.
//
// Third: the RC2 key is EIGHT bytes with 64 effective bits, so there is no
// export weakening — but eight bytes is the whole key, and it is produced by a
// checksum, not a KDF. There is no iteration count anywhere in this format.
// A candidate costs one proprietary hash and one RC2 decryption of under a
// hundred bytes, which is to say the file's security is the password's alone.

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	lotus85MinBlob = 40
	lotus85MaxBlob = 100
	// lotus85MacLength is how many bytes of checksum sit at the end of the
	// decrypted blob.
	lotus85MacLength = 5
	// lotus85Uniquifier is hashed with the password by the SHA-1 step that
	// the key derivation then ignores. See the note above.
	lotus85Uniquifier = "Lotus Notes Password Pad Uniquifier"
)

// lotus85Trans is one step of the proprietary password hash.
//
// The names follow what the two outputs do rather than the C parameter names,
// which are `out` for the chained accumulator and `state` for the thing the
// permutation actually carries. data and sum may be the same slice: the final
// call passes the accumulator as its own message, and the loop below reads
// each byte before overwriting it, so the aliasing is meaningful and kept.
func lotus85Trans(data []byte, sum, mix *[16]byte) {
	var buffer [48]byte
	copy(buffer[0:16], mix[:])
	copy(buffer[16:32], data[:16])
	for i := 0; i < 16; i++ {
		buffer[32+i] = data[i] ^ mix[i]
	}

	var c byte
	for pass := 0; pass < 18; pass++ {
		for i := 0; i < 48; i += 6 {
			// The index counts DOWN from 48 as i counts up, so the six
			// bytes of a group are salted with six consecutive table
			// positions; c carries the last byte of the previous group,
			// and across passes, which is what chains the whole buffer.
			buffer[i] ^= lotusMagicTable[c-byte(i)+48]
			buffer[i+1] ^= lotusMagicTable[buffer[i]-byte(i)+47]
			buffer[i+2] ^= lotusMagicTable[buffer[i+1]-byte(i)+46]
			buffer[i+3] ^= lotusMagicTable[buffer[i+2]-byte(i)+45]
			buffer[i+4] ^= lotusMagicTable[buffer[i+3]-byte(i)+44]
			buffer[i+5] ^= lotusMagicTable[buffer[i+4]-byte(i)+43]
			c = buffer[i+5]
		}
	}
	copy(mix[:], buffer[0:16])

	prev := sum[15]
	for i := 0; i < 16; i += 4 {
		d0, d1, d2, d3 := data[i], data[i+1], data[i+2], data[i+3]
		sum[i] ^= lotusMagicTable[d0^prev]
		sum[i+1] ^= lotusMagicTable[d1^sum[i]]
		sum[i+2] ^= lotusMagicTable[d2^sum[i+1]]
		sum[i+3] ^= lotusMagicTable[d3^sum[i+2]]
		prev = sum[i+3]
	}
}

// lotus85PasswordHash is the sixteen-byte proprietary digest of a password.
//
// The padding is PKCS#7's rule — fill with the count of bytes added — and,
// unlike the Domino 5 hash next door, a password that already fills its last
// block DOES get a whole padding block of sixteen sixteens. The C writes that
// block with memset's arguments transposed (`memset(block1, sizeof(block1),
// sizeof(block1))`, value and length swapped); the value it means to write and
// the value it does write are both 16, so the bug is invisible and the
// behaviour is the padding rule spelled properly.
func lotus85PasswordHash(password string) [16]byte {
	var sum, mix [16]byte
	pw := []byte(password)

	var block [16]byte
	pos := 0
	for pos+16 <= len(pw) {
		copy(block[:], pw[pos:pos+16])
		lotus85Trans(block[:], &sum, &mix)
		pos += 16
	}
	rest := len(pw) - pos
	copy(block[:], pw[pos:])
	fill := byte(16 - rest)
	for i := rest; i < 16; i++ {
		block[i] = fill
	}
	lotus85Trans(block[:], &sum, &mix)

	// One final step over the accumulator itself, which is where data and
	// sum alias.
	lotus85Trans(sum[:], &sum, &mix)
	return mix
}

// lotus85SecretKey derives the eight-byte RC2 key.
func lotus85SecretKey(password string) []byte {
	var key [36]byte
	pwHash := lotus85PasswordHash(password)
	copy(key[0:16], pwHash[:])

	// Computed, stored, and never read again. See the note at the top.
	sum := sha1.Sum([]byte(lotus85Uniquifier + password))
	copy(key[16:36], sum[:])

	// An eight-byte shift register: each of the first sixteen key bytes is
	// XORed with a table lookup on the register's two leading bytes and
	// pushed in at the end.
	var mac [8]byte
	for i := 0; i < 16; i++ {
		k := lotusMagicTable[mac[0]^mac[1]]
		copy(mac[0:7], mac[1:8])
		mac[7] = key[i] ^ k
	}
	out := make([]byte, 8)
	copy(out, mac[:])
	return out
}

// lotus85MsgMAC is the checksum the decrypted blob carries in its last five
// bytes. It is a five-byte register cycled by the message, and the rotate at
// the end is the only thing standing between it and a plain running XOR.
func lotus85MsgMAC(msg []byte) []byte {
	var mac [lotus85MacLength]byte
	j := 0
	for _, b := range msg {
		if j != 4 {
			mac[j] = b ^ lotusMagicTable[mac[j]^mac[j+1]]
			j++
			continue
		}
		mac[j] = b ^ lotusMagicTable[mac[j]^mac[0]]
		j = 0
	}
	c := mac[0]
	copy(mac[0:4], mac[1:5])
	mac[4] = c

	out := make([]byte, lotus85MacLength)
	copy(out, mac[:])
	return out
}

func verifyLotus85(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	blob, err := hex.DecodeString(t)
	if err != nil {
		return false, errors.New("lotus85 record must be hex")
	}
	if len(blob) < lotus85MinBlob || len(blob) > lotus85MaxBlob {
		return false, errors.New("lotus85 blob must be 40 to 100 bytes")
	}

	key := lotus85SecretKey(candidate)
	block, err := newRC2Cipher(key, 64)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(blob))
	// The IV is all zeros: the blob's first block carries no randomisation,
	// so two user.id files made from the same password start identically.
	rc2CBCDecrypt(block, make([]byte, rc2BlockSize), plain, blob)

	cut := len(plain) - lotus85MacLength
	want := plain[cut:]
	got := lotus85MsgMAC(plain[:cut])
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
