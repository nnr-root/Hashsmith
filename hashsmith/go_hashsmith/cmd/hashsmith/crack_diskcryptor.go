package main

// DiskCryptor volumes — Hashcat 20011, 20012 and 20013.
//
//	$diskcryptor$<n>*<2048 bytes of volume header, hex>
//
// The header's first 64 bytes are the PBKDF2 salt, left in the clear; the rest
// is XTS-encrypted. A correct passphrase is proven by the plaintext of the
// block that follows the salt, which begins with the ASCII signature "DCRP".
//
// Two details make this XTS unlike the one in crack_veracrypt.go, and both come
// straight from DiskCryptor's on-disk layout rather than from any choice here.
// The tweak is taken over SECTOR 1, not sector 0. And the block being read sits
// at index 4 within that sector, because the 64 salt bytes were written back
// over the first four blocks after encryption — so the tweak has been advanced
// four times before it reaches the block that matters.
//
// The three modes are the three XTS widths: one cipher (512-bit), a two-cipher
// cascade (1024) or a three-cipher cascade (1536). As with VeraCrypt, the wider
// modes also test the narrower layouts, because Hashcat's kernels do.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xts"
)

const (
	dcrpHeaderLen = 2048
	dcrpSaltLen   = 64
	dcrpIter      = 1000
	// The signature block starts where the salt ends, which is also why the
	// tweak needs advancing past exactly that many blocks.
	dcrpSigOffset = dcrpSaltLen
	dcrpSigBlock  = dcrpSaltLen / 16
	dcrpSector    = 1
)

var dcrpSignature = []byte("DCRP")

// dcrpValidVersionFlags are the (version, flags) words DiskCryptor writes:
// header version 2 with flags 4, 5 or 8. Checking them alongside the signature
// takes the test well past what a wrong passphrase could produce by accident.
var dcrpValidVersionFlags = []uint32{0x00040002, 0x00050002, 0x00080002}

// utf16leBytes encodes s as UTF-16LE, the form every Windows tool hashes.
// Unpaired surrogates are preserved rather than replaced: a password is a byte
// string to be reproduced exactly, not text to be cleaned up.
func utf16leBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2)
	for _, c := range u {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

func dcrpAES(k []byte) (cipher.Block, error)     { return aes.NewCipher(k) }
func dcrpTwofish(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }

// dcrpCascadeOrders lists the cipher layouts DiskCryptor supports at each
// width. Within one layout, entry i holds the cipher whose data key is the
// i-th 32-byte block of the derived material and whose tweak key is the
// (count+i)-th; decryption runs from the last entry to the first, so the list
// reads innermost-first.
var dcrpCascadeOrders = [][][]func([]byte) (cipher.Block, error){
	{
		{newSerpentCipher},
		{dcrpTwofish},
		{dcrpAES},
	},
	{
		{dcrpAES, newSerpentCipher},     // serpent over aes
		{newSerpentCipher, dcrpTwofish}, // twofish over serpent
		{dcrpTwofish, dcrpAES},          // aes over twofish
	},
	{
		{dcrpAES, dcrpTwofish, newSerpentCipher}, // serpent, twofish, aes
		{newSerpentCipher, dcrpTwofish, dcrpAES}, // aes, twofish, serpent
	},
}

func parseDiskCryptor(target string) ([]byte, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$diskcryptor$") {
		return nil, errors.New("not a DiskCryptor record")
	}
	p := strings.SplitN(strings.TrimPrefix(t, "$diskcryptor$"), "*", 2)
	if len(p) != 2 {
		return nil, errors.New("DiskCryptor record must be $diskcryptor$<n>*<header>")
	}
	header, err := hex.DecodeString(p[1])
	if err != nil {
		return nil, errors.New("DiskCryptor header is not hex")
	}
	if len(header) != dcrpHeaderLen {
		return nil, errors.New("DiskCryptor header must be 2048 bytes")
	}
	return header, nil
}

// dcrpDecryptSignatureBlock peels one XTS layer off the signature block.
//
// x/crypto/xts advances the tweak per block within a call, so handing it a
// buffer that ends at the signature block is how the four skipped blocks get
// accounted for — the leading blocks decrypt to nothing anyone reads, and
// their only job is to carry the tweak forward.
func dcrpDecryptSignatureBlock(newBlock func([]byte) (cipher.Block, error), key, in []byte) ([]byte, bool) {
	c, err := xts.NewCipher(newBlock, key)
	if err != nil {
		return nil, false
	}
	src := make([]byte, (dcrpSigBlock+1)*16)
	copy(src[dcrpSigBlock*16:], in)
	dst := make([]byte, len(src))
	c.Decrypt(dst, src, dcrpSector)
	return dst[dcrpSigBlock*16:], true
}

func dcrpHeaderValid(key, encrypted []byte, maxCiphers int) bool {
	for count := 1; count <= maxCiphers; count++ {
		if len(key) < count*64 {
			continue
		}
		for _, order := range dcrpCascadeOrders[count-1] {
			block := append([]byte(nil), encrypted...)
			ok := true
			for i := count - 1; i >= 0; i-- {
				xtsKey := make([]byte, 64)
				copy(xtsKey[:32], key[i*32:(i+1)*32])
				copy(xtsKey[32:], key[(count+i)*32:(count+i+1)*32])
				out, good := dcrpDecryptSignatureBlock(order[i], xtsKey, block)
				if !good {
					ok = false
					break
				}
				block = out
			}
			if !ok {
				continue
			}
			if !bytes.Equal(block[:4], dcrpSignature) {
				continue
			}
			vf := binary.LittleEndian.Uint32(block[8:12])
			for _, want := range dcrpValidVersionFlags {
				if vf == want {
					return true
				}
			}
		}
	}
	return false
}

// verifyDiskCryptor checks a DiskCryptor header. maxCiphers is the mode's XTS
// width in ciphers: 1 for 20011, 2 for 20012, 3 for 20013.
func verifyDiskCryptor(target, candidate string, maxCiphers int) (bool, error) {
	header, err := parseDiskCryptor(target)
	if err != nil {
		return false, err
	}
	// DiskCryptor is a Windows tool and hashes the passphrase as UTF-16LE.
	key := pbkdf2.Key(utf16leBytes(candidate), header[:dcrpSaltLen], dcrpIter, maxCiphers*64, sha512.New)
	return dcrpHeaderValid(key, header[dcrpSigOffset:dcrpSigOffset+16], maxCiphers), nil
}
