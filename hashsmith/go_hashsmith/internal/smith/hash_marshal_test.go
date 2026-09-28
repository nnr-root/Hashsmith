package smith

import (
	"crypto/hmac"
	"encoding"
	"hash"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// opaqueHash hides a hash's BinaryMarshaler so crypto/hmac cannot use the
// state-caching path. It is the control: HMAC over the wrapped hash must agree
// with HMAC over the bare one, which is the only thing that makes adding a
// marshaler safe.
type opaqueHash struct{ hash.Hash }

// Every hash that VeraCrypt's KDF can select must be marshalable, or its
// 500,000-iteration PBKDF2 loop silently pays two extra compressions per
// iteration. This is an assertion about performance, so it is written as one:
// a hash losing its marshaler would otherwise cost only speed, and nothing
// would go red.
func TestVeraCryptKDFHashesAreMarshalable(t *testing.T) {
	for name, newHash := range map[string]func() hash.Hash{
		"ripemd160":         newRIPEMD160,
		"whirlpool":         newWhirlpool,
		"streebog512native": newStreebog512Native,
	} {
		h := newHash()
		if _, ok := h.(encoding.BinaryMarshaler); !ok {
			t.Errorf("%s does not implement encoding.BinaryMarshaler; "+
				"crypto/hmac will re-compress ipad and opad on every PBKDF2 iteration", name)
		}
		if _, ok := h.(encoding.BinaryUnmarshaler); !ok {
			t.Errorf("%s does not implement encoding.BinaryUnmarshaler", name)
		}
	}
}

func TestHashMarshalRoundTrip(t *testing.T) {
	for name, newHash := range map[string]func() hash.Hash{
		"whirlpool":         newWhirlpool,
		"streebog512":       newStreebog512,
		"streebog256":       newStreebog256,
		"streebog512native": newStreebog512Native,
	} {
		for n := 0; n <= 130; n++ {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i * 11)
			}
			saved := newHash()
			_, _ = saved.Write(msg)
			state, err := saved.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Fatalf("%s length %d: %v", name, n, err)
			}
			restored := newHash()
			if err := restored.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Fatalf("%s length %d: %v", name, n, err)
			}
			tail := []byte("tail bytes written past the restore point")
			_, _ = saved.Write(tail)
			_, _ = restored.Write(tail)
			if string(saved.Sum(nil)) != string(restored.Sum(nil)) {
				t.Fatalf("%s length %d: restored state diverged", name, n)
			}
		}
	}
}

func TestStreebogMarshalRejectsForeignState(t *testing.T) {
	state, err := newStreebog256().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := newStreebog512().(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err == nil {
		t.Error("a Streebog-256 state was accepted by Streebog-512")
	}
	if err := newStreebog256().(encoding.BinaryUnmarshaler).UnmarshalBinary(state[:len(state)-1]); err == nil {
		t.Error("a truncated state was accepted")
	}
	wp, err := newWhirlpool().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := newStreebog512().(encoding.BinaryUnmarshaler).UnmarshalBinary(wp); err == nil {
		t.Error("a Whirlpool state was accepted by Streebog-512")
	}
	if err := newWhirlpool().(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err == nil {
		t.Error("a Streebog state was accepted by Whirlpool")
	}
}

// The marshaler changes which code path crypto/hmac takes, so HMAC and PBKDF2
// results must be compared against the same hash with its marshaler hidden.
// Agreeing on bare digests proves nothing about agreeing here.
func TestHMACAgreesWithAndWithoutMarshaler(t *testing.T) {
	for name, newHash := range map[string]func() hash.Hash{
		"ripemd160":         newRIPEMD160,
		"whirlpool":         newWhirlpool,
		"streebog512native": newStreebog512Native,
	} {
		opaque := func() hash.Hash { return opaqueHash{newHash()} }
		if _, ok := opaque().(encoding.BinaryMarshaler); ok {
			t.Fatalf("%s: the control wrapper did not hide the marshaler", name)
		}
		for _, key := range [][]byte{
			[]byte(""),
			[]byte("short"),
			make([]byte, 64),  // exactly one block
			make([]byte, 200), // longer than a block: HMAC hashes it down first
		} {
			msg := []byte("the message under test")
			fast := hmac.New(newHash, key)
			_, _ = fast.Write(msg)
			slow := hmac.New(opaque, key)
			_, _ = slow.Write(msg)
			if string(fast.Sum(nil)) != string(slow.Sum(nil)) {
				t.Fatalf("%s: HMAC differs with a %d-byte key depending on the marshaler", name, len(key))
			}
		}
		// dkLen 192 is VeraCrypt's cascade width, and the iteration count is
		// deliberately not 1: the marshaler only matters from the second
		// iteration onwards.
		a := pbkdf2.Key([]byte("passphrase"), []byte("saltsalt"), 17, 192, newHash)
		b := pbkdf2.Key([]byte("passphrase"), []byte("saltsalt"), 17, 192, opaque)
		if string(a) != string(b) {
			t.Fatalf("%s: PBKDF2 differs depending on the marshaler", name)
		}
	}
}
