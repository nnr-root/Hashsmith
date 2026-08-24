package main

// A buffering hash.Hash adapter around the compact one-shot SM3 primitive.
// SM3-crypt and HMAC need the streaming interface; candidate records are small,
// so retaining the input is simpler and less error-prone than duplicating the
// compression implementation.

type sm3Digest struct{ data []byte }

func newSM3() *sm3Digest                         { return &sm3Digest{} }
func (d *sm3Digest) Size() int                   { return 32 }
func (d *sm3Digest) BlockSize() int              { return 64 }
func (d *sm3Digest) Reset()                      { d.data = d.data[:0] }
func (d *sm3Digest) Write(p []byte) (int, error) { d.data = append(d.data, p...); return len(p), nil }
func (d *sm3Digest) Sum(in []byte) []byte        { return append(in, sm3Sum(d.data)...) }
