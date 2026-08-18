//go:build gpu && darwin

package main

/*
#cgo darwin LDFLAGS: -framework Metal -framework Foundation
#include <stdlib.h>
#include "metal_md5.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// metalBackend runs the MD5 kernel on the Apple GPU via Metal. The MSL source is
// compiled at runtime (newLibraryWithSource), so the offline `metal` shader
// toolchain is not required — only the Metal framework, present on every Mac.
type metalBackend struct {
	ctx unsafe.Pointer
	dev string
}

func newGPUBackend() (gpuBackend, string) {
	var errbuf [256]C.char
	ctx := C.hs_metal_init(&errbuf[0], 256)
	if ctx == nil {
		return nil, C.GoString(&errbuf[0])
	}
	return &metalBackend{ctx: ctx, dev: C.GoString(C.hs_metal_name(ctx))}, ""
}

func (m *metalBackend) name() string { return "Metal (" + m.dev + ")" }

func (m *metalBackend) close() {
	if m.ctx != nil {
		C.hs_metal_free(m.ctx)
		m.ctx = nil
	}
}

// md5 hashes candidates (each ≤55 bytes) in one GPU dispatch.
func (m *metalBackend) md5(cands []string, out [][16]byte) error {
	n := len(cands)
	if n == 0 {
		return nil
	}
	offsets := make([]C.uint32_t, n+1)
	total := 0
	for i, c := range cands {
		offsets[i] = C.uint32_t(total)
		total += len(c)
	}
	offsets[n] = C.uint32_t(total)
	data := make([]byte, total+1) // +1 so &data[0] is valid even if total==0
	p := 0
	for _, c := range cands {
		p += copy(data[p:], c)
	}
	outbuf := make([]byte, n*16)
	rc := C.hs_metal_md5(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		&offsets[0], C.int(n),
		(*C.uint8_t)(unsafe.Pointer(&outbuf[0])))
	if rc != 0 {
		return errors.New("metal md5 dispatch failed")
	}
	for i := 0; i < n; i++ {
		copy(out[i][:], outbuf[i*16:i*16+16])
	}
	return nil
}

// md5Brute dispatches the in-kernel brute-force search over [start, start+count).
func (m *metalBackend) md5Brute(charset string, wordLen int, target [16]byte, start uint64, count uint32) (uint64, bool, error) {
	if count == 0 || len(charset) == 0 {
		return 0, false, nil
	}
	cs := []byte(charset)
	tgt := target
	var outIdx C.uint64_t
	rc := C.hs_metal_md5_brute(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&cs[0])), C.uint32_t(len(cs)), C.uint32_t(wordLen),
		C.uint64_t(start), C.uint32_t(count),
		(*C.uint8_t)(unsafe.Pointer(&tgt[0])), &outIdx)
	if rc < 0 {
		return 0, false, errors.New("metal brute dispatch failed")
	}
	return uint64(outIdx), rc == 1, nil
}

// md5Mask dispatches the in-kernel mask search over [start, start+count).
func (m *metalBackend) md5Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error) {
	if count == 0 || len(sets) == 0 {
		return 0, false, nil
	}
	// Flatten the per-position charsets and record their offsets.
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	var outIdx C.uint64_t
	rc := C.hs_metal_md5_mask(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint8_t)(unsafe.Pointer(&target[0])), &outIdx)
	if rc < 0 {
		return 0, false, errors.New("metal mask dispatch failed")
	}
	return uint64(outIdx), rc == 1, nil
}

// md5MaskMulti searches [start, start+count) for candidates matching any of the
// sorted targets (each 4 uint32). foundFlag/foundIdx are in/out state carried
// across dispatches: a target already flagged is skipped by the kernel.
func (m *metalBackend) md5MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32,
	foundFlag []uint32, foundIdx []uint64) error {
	if count == 0 || len(sets) == 0 || len(foundFlag) == 0 {
		return nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	rc := C.hs_metal_md5_mask_multi(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint32_t)(unsafe.Pointer(&targets[0])), C.uint32_t(len(foundFlag)),
		(*C.uint32_t)(unsafe.Pointer(&foundFlag[0])), (*C.uint64_t)(unsafe.Pointer(&foundIdx[0])))
	if rc < 0 {
		return errors.New("metal mask-multi dispatch failed")
	}
	return nil
}

// ntlmMask / ntlmMaskMulti mirror the md5 variants using the NTLM kernels.
func (m *metalBackend) ntlmMask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error) {
	if count == 0 || len(sets) == 0 {
		return 0, false, nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	var outIdx C.uint64_t
	rc := C.hs_metal_ntlm_mask(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint8_t)(unsafe.Pointer(&target[0])), &outIdx)
	if rc < 0 {
		return 0, false, errors.New("metal ntlm mask dispatch failed")
	}
	return uint64(outIdx), rc == 1, nil
}

func (m *metalBackend) ntlmMaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32,
	foundFlag []uint32, foundIdx []uint64) error {
	if count == 0 || len(sets) == 0 || len(foundFlag) == 0 {
		return nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	rc := C.hs_metal_ntlm_mask_multi(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint32_t)(unsafe.Pointer(&targets[0])), C.uint32_t(len(foundFlag)),
		(*C.uint32_t)(unsafe.Pointer(&foundFlag[0])), (*C.uint64_t)(unsafe.Pointer(&foundIdx[0])))
	if rc < 0 {
		return errors.New("metal ntlm mask-multi dispatch failed")
	}
	return nil
}

// sha256Mask / sha256MaskMulti use the SHA-256 kernels (32-byte digests).
func (m *metalBackend) sha256Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error) {
	if count == 0 || len(sets) == 0 {
		return 0, false, nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	var outIdx C.uint64_t
	rc := C.hs_metal_sha256_mask(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint8_t)(unsafe.Pointer(&target[0])), &outIdx)
	if rc < 0 {
		return 0, false, errors.New("metal sha256 mask dispatch failed")
	}
	return uint64(outIdx), rc == 1, nil
}

func (m *metalBackend) sha256MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32,
	foundFlag []uint32, foundIdx []uint64) error {
	if count == 0 || len(sets) == 0 || len(foundFlag) == 0 {
		return nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	rc := C.hs_metal_sha256_mask_multi(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint32_t)(unsafe.Pointer(&targets[0])), C.uint32_t(len(foundFlag)),
		(*C.uint32_t)(unsafe.Pointer(&foundFlag[0])), (*C.uint64_t)(unsafe.Pointer(&foundIdx[0])))
	if rc < 0 {
		return errors.New("metal sha256 mask-multi dispatch failed")
	}
	return nil
}

// sha1Mask / sha1MaskMulti use the SHA-1 kernels (20-byte digests).
func (m *metalBackend) sha1Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error) {
	if count == 0 || len(sets) == 0 {
		return 0, false, nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	var outIdx C.uint64_t
	rc := C.hs_metal_sha1_mask(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint8_t)(unsafe.Pointer(&target[0])), &outIdx)
	if rc < 0 {
		return 0, false, errors.New("metal sha1 mask dispatch failed")
	}
	return uint64(outIdx), rc == 1, nil
}

func (m *metalBackend) sha1MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32,
	foundFlag []uint32, foundIdx []uint64) error {
	if count == 0 || len(sets) == 0 || len(foundFlag) == 0 {
		return nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	rc := C.hs_metal_sha1_mask_multi(m.ctx,
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint32_t)(unsafe.Pointer(&targets[0])), C.uint32_t(len(foundFlag)),
		(*C.uint32_t)(unsafe.Pointer(&foundFlag[0])), (*C.uint64_t)(unsafe.Pointer(&foundIdx[0])))
	if rc < 0 {
		return errors.New("metal sha1 mask-multi dispatch failed")
	}
	return nil
}

// maskSweepMulti runs a pipelined multi-target sweep over [start, start+span),
// keeping several command buffers in flight so the GPU never idles between
// chunks. foundFlag/foundIdx are in/out (accumulated).
func (m *metalBackend) maskSweepMulti(algo int, sets [][]byte, targetWords int, targets []uint32,
	start, span uint64, chunk uint32, foundFlag []uint32, foundIdx []uint64) error {
	if span == 0 || len(sets) == 0 || len(foundFlag) == 0 {
		return nil
	}
	offsets := make([]C.uint32_t, len(sets)+1)
	var flat []byte
	for i, set := range sets {
		offsets[i] = C.uint32_t(len(flat))
		flat = append(flat, set...)
	}
	offsets[len(sets)] = C.uint32_t(len(flat))
	if len(flat) == 0 {
		flat = []byte{0}
	}
	rc := C.hs_metal_sweep_multi(m.ctx, C.int(algo),
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0], C.uint32_t(len(sets)),
		C.uint64_t(start), C.uint64_t(span), C.uint32_t(chunk),
		(*C.uint32_t)(unsafe.Pointer(&targets[0])), C.uint32_t(len(foundFlag)), C.uint32_t(targetWords),
		(*C.uint32_t)(unsafe.Pointer(&foundFlag[0])), (*C.uint64_t)(unsafe.Pointer(&foundIdx[0])))
	if rc < 0 {
		return errors.New("metal pipelined sweep failed")
	}
	return nil
}
