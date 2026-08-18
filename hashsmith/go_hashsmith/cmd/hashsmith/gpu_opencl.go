//go:build opencl

package main

/*
#cgo darwin LDFLAGS: -framework OpenCL
#cgo linux LDFLAGS: -lOpenCL
#include <stdlib.h>
#include "opencl_host.h"
*/
import "C"
import (
	_ "embed"
	"errors"
	"unsafe"
)

//go:embed opencl_kernels.cl
var openclSrc string

// oclBackend implements gpuBackend on any OpenCL device (NVIDIA / AMD / Intel /
// Apple), so the same kernels accelerate cracking across every GPU vendor.
type oclBackend struct {
	ctx unsafe.Pointer
	dev string
}

func newGPUBackend() (gpuBackend, string) {
	var errbuf [512]C.char
	csrc := C.CString(openclSrc)
	defer C.free(unsafe.Pointer(csrc))
	ctx := C.hs_ocl_init(csrc, &errbuf[0], 512)
	if ctx == nil {
		return nil, C.GoString(&errbuf[0])
	}
	return &oclBackend{ctx: ctx, dev: C.GoString(C.hs_ocl_name(ctx))}, ""
}

func (o *oclBackend) name() string { return "OpenCL (" + o.dev + ")" }
func (o *oclBackend) close() {
	if o.ctx != nil {
		C.hs_ocl_free(o.ctx)
		o.ctx = nil
	}
}

func (o *oclBackend) md5(cands []string, out [][16]byte) error {
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
	data := make([]byte, total+1)
	p := 0
	for _, c := range cands {
		p += copy(data[p:], c)
	}
	outbuf := make([]byte, n*16)
	rc := C.hs_ocl_md5_batch(o.ctx, (*C.uint8_t)(unsafe.Pointer(&data[0])), &offsets[0], C.int(n),
		(*C.uint8_t)(unsafe.Pointer(&outbuf[0])))
	if rc < 0 {
		return errors.New("opencl md5 batch failed")
	}
	for i := 0; i < n; i++ {
		copy(out[i][:], outbuf[i*16:i*16+16])
	}
	return nil
}

func (o *oclBackend) maskOne(kid int, sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error) {
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
	rc := C.hs_ocl_mask(o.ctx, C.int(kid),
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint32_t(count),
		(*C.uint8_t)(unsafe.Pointer(&target[0])), C.uint32_t(len(target)), &outIdx)
	if rc < 0 {
		return 0, false, errors.New("opencl mask dispatch failed")
	}
	return uint64(outIdx), rc == 1, nil
}

func (o *oclBackend) md5Mask(s [][]byte, t []byte, st uint64, c uint32) (uint64, bool, error) {
	return o.maskOne(0, s, t, st, c)
}
func (o *oclBackend) ntlmMask(s [][]byte, t []byte, st uint64, c uint32) (uint64, bool, error) {
	return o.maskOne(2, s, t, st, c)
}
func (o *oclBackend) sha256Mask(s [][]byte, t []byte, st uint64, c uint32) (uint64, bool, error) {
	return o.maskOne(4, s, t, st, c)
}
func (o *oclBackend) sha1Mask(s [][]byte, t []byte, st uint64, c uint32) (uint64, bool, error) {
	return o.maskOne(6, s, t, st, c)
}

func (o *oclBackend) sweep(kid, words int, sets [][]byte, targets []uint32, start, span uint64, chunk uint32, ff []uint32, fi []uint64) error {
	if span == 0 || len(sets) == 0 || len(ff) == 0 {
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
	rc := C.hs_ocl_sweep_multi(o.ctx, C.int(kid),
		(*C.uint8_t)(unsafe.Pointer(&flat[0])), C.uint32_t(len(flat)), &offsets[0],
		C.uint32_t(len(sets)), C.uint64_t(start), C.uint64_t(span), C.uint32_t(chunk),
		(*C.uint32_t)(unsafe.Pointer(&targets[0])), C.uint32_t(len(ff)), C.uint32_t(words),
		(*C.uint32_t)(unsafe.Pointer(&ff[0])), (*C.uint64_t)(unsafe.Pointer(&fi[0])))
	if rc < 0 {
		return errors.New("opencl sweep dispatch failed")
	}
	return nil
}
func (o *oclBackend) md5MaskMulti(s [][]byte, t []uint32, st uint64, c uint32, ff []uint32, fi []uint64) error {
	return o.sweep(1, 4, s, t, st, uint64(c), c, ff, fi)
}
func (o *oclBackend) ntlmMaskMulti(s [][]byte, t []uint32, st uint64, c uint32, ff []uint32, fi []uint64) error {
	return o.sweep(3, 4, s, t, st, uint64(c), c, ff, fi)
}
func (o *oclBackend) sha256MaskMulti(s [][]byte, t []uint32, st uint64, c uint32, ff []uint32, fi []uint64) error {
	return o.sweep(5, 8, s, t, st, uint64(c), c, ff, fi)
}
func (o *oclBackend) sha1MaskMulti(s [][]byte, t []uint32, st uint64, c uint32, ff []uint32, fi []uint64) error {
	return o.sweep(7, 5, s, t, st, uint64(c), c, ff, fi)
}
func (o *oclBackend) maskSweepMulti(algo int, sets [][]byte, targetWords int, targets []uint32, start, span uint64, chunk uint32, ff []uint32, fi []uint64) error {
	return o.sweep(algo*2+1, targetWords, sets, targets, start, span, chunk, ff, fi)
}

// md5Brute is unused by the drivers (they use the mask path); satisfy interface.
func (o *oclBackend) md5Brute(charset string, wordLen int, target [16]byte, start uint64, count uint32) (uint64, bool, error) {
	return 0, false, errors.New("opencl brute uses the mask path")
}
