//go:build opencl
#ifndef HS_OCL_H
#define HS_OCL_H
#include <stdint.h>
void *hs_ocl_init(const char *src, char *err, int errlen);
const char *hs_ocl_name(void *ctx);
int hs_ocl_mask(void *ctx, int kid, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                uint32_t wordLen, uint64_t start, uint32_t count,
                const uint8_t *target, uint32_t targetLen, uint64_t *outIdx);
int hs_ocl_sweep_multi(void *ctx, int kid, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                       uint32_t wordLen, uint64_t start, uint64_t span, uint32_t chunk,
                       const uint32_t *targets, uint32_t nTargets, uint32_t targetWords,
                       uint32_t *foundFlag, uint64_t *foundIdx);
int hs_ocl_md5_batch(void *ctx, const uint8_t *data, const uint32_t *offsets, int n, uint8_t *out);
void hs_ocl_free(void *ctx);
#endif
