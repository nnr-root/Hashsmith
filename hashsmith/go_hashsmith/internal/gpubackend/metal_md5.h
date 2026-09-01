//go:build gpu && darwin && !opencl
#ifndef HS_METAL_MD5_H
#define HS_METAL_MD5_H
#include <stdint.h>
void *hs_metal_init(char *errbuf, int errlen);
const char *hs_metal_name(void *ctx);
int hs_metal_md5(void *ctx, const uint8_t *data, const uint32_t *offsets, int n, uint8_t *out);
int hs_metal_md5_brute(void *ctx, const uint8_t *charset, uint32_t csLen, uint32_t wordLen,
                       uint64_t start, uint32_t count, const uint8_t *target16, uint64_t *outIdx);
int hs_metal_md5_mask(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                      uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target16, uint64_t *outIdx);
int hs_metal_md5_mask_multi(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                            uint32_t wordLen, uint64_t start, uint32_t count,
                            const uint32_t *targets, uint32_t nTargets,
                            uint32_t *foundFlag, uint64_t *foundIdx);
int hs_metal_ntlm_mask(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                       uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target16, uint64_t *outIdx);
int hs_metal_ntlm_mask_multi(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                             uint32_t wordLen, uint64_t start, uint32_t count,
                             const uint32_t *targets, uint32_t nTargets,
                             uint32_t *foundFlag, uint64_t *foundIdx);
int hs_metal_sha256_mask(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                         uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target32, uint64_t *outIdx);
int hs_metal_sha256_mask_multi(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                               uint32_t wordLen, uint64_t start, uint32_t count,
                               const uint32_t *targets, uint32_t nTargets,
                               uint32_t *foundFlag, uint64_t *foundIdx);
int hs_metal_sha1_mask(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                       uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target20, uint64_t *outIdx);
int hs_metal_sha1_mask_multi(void *ctx, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                             uint32_t wordLen, uint64_t start, uint32_t count,
                             const uint32_t *targets, uint32_t nTargets,
                             uint32_t *foundFlag, uint64_t *foundIdx);
int hs_metal_sweep_multi(void *ctx, int algo,
                         const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff, uint32_t wordLen,
                         uint64_t start, uint64_t span, uint32_t chunk,
                         const uint32_t *targets, uint32_t nTargets, uint32_t targetWords,
                         uint32_t *foundFlag, uint64_t *foundIdx);
void hs_metal_free(void *ctx);
#endif
