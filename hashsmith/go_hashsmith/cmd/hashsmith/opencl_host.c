//go:build opencl

#define CL_SILENCE_DEPRECATION
#define CL_TARGET_OPENCL_VERSION 120
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "opencl_host.h"

// Kernel ids must match the Go side.
static const char *kNames[9] = {
    "md5mask","md5maskmulti","ntlmmask","ntlmmaskmulti",
    "sha256mask","sha256maskmulti","sha1mask","sha1maskmulti","md5k"};

typedef struct {
    cl_context ctx;
    cl_command_queue queue;
    cl_program prog;
    cl_kernel kernels[9];
    char name[128];
} hs_ocl;

void *hs_ocl_init(const char *src, char *err, int errlen) {
    cl_uint np = 0;
    if (clGetPlatformIDs(0, NULL, &np) != CL_SUCCESS || np == 0) { snprintf(err, errlen, "no OpenCL platform"); return NULL; }
    cl_platform_id plat; clGetPlatformIDs(1, &plat, NULL);
    cl_device_id dev;
    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL) != CL_SUCCESS) {
        if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, 1, &dev, NULL) != CL_SUCCESS) { snprintf(err, errlen, "no OpenCL device"); return NULL; }
    }
    cl_int e;
    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &e);
    if (e != CL_SUCCESS) { snprintf(err, errlen, "clCreateContext %d", e); return NULL; }
    cl_command_queue q = clCreateCommandQueue(ctx, dev, 0, &e);
    if (e != CL_SUCCESS) { snprintf(err, errlen, "clCreateCommandQueue %d", e); return NULL; }
    size_t slen = strlen(src);
    cl_program prog = clCreateProgramWithSource(ctx, 1, &src, &slen, &e);
    if (e != CL_SUCCESS) { snprintf(err, errlen, "clCreateProgram %d", e); return NULL; }
    if (clBuildProgram(prog, 1, &dev, "", NULL, NULL) != CL_SUCCESS) {
        size_t ln = 0; clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &ln);
        char *log = (char *)malloc(ln + 1); log[ln] = 0;
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, ln, log, NULL);
        snprintf(err, errlen, "build failed: %.*s", errlen - 16, log);
        free(log); return NULL;
    }
    hs_ocl *h = (hs_ocl *)calloc(1, sizeof(hs_ocl));
    h->ctx = ctx; h->queue = q; h->prog = prog;
    for (int i = 0; i < 9; i++) {
        h->kernels[i] = clCreateKernel(prog, kNames[i], &e);
        if (e != CL_SUCCESS) { snprintf(err, errlen, "kernel %s missing", kNames[i]); free(h); return NULL; }
    }
    clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(h->name), h->name, NULL);
    return h;
}

const char *hs_ocl_name(void *c) { return ((hs_ocl *)c)->name; }

// single-target mask (kid is even: md5mask/ntlmmask/sha256mask/sha1mask)
int hs_ocl_mask(void *c, int kid, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                uint32_t wordLen, uint64_t start, uint32_t count,
                const uint8_t *target, uint32_t targetLen, uint64_t *outIdx) {
    hs_ocl *h = (hs_ocl *)c; cl_int e; cl_kernel k = h->kernels[kid];
    cl_ulong s = start; cl_uint zero = 0; cl_ulong zidx = 0;
    cl_mem bSets = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, setsLen ? setsLen : 1, (void *)sets, &e);
    cl_mem bOff = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (wordLen + 1) * sizeof(uint32_t), (void *)setOff, &e);
    cl_mem bTgt = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, targetLen, (void *)target, &e);
    cl_mem bFound = clCreateBuffer(h->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(cl_uint), &zero, &e);
    cl_mem bFi = clCreateBuffer(h->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(cl_ulong), &zidx, &e);
    clSetKernelArg(k, 0, sizeof(cl_mem), &bSets);
    clSetKernelArg(k, 1, sizeof(cl_mem), &bOff);
    clSetKernelArg(k, 2, sizeof(cl_uint), &wordLen);
    clSetKernelArg(k, 3, sizeof(cl_ulong), &s);
    clSetKernelArg(k, 4, sizeof(cl_uint), &count);
    clSetKernelArg(k, 5, sizeof(cl_mem), &bTgt);
    clSetKernelArg(k, 6, sizeof(cl_mem), &bFound);
    clSetKernelArg(k, 7, sizeof(cl_mem), &bFi);
    size_t gsz = count;
    e = clEnqueueNDRangeKernel(h->queue, k, 1, NULL, &gsz, NULL, 0, NULL, NULL);
    clFinish(h->queue);
    cl_uint found = 0; clEnqueueReadBuffer(h->queue, bFound, CL_TRUE, 0, sizeof(cl_uint), &found, 0, NULL, NULL);
    if (found) clEnqueueReadBuffer(h->queue, bFi, CL_TRUE, 0, sizeof(cl_ulong), outIdx, 0, NULL, NULL);
    clReleaseMemObject(bSets); clReleaseMemObject(bOff); clReleaseMemObject(bTgt); clReleaseMemObject(bFound); clReleaseMemObject(bFi);
    return found ? 1 : (e == CL_SUCCESS ? 0 : -1);
}

// multi-target pipelined sweep (kid is odd: *maskmulti)
int hs_ocl_sweep_multi(void *c, int kid, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                       uint32_t wordLen, uint64_t start, uint64_t span, uint32_t chunk,
                       const uint32_t *targets, uint32_t nTargets, uint32_t targetWords,
                       uint32_t *foundFlag, uint64_t *foundIdx) {
    hs_ocl *h = (hs_ocl *)c; cl_int e; cl_kernel k = h->kernels[kid];
    cl_mem bSets = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, setsLen ? setsLen : 1, (void *)sets, &e);
    cl_mem bOff = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (wordLen + 1) * sizeof(uint32_t), (void *)setOff, &e);
    cl_mem bTgt = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, nTargets * targetWords * sizeof(uint32_t), (void *)targets, &e);
    cl_mem bFlag = clCreateBuffer(h->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, nTargets * sizeof(uint32_t), foundFlag, &e);
    cl_mem bFi = clCreateBuffer(h->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, nTargets * sizeof(uint64_t), foundIdx, &e);
    clSetKernelArg(k, 0, sizeof(cl_mem), &bSets);
    clSetKernelArg(k, 1, sizeof(cl_mem), &bOff);
    clSetKernelArg(k, 2, sizeof(cl_uint), &wordLen);
    // args 3 (start), 4 (count) set per chunk
    clSetKernelArg(k, 5, sizeof(cl_mem), &bTgt);
    clSetKernelArg(k, 6, sizeof(cl_uint), &nTargets);
    clSetKernelArg(k, 7, sizeof(cl_mem), &bFlag);
    clSetKernelArg(k, 8, sizeof(cl_mem), &bFi);
    uint64_t off = 0;
    while (off < span) {
        cl_uint cnt = (span - off > (uint64_t)chunk) ? chunk : (cl_uint)(span - off);
        cl_ulong s = start + off;
        clSetKernelArg(k, 3, sizeof(cl_ulong), &s);
        clSetKernelArg(k, 4, sizeof(cl_uint), &cnt);
        size_t gsz = cnt;
        clEnqueueNDRangeKernel(h->queue, k, 1, NULL, &gsz, NULL, 0, NULL, NULL); // queued, runs back-to-back
        off += cnt;
    }
    clFinish(h->queue);
    clEnqueueReadBuffer(h->queue, bFlag, CL_TRUE, 0, nTargets * sizeof(uint32_t), foundFlag, 0, NULL, NULL);
    clEnqueueReadBuffer(h->queue, bFi, CL_TRUE, 0, nTargets * sizeof(uint64_t), foundIdx, 0, NULL, NULL);
    clReleaseMemObject(bSets); clReleaseMemObject(bOff); clReleaseMemObject(bTgt); clReleaseMemObject(bFlag); clReleaseMemObject(bFi);
    return 0;
}

int hs_ocl_md5_batch(void *c, const uint8_t *data, const uint32_t *offsets, int n, uint8_t *out) {
    hs_ocl *h = (hs_ocl *)c; cl_int e; cl_kernel k = h->kernels[8];
    uint32_t total = offsets[n]; if (total == 0) total = 1;
    cl_mem bData = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, total, (void *)data, &e);
    cl_mem bOff = clCreateBuffer(h->ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (n + 1) * sizeof(uint32_t), (void *)offsets, &e);
    cl_mem bOut = clCreateBuffer(h->ctx, CL_MEM_WRITE_ONLY, n * 16, NULL, &e);
    cl_uint nn = (cl_uint)n;
    clSetKernelArg(k, 0, sizeof(cl_mem), &bData);
    clSetKernelArg(k, 1, sizeof(cl_mem), &bOff);
    clSetKernelArg(k, 2, sizeof(cl_mem), &bOut);
    clSetKernelArg(k, 3, sizeof(cl_uint), &nn);
    size_t gsz = n;
    clEnqueueNDRangeKernel(h->queue, k, 1, NULL, &gsz, NULL, 0, NULL, NULL);
    clFinish(h->queue);
    clEnqueueReadBuffer(h->queue, bOut, CL_TRUE, 0, n * 16, out, 0, NULL, NULL);
    clReleaseMemObject(bData); clReleaseMemObject(bOff); clReleaseMemObject(bOut);
    return e == CL_SUCCESS ? 0 : -1;
}

void hs_ocl_free(void *c) {
    hs_ocl *h = (hs_ocl *)c;
    if (!h) return;
    for (int i = 0; i < 9; i++) if (h->kernels[i]) clReleaseKernel(h->kernels[i]);
    if (h->prog) clReleaseProgram(h->prog);
    if (h->queue) clReleaseCommandQueue(h->queue);
    if (h->ctx) clReleaseContext(h->ctx);
    free(h);
}
