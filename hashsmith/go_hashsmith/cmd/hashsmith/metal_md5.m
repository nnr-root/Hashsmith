//go:build gpu && darwin && !opencl

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include "metal_md5.h"
#include <string.h>

// Two MD5 kernels sharing one compress function:
//   md5k     — hash a batch of CPU-provided candidates (transfer-bound)
//   md5brute — generate each candidate from its keyspace index IN-KERNEL, hash,
//              and compare to the target on-device, so no candidates are
//              transferred and only a match flag returns (the fast path).
static const char *kMSL =
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"constant uint K[64] = {\n"
"0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,\n"
"0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,\n"
"0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,\n"
"0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,\n"
"0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,\n"
"0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,\n"
"0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,\n"
"0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};\n"
"constant uint S[64] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,\n"
"5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,\n"
"4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,\n"
"6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};\n"
"static void md5_compress(thread uint* M, thread uint& a0, thread uint& b0, thread uint& c0, thread uint& d0){\n"
"  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;\n"
"  for (uint i=0;i<64;i++){\n"
"    uint f,g;\n"
"    if (i<16){ f=(b&c)|((~b)&d); g=i; }\n"
"    else if (i<32){ f=(d&b)|((~d)&c); g=(5*i+1)&15; }\n"
"    else if (i<48){ f=b^c^d; g=(3*i+5)&15; }\n"
"    else { f=c^(b|(~d)); g=(7*i)&15; }\n"
"    uint tmp=d; d=c; c=b;\n"
"    uint x=a+f+K[i]+M[g]; uint s=S[i];\n"
"    b=b+((x<<s)|(x>>(32-s)));\n"
"    a=tmp;\n"
"  }\n"
"  a0=a+0x67452301; b0=b+0xefcdab89; c0=c+0x98badcfe; d0=d+0x10325476;\n"
"}\n"
"static void build_block(thread uchar* msg, uint len){\n"
"  msg[len]=0x80;\n"
"  uint bitlen=len*8;\n"
"  msg[56]=bitlen&0xff; msg[57]=(bitlen>>8)&0xff; msg[58]=(bitlen>>16)&0xff; msg[59]=(bitlen>>24)&0xff;\n"
"}\n"
"#define ROTL(x,s) (((x)<<(s))|((x)>>(32u-(s))))\n"
"static void md4_compress(thread uint* M, thread uint& a0, thread uint& b0, thread uint& c0, thread uint& d0){\n"
"  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;\n"
"#define FF(a,b,c,d,k,s) a=ROTL(a+(((b)&(c))|((~(b))&(d)))+M[k], s)\n"
"  FF(a,b,c,d,0,3); FF(d,a,b,c,1,7); FF(c,d,a,b,2,11); FF(b,c,d,a,3,19);\n"
"  FF(a,b,c,d,4,3); FF(d,a,b,c,5,7); FF(c,d,a,b,6,11); FF(b,c,d,a,7,19);\n"
"  FF(a,b,c,d,8,3); FF(d,a,b,c,9,7); FF(c,d,a,b,10,11); FF(b,c,d,a,11,19);\n"
"  FF(a,b,c,d,12,3); FF(d,a,b,c,13,7); FF(c,d,a,b,14,11); FF(b,c,d,a,15,19);\n"
"#define GG(a,b,c,d,k,s) a=ROTL(a+(((b)&(c))|((b)&(d))|((c)&(d)))+M[k]+0x5a827999u, s)\n"
"  GG(a,b,c,d,0,3); GG(d,a,b,c,4,5); GG(c,d,a,b,8,9); GG(b,c,d,a,12,13);\n"
"  GG(a,b,c,d,1,3); GG(d,a,b,c,5,5); GG(c,d,a,b,9,9); GG(b,c,d,a,13,13);\n"
"  GG(a,b,c,d,2,3); GG(d,a,b,c,6,5); GG(c,d,a,b,10,9); GG(b,c,d,a,14,13);\n"
"  GG(a,b,c,d,3,3); GG(d,a,b,c,7,5); GG(c,d,a,b,11,9); GG(b,c,d,a,15,13);\n"
"#define HH(a,b,c,d,k,s) a=ROTL(a+((b)^(c)^(d))+M[k]+0x6ed9eba1u, s)\n"
"  HH(a,b,c,d,0,3); HH(d,a,b,c,8,9); HH(c,d,a,b,4,11); HH(b,c,d,a,12,15);\n"
"  HH(a,b,c,d,2,3); HH(d,a,b,c,10,9); HH(c,d,a,b,6,11); HH(b,c,d,a,14,15);\n"
"  HH(a,b,c,d,1,3); HH(d,a,b,c,9,9); HH(c,d,a,b,5,11); HH(b,c,d,a,13,15);\n"
"  HH(a,b,c,d,3,3); HH(d,a,b,c,11,9); HH(c,d,a,b,7,11); HH(b,c,d,a,15,15);\n"
"#undef FF\n#undef GG\n#undef HH\n"
"  a0=a+0x67452301; b0=b+0xefcdab89; c0=c+0x98badcfe; d0=d+0x10325476;\n"
"}\n"
"constant uint SK[64] = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};\n"
"static void build_block_be(thread uchar* msg, uint len){ msg[len]=0x80; uint bl=len*8u; msg[63]=bl&0xff; msg[62]=(bl>>8)&0xff; msg[61]=(bl>>16)&0xff; msg[60]=(bl>>24)&0xff; }\n"
"static void sha256_compress(thread uint* M, thread uint* H8){\n"
"  uint w[64];\n"
"  for (uint i=0;i<16;i++) w[i]=M[i];\n"
"  for (uint i=16;i<64;i++){ uint x=w[i-15]; uint s0=((x>>7)|(x<<25))^((x>>18)|(x<<14))^(x>>3); uint y=w[i-2]; uint s1=((y>>17)|(y<<15))^((y>>19)|(y<<13))^(y>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }\n"
"  uint a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;\n"
"  for (uint i=0;i<64;i++){ uint S1=((e>>6)|(e<<26))^((e>>11)|(e<<21))^((e>>25)|(e<<7)); uint ch=(e&f)^((~e)&g); uint t1=h+S1+ch+SK[i]+w[i]; uint S0=((a>>2)|(a<<30))^((a>>13)|(a<<19))^((a>>22)|(a<<10)); uint mj=(a&b)^(a&c)^(b&c); uint t2=S0+mj; h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }\n"
"  H8[0]=a+0x6a09e667;H8[1]=b+0xbb67ae85;H8[2]=c+0x3c6ef372;H8[3]=d+0xa54ff53a;H8[4]=e+0x510e527f;H8[5]=f+0x9b05688c;H8[6]=g+0x1f83d9ab;H8[7]=h+0x5be0cd19;\n"
"}\n"
"static void sha1_compress(thread uint* M, thread uint* H5){\n"
"  uint w[80];\n"
"  for (uint i=0;i<16;i++) w[i]=M[i];\n"
"  for (uint i=16;i<80;i++){ uint x=w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i]=(x<<1)|(x>>31); }\n"
"  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476,e=0xc3d2e1f0;\n"
"  for (uint i=0;i<80;i++){ uint f,k;\n"
"    if (i<20){ f=(b&c)|((~b)&d); k=0x5a827999u; }\n"
"    else if (i<40){ f=b^c^d; k=0x6ed9eba1u; }\n"
"    else if (i<60){ f=(b&c)|(b&d)|(c&d); k=0x8f1bbcdcu; }\n"
"    else { f=b^c^d; k=0xca62c1d6u; }\n"
"    uint tmp=((a<<5)|(a>>27))+f+e+k+w[i]; e=d; d=c; c=(b<<30)|(b>>2); b=a; a=tmp; }\n"
"  H5[0]=a+0x67452301; H5[1]=b+0xefcdab89; H5[2]=c+0x98badcfe; H5[3]=d+0x10325476; H5[4]=e+0xc3d2e1f0;\n"
"}\n"
"kernel void md5k(device const uchar* data [[buffer(0)]],\n"
"                 device const uint* offsets [[buffer(1)]],\n"
"                 device uchar* out [[buffer(2)]],\n"
"                 constant uint& n [[buffer(3)]],\n"
"                 uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= n) return;\n"
"  uint start = offsets[gid]; uint len = offsets[gid+1]-start;\n"
"  uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0;\n"
"  for (uint i=0;i<len && i<55;i++) msg[i]=data[start+i];\n"
"  build_block(msg,len);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=msg[i*4]|(uint(msg[i*4+1])<<8)|(uint(msg[i*4+2])<<16)|(uint(msg[i*4+3])<<24);\n"
"  uint a,b,c,d; md5_compress(M,a,b,c,d);\n"
"  uint o=gid*16;\n"
"  out[o+0]=a&0xff;out[o+1]=(a>>8)&0xff;out[o+2]=(a>>16)&0xff;out[o+3]=(a>>24)&0xff;\n"
"  out[o+4]=b&0xff;out[o+5]=(b>>8)&0xff;out[o+6]=(b>>16)&0xff;out[o+7]=(b>>24)&0xff;\n"
"  out[o+8]=c&0xff;out[o+9]=(c>>8)&0xff;out[o+10]=(c>>16)&0xff;out[o+11]=(c>>24)&0xff;\n"
"  out[o+12]=d&0xff;out[o+13]=(d>>8)&0xff;out[o+14]=(d>>16)&0xff;out[o+15]=(d>>24)&0xff;\n"
"}\n"
"kernel void md5brute(device const uchar* charset [[buffer(0)]],\n"
"                     constant uint& csLen [[buffer(1)]],\n"
"                     constant uint& wordLen [[buffer(2)]],\n"
"                     constant ulong& startIdx [[buffer(3)]],\n"
"                     constant uint& count [[buffer(4)]],\n"
"                     device const uchar* target [[buffer(5)]],\n"
"                     device atomic_uint* found [[buffer(6)]],\n"
"                     device ulong* foundIdx [[buffer(7)]],\n"
"                     uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0;\n"
"  ulong t = idx;\n"
"  for (int p=(int)wordLen-1; p>=0; p--){ msg[p]=charset[t % (ulong)csLen]; t /= (ulong)csLen; }\n"
"  build_block(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=msg[i*4]|(uint(msg[i*4+1])<<8)|(uint(msg[i*4+2])<<16)|(uint(msg[i*4+3])<<24);\n"
"  uint a,b,c,d; md5_compress(M,a,b,c,d);\n"
"  uint t0=target[0]|(uint(target[1])<<8)|(uint(target[2])<<16)|(uint(target[3])<<24);\n"
"  uint t1=target[4]|(uint(target[5])<<8)|(uint(target[6])<<16)|(uint(target[7])<<24);\n"
"  uint t2=target[8]|(uint(target[9])<<8)|(uint(target[10])<<16)|(uint(target[11])<<24);\n"
"  uint t3=target[12]|(uint(target[13])<<8)|(uint(target[14])<<16)|(uint(target[15])<<24);\n"
"  if (a==t0 && b==t1 && c==t2 && d==t3){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void md5mask(device const uchar* sets [[buffer(0)]],\n"
"                    device const uint* setOff [[buffer(1)]],\n"
"                    constant uint& wordLen [[buffer(2)]],\n"
"                    constant ulong& startIdx [[buffer(3)]],\n"
"                    constant uint& count [[buffer(4)]],\n"
"                    device const uchar* target [[buffer(5)]],\n"
"                    device atomic_uint* found [[buffer(6)]],\n"
"                    device ulong* foundIdx [[buffer(7)]],\n"
"                    uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0;\n"
"  ulong t = idx;\n"
"  for (int p=(int)wordLen-1; p>=0; p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=msg[i*4]|(uint(msg[i*4+1])<<8)|(uint(msg[i*4+2])<<16)|(uint(msg[i*4+3])<<24);\n"
"  uint a,b,c,d; md5_compress(M,a,b,c,d);\n"
"  uint t0=target[0]|(uint(target[1])<<8)|(uint(target[2])<<16)|(uint(target[3])<<24);\n"
"  uint t1=target[4]|(uint(target[5])<<8)|(uint(target[6])<<16)|(uint(target[7])<<24);\n"
"  uint t2=target[8]|(uint(target[9])<<8)|(uint(target[10])<<16)|(uint(target[11])<<24);\n"
"  uint t3=target[12]|(uint(target[13])<<8)|(uint(target[14])<<16)|(uint(target[15])<<24);\n"
"  if (a==t0 && b==t1 && c==t2 && d==t3){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void md5maskmulti(device const uchar* sets [[buffer(0)]],\n"
"                         device const uint* setOff [[buffer(1)]],\n"
"                         constant uint& wordLen [[buffer(2)]],\n"
"                         constant ulong& startIdx [[buffer(3)]],\n"
"                         constant uint& count [[buffer(4)]],\n"
"                         device const uint* targets [[buffer(5)]],\n"
"                         constant uint& nTargets [[buffer(6)]],\n"
"                         device atomic_uint* foundFlag [[buffer(7)]],\n"
"                         device ulong* foundIdx [[buffer(8)]],\n"
"                         uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0;\n"
"  ulong t = idx;\n"
"  for (int p=(int)wordLen-1; p>=0; p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=msg[i*4]|(uint(msg[i*4+1])<<8)|(uint(msg[i*4+2])<<16)|(uint(msg[i*4+3])<<24);\n"
"  uint a,b,c,d; md5_compress(M,a,b,c,d);\n"
"  int lo=0, hi=(int)nTargets-1;\n"
"  while (lo<=hi){\n"
"    int mid=(lo+hi)>>1;\n"
"    uint ta=targets[mid*4], tb=targets[mid*4+1], tc=targets[mid*4+2], td=targets[mid*4+3];\n"
"    int cmp;\n"
"    if (a!=ta) cmp=(a<ta)?-1:1;\n"
"    else if (b!=tb) cmp=(b<tb)?-1:1;\n"
"    else if (c!=tc) cmp=(c<tc)?-1:1;\n"
"    else if (d!=td) cmp=(d<td)?-1:1;\n"
"    else cmp=0;\n"
"    if (cmp==0){ if (atomic_fetch_or_explicit(&foundFlag[mid],1u,memory_order_relaxed)==0u) foundIdx[mid]=idx; break; }\n"
"    else if (cmp<0) hi=mid-1; else lo=mid+1;\n"
"  }\n"
"}\n"
"kernel void ntlmmask(device const uchar* sets [[buffer(0)]],\n"
"                     device const uint* setOff [[buffer(1)]],\n"
"                     constant uint& wordLen [[buffer(2)]],\n"
"                     constant ulong& startIdx [[buffer(3)]],\n"
"                     constant uint& count [[buffer(4)]],\n"
"                     device const uchar* target [[buffer(5)]],\n"
"                     device atomic_uint* found [[buffer(6)]],\n"
"                     device ulong* foundIdx [[buffer(7)]],\n"
"                     uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0;\n"
"  ulong t = idx;\n"
"  for (int p=(int)wordLen-1; p>=0; p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p*2]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block(msg,wordLen*2);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=msg[i*4]|(uint(msg[i*4+1])<<8)|(uint(msg[i*4+2])<<16)|(uint(msg[i*4+3])<<24);\n"
"  uint a,b,c,d; md4_compress(M,a,b,c,d);\n"
"  uint t0=target[0]|(uint(target[1])<<8)|(uint(target[2])<<16)|(uint(target[3])<<24);\n"
"  uint t1=target[4]|(uint(target[5])<<8)|(uint(target[6])<<16)|(uint(target[7])<<24);\n"
"  uint t2=target[8]|(uint(target[9])<<8)|(uint(target[10])<<16)|(uint(target[11])<<24);\n"
"  uint t3=target[12]|(uint(target[13])<<8)|(uint(target[14])<<16)|(uint(target[15])<<24);\n"
"  if (a==t0 && b==t1 && c==t2 && d==t3){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void ntlmmaskmulti(device const uchar* sets [[buffer(0)]],\n"
"                          device const uint* setOff [[buffer(1)]],\n"
"                          constant uint& wordLen [[buffer(2)]],\n"
"                          constant ulong& startIdx [[buffer(3)]],\n"
"                          constant uint& count [[buffer(4)]],\n"
"                          device const uint* targets [[buffer(5)]],\n"
"                          constant uint& nTargets [[buffer(6)]],\n"
"                          device atomic_uint* foundFlag [[buffer(7)]],\n"
"                          device ulong* foundIdx [[buffer(8)]],\n"
"                          uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0;\n"
"  ulong t = idx;\n"
"  for (int p=(int)wordLen-1; p>=0; p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p*2]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block(msg,wordLen*2);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=msg[i*4]|(uint(msg[i*4+1])<<8)|(uint(msg[i*4+2])<<16)|(uint(msg[i*4+3])<<24);\n"
"  uint a,b,c,d; md4_compress(M,a,b,c,d);\n"
"  int lo=0, hi=(int)nTargets-1;\n"
"  while (lo<=hi){\n"
"    int mid=(lo+hi)>>1;\n"
"    uint ta=targets[mid*4], tb=targets[mid*4+1], tc=targets[mid*4+2], td=targets[mid*4+3];\n"
"    int cmp;\n"
"    if (a!=ta) cmp=(a<ta)?-1:1;\n"
"    else if (b!=tb) cmp=(b<tb)?-1:1;\n"
"    else if (c!=tc) cmp=(c<tc)?-1:1;\n"
"    else if (d!=td) cmp=(d<td)?-1:1;\n"
"    else cmp=0;\n"
"    if (cmp==0){ if (atomic_fetch_or_explicit(&foundFlag[mid],1u,memory_order_relaxed)==0u) foundIdx[mid]=idx; break; }\n"
"    else if (cmp<0) hi=mid-1; else lo=mid+1;\n"
"  }\n"
"}\n"
"kernel void sha256mask(device const uchar* sets [[buffer(0)]], device const uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]], device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid>=count) return; ulong idx=startIdx+(ulong)gid; uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0; ulong t=idx;\n"
"  for (int p=(int)wordLen-1;p>=0;p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block_be(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=(uint(msg[i*4])<<24)|(uint(msg[i*4+1])<<16)|(uint(msg[i*4+2])<<8)|uint(msg[i*4+3]);\n"
"  uint H8[8]; sha256_compress(M,H8);\n"
"  uint t0=(uint(target[0])<<24)|(uint(target[1])<<16)|(uint(target[2])<<8)|uint(target[3]);\n""  uint t1=(uint(target[4])<<24)|(uint(target[5])<<16)|(uint(target[6])<<8)|uint(target[7]);\n""  uint t2=(uint(target[8])<<24)|(uint(target[9])<<16)|(uint(target[10])<<8)|uint(target[11]);\n""  uint t3=(uint(target[12])<<24)|(uint(target[13])<<16)|(uint(target[14])<<8)|uint(target[15]);\n""  uint t4=(uint(target[16])<<24)|(uint(target[17])<<16)|(uint(target[18])<<8)|uint(target[19]);\n""  uint t5=(uint(target[20])<<24)|(uint(target[21])<<16)|(uint(target[22])<<8)|uint(target[23]);\n""  uint t6=(uint(target[24])<<24)|(uint(target[25])<<16)|(uint(target[26])<<8)|uint(target[27]);\n""  uint t7=(uint(target[28])<<24)|(uint(target[29])<<16)|(uint(target[30])<<8)|uint(target[31]);\n"
"  if (H8[0]==t0&&H8[1]==t1&&H8[2]==t2&&H8[3]==t3&&H8[4]==t4&&H8[5]==t5&&H8[6]==t6&&H8[7]==t7){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void sha256maskmulti(device const uchar* sets [[buffer(0)]], device const uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid>=count) return; ulong idx=startIdx+(ulong)gid; uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0; ulong t=idx;\n"
"  for (int p=(int)wordLen-1;p>=0;p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block_be(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=(uint(msg[i*4])<<24)|(uint(msg[i*4+1])<<16)|(uint(msg[i*4+2])<<8)|uint(msg[i*4+3]);\n"
"  uint H8[8]; sha256_compress(M,H8);\n"
"  int lo=0, hi=(int)nTargets-1;\n"
"  while (lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;\n"
"    for (int j=0;j<8;j++){ uint tv=targets[mid*8+j]; if (H8[j]!=tv){ cmp=(H8[j]<tv)?-1:1; break; } }\n"
"    if (cmp==0){ if (atomic_fetch_or_explicit(&foundFlag[mid],1u,memory_order_relaxed)==0u) foundIdx[mid]=idx; break; }\n"
"    else if (cmp<0) hi=mid-1; else lo=mid+1; }\n"
"}\n"
"kernel void sha1mask(device const uchar* sets [[buffer(0)]], device const uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]], device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid>=count) return; ulong idx=startIdx+(ulong)gid; uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0; ulong t=idx;\n"
"  for (int p=(int)wordLen-1;p>=0;p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block_be(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=(uint(msg[i*4])<<24)|(uint(msg[i*4+1])<<16)|(uint(msg[i*4+2])<<8)|uint(msg[i*4+3]);\n""  uint H5[5]; sha1_compress(M,H5);\n"
"  uint t0=(uint(target[0])<<24)|(uint(target[1])<<16)|(uint(target[2])<<8)|uint(target[3]);\n""  uint t1=(uint(target[4])<<24)|(uint(target[5])<<16)|(uint(target[6])<<8)|uint(target[7]);\n""  uint t2=(uint(target[8])<<24)|(uint(target[9])<<16)|(uint(target[10])<<8)|uint(target[11]);\n""  uint t3=(uint(target[12])<<24)|(uint(target[13])<<16)|(uint(target[14])<<8)|uint(target[15]);\n""  uint t4=(uint(target[16])<<24)|(uint(target[17])<<16)|(uint(target[18])<<8)|uint(target[19]);\n"
"  if (H5[0]==t0&&H5[1]==t1&&H5[2]==t2&&H5[3]==t3&&H5[4]==t4){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void sha1maskmulti(device const uchar* sets [[buffer(0)]], device const uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid>=count) return; ulong idx=startIdx+(ulong)gid; uchar msg[64]; for (uint i=0;i<64;i++) msg[i]=0; ulong t=idx;\n"
"  for (int p=(int)wordLen-1;p>=0;p--){ uint off=setOff[p]; uint sz=setOff[p+1]-off; msg[p]=sets[off+(uint)(t%(ulong)sz)]; t/=(ulong)sz; }\n"
"  build_block_be(msg,wordLen);\n"
"  uint M[16]; for (uint i=0;i<16;i++) M[i]=(uint(msg[i*4])<<24)|(uint(msg[i*4+1])<<16)|(uint(msg[i*4+2])<<8)|uint(msg[i*4+3]);\n""  uint H5[5]; sha1_compress(M,H5);\n"
"  int lo=0, hi=(int)nTargets-1;\n"
"  while (lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;\n"
"    for (int j=0;j<5;j++){ uint tv=targets[mid*5+j]; if (H5[j]!=tv){ cmp=(H5[j]<tv)?-1:1; break; } }\n"
"    if (cmp==0){ if (atomic_fetch_or_explicit(&foundFlag[mid],1u,memory_order_relaxed)==0u) foundIdx[mid]=idx; break; }\n"
"    else if (cmp<0) hi=mid-1; else lo=mid+1; }\n"
"}\n";

typedef struct {
    id<MTLDevice> dev;
    id<MTLCommandQueue> queue;
    id<MTLComputePipelineState> pipe;
    id<MTLComputePipelineState> pipeBrute;
    id<MTLComputePipelineState> pipeMask;
    id<MTLComputePipelineState> pipeMaskMulti;
    id<MTLComputePipelineState> pipeNtlmMask;
    id<MTLComputePipelineState> pipeNtlmMaskMulti;
    id<MTLComputePipelineState> pipeShaMask;
    id<MTLComputePipelineState> pipeShaMaskMulti;
    id<MTLComputePipelineState> pipeSha1Mask;
    id<MTLComputePipelineState> pipeSha1MaskMulti;
    char devName[128];
} hs_ctx;

static id<MTLComputePipelineState> mkpipe(id<MTLDevice> dev, id<MTLLibrary> lib, NSString *fn, char *errbuf, int errlen) {
    id<MTLFunction> f = [lib newFunctionWithName:fn];
    if (!f) { strncpy(errbuf, "kernel not found", errlen); return nil; }
    NSError *err = nil;
    id<MTLComputePipelineState> p = [dev newComputePipelineStateWithFunction:f error:&err];
    if (!p) { strncpy(errbuf, err ? [[err localizedDescription] UTF8String] : "pipeline failed", errlen); }
    return p;
}

void *hs_metal_init(char *errbuf, int errlen) {
    @autoreleasepool {
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        if (!dev) { strncpy(errbuf, "no Metal device", errlen); return NULL; }
        NSError *err = nil;
        id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:kMSL] options:nil error:&err];
        if (!lib) { strncpy(errbuf, err ? [[err localizedDescription] UTF8String] : "compile failed", errlen); return NULL; }
        id<MTLComputePipelineState> p1 = mkpipe(dev, lib, @"md5k", errbuf, errlen);
        if (!p1) return NULL;
        id<MTLComputePipelineState> p2 = mkpipe(dev, lib, @"md5brute", errbuf, errlen);
        if (!p2) return NULL;
        id<MTLComputePipelineState> p3 = mkpipe(dev, lib, @"md5mask", errbuf, errlen);
        if (!p3) return NULL;
        id<MTLComputePipelineState> p4 = mkpipe(dev, lib, @"md5maskmulti", errbuf, errlen);
        if (!p4) return NULL;
        id<MTLComputePipelineState> p5 = mkpipe(dev, lib, @"ntlmmask", errbuf, errlen);
        if (!p5) return NULL;
        id<MTLComputePipelineState> p6 = mkpipe(dev, lib, @"ntlmmaskmulti", errbuf, errlen);
        if (!p6) return NULL;
        id<MTLComputePipelineState> p7 = mkpipe(dev, lib, @"sha256mask", errbuf, errlen);
        if (!p7) return NULL;
        id<MTLComputePipelineState> p8 = mkpipe(dev, lib, @"sha256maskmulti", errbuf, errlen);
        if (!p8) return NULL;
        id<MTLComputePipelineState> p9 = mkpipe(dev, lib, @"sha1mask", errbuf, errlen);
        if (!p9) return NULL;
        id<MTLComputePipelineState> p10 = mkpipe(dev, lib, @"sha1maskmulti", errbuf, errlen);
        if (!p10) return NULL;
        hs_ctx *ctx = (hs_ctx *)calloc(1, sizeof(hs_ctx));
        ctx->dev = dev; ctx->queue = [dev newCommandQueue]; ctx->pipe = p1; ctx->pipeBrute = p2; ctx->pipeMask = p3; ctx->pipeMaskMulti = p4;
        ctx->pipeNtlmMask = p5; ctx->pipeNtlmMaskMulti = p6; ctx->pipeShaMask = p7; ctx->pipeShaMaskMulti = p8;
        ctx->pipeSha1Mask = p9; ctx->pipeSha1MaskMulti = p10;
        strncpy(ctx->devName, [[dev name] UTF8String], sizeof(ctx->devName)-1);
        return ctx;
    }
}

const char *hs_metal_name(void *c) { return ((hs_ctx *)c)->devName; }

int hs_metal_md5(void *c, const uint8_t *data, const uint32_t *offsets, int n, uint8_t *out) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        uint32_t total = offsets[n]; if (total == 0) total = 1;
        id<MTLBuffer> bData = [ctx->dev newBufferWithBytes:data length:total options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff  = [ctx->dev newBufferWithBytes:offsets length:(n+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOut  = [ctx->dev newBufferWithLength:n*16 options:MTLResourceStorageModeShared];
        uint32_t nn = (uint32_t)n;
        id<MTLBuffer> bN = [ctx->dev newBufferWithBytes:&nn length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipe];
        [enc setBuffer:bData offset:0 atIndex:0];
        [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bOut offset:0 atIndex:2];
        [enc setBuffer:bN offset:0 atIndex:3];
        NSUInteger tg = ctx->pipe.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(n,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        memcpy(out, [bOut contents], n*16);
        return 0;
    }
}

int hs_metal_md5_brute(void *c, const uint8_t *charset, uint32_t csLen, uint32_t wordLen,
                       uint64_t start, uint32_t count, const uint8_t *target16, uint64_t *outIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bCs = [ctx->dev newBufferWithBytes:charset length:csLen options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCsLen = [ctx->dev newBufferWithBytes:&csLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:target16 length:16 options:MTLResourceStorageModeShared];
        uint32_t zero = 0;
        id<MTLBuffer> bFound = [ctx->dev newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithLength:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeBrute];
        [enc setBuffer:bCs offset:0 atIndex:0];
        [enc setBuffer:bCsLen offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2];
        [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4];
        [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bFound offset:0 atIndex:6];
        [enc setBuffer:bFi offset:0 atIndex:7];
        NSUInteger tg = ctx->pipeBrute.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        uint32_t found = *(uint32_t *)[bFound contents];
        if (found) { *outIdx = *(uint64_t *)[bFi contents]; return 1; }
        return 0;
    }
}

int hs_metal_md5_mask(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                      uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target16, uint64_t *outIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:target16 length:16 options:MTLResourceStorageModeShared];
        uint32_t zero = 0;
        id<MTLBuffer> bFound = [ctx->dev newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithLength:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeMask];
        [enc setBuffer:bSets offset:0 atIndex:0];
        [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2];
        [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4];
        [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bFound offset:0 atIndex:6];
        [enc setBuffer:bFi offset:0 atIndex:7];
        NSUInteger tg = ctx->pipeMask.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        uint32_t found = *(uint32_t *)[bFound contents];
        if (found) { *outIdx = *(uint64_t *)[bFi contents]; return 1; }
        return 0;
    }
}

int hs_metal_md5_mask_multi(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                            uint32_t wordLen, uint64_t start, uint32_t count,
                            const uint32_t *targets, uint32_t nTargets,
                            uint32_t *foundFlag, uint64_t *foundIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:targets length:nTargets*4*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bNT = [ctx->dev newBufferWithBytes:&nTargets length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFlag = [ctx->dev newBufferWithBytes:foundFlag length:nTargets*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithBytes:foundIdx length:nTargets*sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeMaskMulti];
        [enc setBuffer:bSets offset:0 atIndex:0];
        [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2];
        [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4];
        [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bNT offset:0 atIndex:6];
        [enc setBuffer:bFlag offset:0 atIndex:7];
        [enc setBuffer:bFi offset:0 atIndex:8];
        NSUInteger tg = ctx->pipeMaskMulti.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        memcpy(foundFlag, [bFlag contents], nTargets*sizeof(uint32_t));
        memcpy(foundIdx, [bFi contents], nTargets*sizeof(uint64_t));
        return 0;
    }
}

int hs_metal_ntlm_mask(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                       uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target16, uint64_t *outIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:target16 length:16 options:MTLResourceStorageModeShared];
        uint32_t zero = 0;
        id<MTLBuffer> bFound = [ctx->dev newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithLength:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeNtlmMask];
        [enc setBuffer:bSets offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2]; [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4]; [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bFound offset:0 atIndex:6]; [enc setBuffer:bFi offset:0 atIndex:7];
        NSUInteger tg = ctx->pipeNtlmMask.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        uint32_t found = *(uint32_t *)[bFound contents];
        if (found) { *outIdx = *(uint64_t *)[bFi contents]; return 1; }
        return 0;
    }
}

int hs_metal_ntlm_mask_multi(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                             uint32_t wordLen, uint64_t start, uint32_t count,
                             const uint32_t *targets, uint32_t nTargets,
                             uint32_t *foundFlag, uint64_t *foundIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:targets length:nTargets*4*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bNT = [ctx->dev newBufferWithBytes:&nTargets length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFlag = [ctx->dev newBufferWithBytes:foundFlag length:nTargets*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithBytes:foundIdx length:nTargets*sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeNtlmMaskMulti];
        [enc setBuffer:bSets offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2]; [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4]; [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bNT offset:0 atIndex:6]; [enc setBuffer:bFlag offset:0 atIndex:7];
        [enc setBuffer:bFi offset:0 atIndex:8];
        NSUInteger tg = ctx->pipeNtlmMaskMulti.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        memcpy(foundFlag, [bFlag contents], nTargets*sizeof(uint32_t));
        memcpy(foundIdx, [bFi contents], nTargets*sizeof(uint64_t));
        return 0;
    }
}

int hs_metal_sha256_mask(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                         uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target32, uint64_t *outIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:target32 length:32 options:MTLResourceStorageModeShared];
        uint32_t zero = 0;
        id<MTLBuffer> bFound = [ctx->dev newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithLength:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeShaMask];
        [enc setBuffer:bSets offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2]; [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4]; [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bFound offset:0 atIndex:6]; [enc setBuffer:bFi offset:0 atIndex:7];
        NSUInteger tg = ctx->pipeShaMask.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        uint32_t found = *(uint32_t *)[bFound contents];
        if (found) { *outIdx = *(uint64_t *)[bFi contents]; return 1; }
        return 0;
    }
}

int hs_metal_sha256_mask_multi(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                               uint32_t wordLen, uint64_t start, uint32_t count,
                               const uint32_t *targets, uint32_t nTargets,
                               uint32_t *foundFlag, uint64_t *foundIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:targets length:nTargets*8*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bNT = [ctx->dev newBufferWithBytes:&nTargets length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFlag = [ctx->dev newBufferWithBytes:foundFlag length:nTargets*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithBytes:foundIdx length:nTargets*sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeShaMaskMulti];
        [enc setBuffer:bSets offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2]; [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4]; [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bNT offset:0 atIndex:6]; [enc setBuffer:bFlag offset:0 atIndex:7];
        [enc setBuffer:bFi offset:0 atIndex:8];
        NSUInteger tg = ctx->pipeShaMaskMulti.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        memcpy(foundFlag, [bFlag contents], nTargets*sizeof(uint32_t));
        memcpy(foundIdx, [bFi contents], nTargets*sizeof(uint64_t));
        return 0;
    }
}

int hs_metal_sha1_mask(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                       uint32_t wordLen, uint64_t start, uint32_t count, const uint8_t *target20, uint64_t *outIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:target20 length:20 options:MTLResourceStorageModeShared];
        uint32_t zero = 0;
        id<MTLBuffer> bFound = [ctx->dev newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithLength:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeSha1Mask];
        [enc setBuffer:bSets offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2]; [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4]; [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bFound offset:0 atIndex:6]; [enc setBuffer:bFi offset:0 atIndex:7];
        NSUInteger tg = ctx->pipeSha1Mask.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        uint32_t found = *(uint32_t *)[bFound contents];
        if (found) { *outIdx = *(uint64_t *)[bFi contents]; return 1; }
        return 0;
    }
}

int hs_metal_sha1_mask_multi(void *c, const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff,
                             uint32_t wordLen, uint64_t start, uint32_t count,
                             const uint32_t *targets, uint32_t nTargets,
                             uint32_t *foundFlag, uint64_t *foundIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bWl = [ctx->dev newBufferWithBytes:&wordLen length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bStart = [ctx->dev newBufferWithBytes:&start length:sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bCount = [ctx->dev newBufferWithBytes:&count length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt = [ctx->dev newBufferWithBytes:targets length:nTargets*5*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bNT = [ctx->dev newBufferWithBytes:&nTargets length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFlag = [ctx->dev newBufferWithBytes:foundFlag length:nTargets*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi = [ctx->dev newBufferWithBytes:foundIdx length:nTargets*sizeof(uint64_t) options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx->pipeSha1MaskMulti];
        [enc setBuffer:bSets offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bWl offset:0 atIndex:2]; [enc setBuffer:bStart offset:0 atIndex:3];
        [enc setBuffer:bCount offset:0 atIndex:4]; [enc setBuffer:bTgt offset:0 atIndex:5];
        [enc setBuffer:bNT offset:0 atIndex:6]; [enc setBuffer:bFlag offset:0 atIndex:7];
        [enc setBuffer:bFi offset:0 atIndex:8];
        NSUInteger tg = ctx->pipeSha1MaskMulti.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
        [enc endEncoding]; [cmd commit]; [cmd waitUntilCompleted];
        memcpy(foundFlag, [bFlag contents], nTargets*sizeof(uint32_t));
        memcpy(foundIdx, [bFi contents], nTargets*sizeof(uint64_t));
        return 0;
    }
}

int hs_metal_sweep_multi(void *c, int algo,
                         const uint8_t *sets, uint32_t setsLen, const uint32_t *setOff, uint32_t wordLen,
                         uint64_t start, uint64_t span, uint32_t chunk,
                         const uint32_t *targets, uint32_t nTargets, uint32_t targetWords,
                         uint32_t *foundFlag, uint64_t *foundIdx) {
    @autoreleasepool {
        hs_ctx *ctx = (hs_ctx *)c;
        id<MTLComputePipelineState> pipe;
        switch (algo) {
            case 1: pipe = ctx->pipeNtlmMaskMulti; break;
            case 2: pipe = ctx->pipeShaMaskMulti; break;
            case 3: pipe = ctx->pipeSha1MaskMulti; break;
            default: pipe = ctx->pipeMaskMulti; break;
        }
        // Buffers shared across every in-flight dispatch (allocated once).
        id<MTLBuffer> bSets = [ctx->dev newBufferWithBytes:sets length:(setsLen==0?1:setsLen) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bOff  = [ctx->dev newBufferWithBytes:setOff length:(wordLen+1)*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bTgt  = [ctx->dev newBufferWithBytes:targets length:nTargets*targetWords*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFlag = [ctx->dev newBufferWithBytes:foundFlag length:nTargets*sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bFi   = [ctx->dev newBufferWithBytes:foundIdx length:nTargets*sizeof(uint64_t) options:MTLResourceStorageModeShared];
        NSUInteger tg = pipe.maxTotalThreadsPerThreadgroup; if (tg > 256) tg = 256;

        const int DEPTH = 4;
        id<MTLCommandBuffer> ring[4] = {nil,nil,nil,nil};
        int head = 0, inflight = 0;
        uint64_t off = 0;
        while (off < span) {
            uint32_t cnt = (span - off > (uint64_t)chunk) ? chunk : (uint32_t)(span - off);
            uint64_t s = start + off;
            id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pipe];
            [enc setBuffer:bSets offset:0 atIndex:0];
            [enc setBuffer:bOff offset:0 atIndex:1];
            [enc setBytes:&wordLen length:sizeof(uint32_t) atIndex:2];
            [enc setBytes:&s length:sizeof(uint64_t) atIndex:3];
            [enc setBytes:&cnt length:sizeof(uint32_t) atIndex:4];
            [enc setBuffer:bTgt offset:0 atIndex:5];
            [enc setBytes:&nTargets length:sizeof(uint32_t) atIndex:6];
            [enc setBuffer:bFlag offset:0 atIndex:7];
            [enc setBuffer:bFi offset:0 atIndex:8];
            [enc dispatchThreads:MTLSizeMake(cnt,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
            [enc endEncoding];
            [cmd commit];
            if (inflight == DEPTH) {
                [ring[head] waitUntilCompleted];
                head = (head + 1) % DEPTH;
                inflight--;
            }
            ring[(head + inflight) % DEPTH] = cmd;
            inflight++;
            off += cnt;
        }
        while (inflight > 0) {
            [ring[head] waitUntilCompleted];
            head = (head + 1) % DEPTH;
            inflight--;
        }
        memcpy(foundFlag, [bFlag contents], nTargets*sizeof(uint32_t));
        memcpy(foundIdx, [bFi contents], nTargets*sizeof(uint64_t));
        return 0;
    }
}

void hs_metal_free(void *c) { if (c) free(c); }
