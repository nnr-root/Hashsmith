//go:build gpu && darwin && !opencl

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include "metal_md5.h"
#include <string.h>

// The Metal shader source below, compiled at init with newLibraryWithSource.
//
// Kernel shapes:
//   md5k      — hash a batch of CPU-provided candidates (transfer-bound)
//   *brute    — generate each candidate from its keyspace index IN-KERNEL, hash,
//               and compare to the target on-device, so no candidates cross the
//               bus and only a match flag returns (the fast path)
//   *mask     — same, with a per-position charset
//   *maskmulti — same, binary-searching a sorted target list on-device
//
// Two rules govern everything in here, and breaking either one costs an order
// of magnitude:
//
//  1. No thread-private array may ever be indexed by a runtime value. Such an
//     array cannot live in registers, so it is spilled to thread memory (device
//     backed on Apple GPUs) and every access becomes a memory round trip. That
//     is why the compression functions, the message-schedule windows and the
//     candidate-generation walk are all fully unrolled: every index, rotation
//     and round constant below is an immediate.
//
//  2. 64-bit integer division is emulated in software. The mixed-radix index
//     decode drops to 32-bit arithmetic the moment the remaining index fits,
//     which for realistic keyspaces is after at most a couple of digits.
//
// The index → candidate mapping is a contract shared with the CPU engine
// (--skip/--limit slicing relies on it being the same pure function on both
// sides); it is preserved exactly here. Only how it is computed changed.
static const char *kMSL =
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"#define ROTL(x,s) (((x)<<(s))|((x)>>(32u-(s))))\n"
"#define HSINL inline __attribute__((always_inline))\n"
"// Every hot helper is force-inlined and every array index below is a compile-\n"
"// time constant: a runtime index into a thread-private array cannot live in\n"
"// registers and spills to (device-backed) thread memory, which is what makes\n"
"// the difference between a few ALU ops and a memory round trip per step.\n"
"// MD5, fully unrolled: message word index, rotation and constant are all\n"
"// immediates, so M[] stays in registers and every rotate is rotate-by-imm.\n"
"#define MD5F(a,b,c,d,x,s,t) a = b + ROTL(a + (((b)&(c))|((~(b))&(d))) + (x) + (t), s);\n"
"#define MD5G(a,b,c,d,x,s,t) a = b + ROTL(a + (((d)&(b))|((~(d))&(c))) + (x) + (t), s);\n"
"#define MD5H(a,b,c,d,x,s,t) a = b + ROTL(a + ((b)^(c)^(d)) + (x) + (t), s);\n"
"#define MD5I(a,b,c,d,x,s,t) a = b + ROTL(a + ((c)^((b)|(~(d)))) + (x) + (t), s);\n"
"HSINL void md5_compress(thread uint* M, thread uint& a0, thread uint& b0, thread uint& c0, thread uint& d0){\n"
"  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;\n"
"  MD5F(a,b,c,d,M[0],7,0xd76aa478u)\n"
"  MD5F(d,a,b,c,M[1],12,0xe8c7b756u)\n"
"  MD5F(c,d,a,b,M[2],17,0x242070dbu)\n"
"  MD5F(b,c,d,a,M[3],22,0xc1bdceeeu)\n"
"  MD5F(a,b,c,d,M[4],7,0xf57c0fafu)\n"
"  MD5F(d,a,b,c,M[5],12,0x4787c62au)\n"
"  MD5F(c,d,a,b,M[6],17,0xa8304613u)\n"
"  MD5F(b,c,d,a,M[7],22,0xfd469501u)\n"
"  MD5F(a,b,c,d,M[8],7,0x698098d8u)\n"
"  MD5F(d,a,b,c,M[9],12,0x8b44f7afu)\n"
"  MD5F(c,d,a,b,M[10],17,0xffff5bb1u)\n"
"  MD5F(b,c,d,a,M[11],22,0x895cd7beu)\n"
"  MD5F(a,b,c,d,M[12],7,0x6b901122u)\n"
"  MD5F(d,a,b,c,M[13],12,0xfd987193u)\n"
"  MD5F(c,d,a,b,M[14],17,0xa679438eu)\n"
"  MD5F(b,c,d,a,M[15],22,0x49b40821u)\n"
"  MD5G(a,b,c,d,M[1],5,0xf61e2562u)\n"
"  MD5G(d,a,b,c,M[6],9,0xc040b340u)\n"
"  MD5G(c,d,a,b,M[11],14,0x265e5a51u)\n"
"  MD5G(b,c,d,a,M[0],20,0xe9b6c7aau)\n"
"  MD5G(a,b,c,d,M[5],5,0xd62f105du)\n"
"  MD5G(d,a,b,c,M[10],9,0x02441453u)\n"
"  MD5G(c,d,a,b,M[15],14,0xd8a1e681u)\n"
"  MD5G(b,c,d,a,M[4],20,0xe7d3fbc8u)\n"
"  MD5G(a,b,c,d,M[9],5,0x21e1cde6u)\n"
"  MD5G(d,a,b,c,M[14],9,0xc33707d6u)\n"
"  MD5G(c,d,a,b,M[3],14,0xf4d50d87u)\n"
"  MD5G(b,c,d,a,M[8],20,0x455a14edu)\n"
"  MD5G(a,b,c,d,M[13],5,0xa9e3e905u)\n"
"  MD5G(d,a,b,c,M[2],9,0xfcefa3f8u)\n"
"  MD5G(c,d,a,b,M[7],14,0x676f02d9u)\n"
"  MD5G(b,c,d,a,M[12],20,0x8d2a4c8au)\n"
"  MD5H(a,b,c,d,M[5],4,0xfffa3942u)\n"
"  MD5H(d,a,b,c,M[8],11,0x8771f681u)\n"
"  MD5H(c,d,a,b,M[11],16,0x6d9d6122u)\n"
"  MD5H(b,c,d,a,M[14],23,0xfde5380cu)\n"
"  MD5H(a,b,c,d,M[1],4,0xa4beea44u)\n"
"  MD5H(d,a,b,c,M[4],11,0x4bdecfa9u)\n"
"  MD5H(c,d,a,b,M[7],16,0xf6bb4b60u)\n"
"  MD5H(b,c,d,a,M[10],23,0xbebfbc70u)\n"
"  MD5H(a,b,c,d,M[13],4,0x289b7ec6u)\n"
"  MD5H(d,a,b,c,M[0],11,0xeaa127fau)\n"
"  MD5H(c,d,a,b,M[3],16,0xd4ef3085u)\n"
"  MD5H(b,c,d,a,M[6],23,0x04881d05u)\n"
"  MD5H(a,b,c,d,M[9],4,0xd9d4d039u)\n"
"  MD5H(d,a,b,c,M[12],11,0xe6db99e5u)\n"
"  MD5H(c,d,a,b,M[15],16,0x1fa27cf8u)\n"
"  MD5H(b,c,d,a,M[2],23,0xc4ac5665u)\n"
"  MD5I(a,b,c,d,M[0],6,0xf4292244u)\n"
"  MD5I(d,a,b,c,M[7],10,0x432aff97u)\n"
"  MD5I(c,d,a,b,M[14],15,0xab9423a7u)\n"
"  MD5I(b,c,d,a,M[5],21,0xfc93a039u)\n"
"  MD5I(a,b,c,d,M[12],6,0x655b59c3u)\n"
"  MD5I(d,a,b,c,M[3],10,0x8f0ccc92u)\n"
"  MD5I(c,d,a,b,M[10],15,0xffeff47du)\n"
"  MD5I(b,c,d,a,M[1],21,0x85845dd1u)\n"
"  MD5I(a,b,c,d,M[8],6,0x6fa87e4fu)\n"
"  MD5I(d,a,b,c,M[15],10,0xfe2ce6e0u)\n"
"  MD5I(c,d,a,b,M[6],15,0xa3014314u)\n"
"  MD5I(b,c,d,a,M[13],21,0x4e0811a1u)\n"
"  MD5I(a,b,c,d,M[4],6,0xf7537e82u)\n"
"  MD5I(d,a,b,c,M[11],10,0xbd3af235u)\n"
"  MD5I(c,d,a,b,M[2],15,0x2ad7d2bbu)\n"
"  MD5I(b,c,d,a,M[9],21,0xeb86d391u)\n"
"  a0=a+0x67452301; b0=b+0xefcdab89; c0=c+0x98badcfe; d0=d+0x10325476;\n"
"}\n"
"#undef MD5F\n"
"#undef MD5G\n"
"#undef MD5H\n"
"#undef MD5I\n"
"HSINL void md4_compress(thread uint* M, thread uint& a0, thread uint& b0, thread uint& c0, thread uint& d0){\n"
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
"#undef FF\n"
"#undef GG\n"
"#undef HH\n"
"  a0=a+0x67452301; b0=b+0xefcdab89; c0=c+0x98badcfe; d0=d+0x10325476;\n"
"}\n"
"// SHA-1, fully unrolled over a 16-word rolling schedule window (W[] indices\n"
"// are constant, so no 80-word spilled array).\n"
"#define S1W(i) (W[(i)&15] = ROTL(W[((i)+13)&15]^W[((i)+8)&15]^W[((i)+2)&15]^W[(i)&15],1))\n"
"#define S1R(a,b,c,d,e,f,k,w) e += ROTL(a,5) + (f) + (k) + (w); b = ROTL(b,30);\n"
"HSINL void sha1_compress(thread uint* M, thread uint* H5){\n"
"  uint W[16];\n"
"  W[0]=M[0]; W[1]=M[1]; W[2]=M[2]; W[3]=M[3]; W[4]=M[4]; W[5]=M[5]; W[6]=M[6]; W[7]=M[7]; W[8]=M[8]; W[9]=M[9]; W[10]=M[10]; W[11]=M[11]; W[12]=M[12]; W[13]=M[13]; W[14]=M[14]; W[15]=M[15];\n"
"  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476,e=0xc3d2e1f0;\n"
"  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[0])\n"
"  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,W[1])\n"
"  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,W[2])\n"
"  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,W[3])\n"
"  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,W[4])\n"
"  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[5])\n"
"  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,W[6])\n"
"  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,W[7])\n"
"  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,W[8])\n"
"  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,W[9])\n"
"  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[10])\n"
"  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,W[11])\n"
"  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,W[12])\n"
"  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,W[13])\n"
"  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,W[14])\n"
"  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[15])\n"
"  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,S1W(16))\n"
"  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,S1W(17))\n"
"  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,S1W(18))\n"
"  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,S1W(19))\n"
"  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(20))\n"
"  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(21))\n"
"  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(22))\n"
"  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(23))\n"
"  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(24))\n"
"  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(25))\n"
"  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(26))\n"
"  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(27))\n"
"  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(28))\n"
"  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(29))\n"
"  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(30))\n"
"  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(31))\n"
"  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(32))\n"
"  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(33))\n"
"  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(34))\n"
"  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(35))\n"
"  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(36))\n"
"  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(37))\n"
"  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(38))\n"
"  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(39))\n"
"  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(40))\n"
"  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(41))\n"
"  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(42))\n"
"  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(43))\n"
"  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(44))\n"
"  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(45))\n"
"  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(46))\n"
"  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(47))\n"
"  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(48))\n"
"  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(49))\n"
"  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(50))\n"
"  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(51))\n"
"  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(52))\n"
"  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(53))\n"
"  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(54))\n"
"  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(55))\n"
"  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(56))\n"
"  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(57))\n"
"  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(58))\n"
"  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(59))\n"
"  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(60))\n"
"  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(61))\n"
"  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(62))\n"
"  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(63))\n"
"  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(64))\n"
"  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(65))\n"
"  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(66))\n"
"  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(67))\n"
"  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(68))\n"
"  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(69))\n"
"  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(70))\n"
"  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(71))\n"
"  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(72))\n"
"  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(73))\n"
"  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(74))\n"
"  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(75))\n"
"  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(76))\n"
"  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(77))\n"
"  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(78))\n"
"  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(79))\n"
"  H5[0]=a+0x67452301; H5[1]=b+0xefcdab89; H5[2]=c+0x98badcfe; H5[3]=d+0x10325476; H5[4]=e+0xc3d2e1f0;\n"
"}\n"
"#undef S1W\n"
"#undef S1R\n"
"// SHA-256, fully unrolled over a 16-word rolling schedule window.\n"
"#define ROTR(x,s) (((x)>>(s))|((x)<<(32u-(s))))\n"
"#define S2S0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))\n"
"#define S2S1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))\n"
"#define S2W(i) (W[(i)&15] += S2S1(W[((i)+14)&15]) + W[((i)+9)&15] + S2S0(W[((i)+1)&15]))\n"
"#define S2R(a,b,c,d,e,f,g,h,k,w) { uint _t1 = h + (ROTR(e,6)^ROTR(e,11)^ROTR(e,25)) + (((e)&(f))^((~(e))&(g))) + (k) + (w); \\\n"
"  uint _t2 = (ROTR(a,2)^ROTR(a,13)^ROTR(a,22)) + (((a)&(b))^((a)&(c))^((b)&(c))); d += _t1; h = _t1 + _t2; }\n"
"HSINL void sha256_compress(thread uint* M, thread uint* H8){\n"
"  uint W[16];\n"
"  W[0]=M[0]; W[1]=M[1]; W[2]=M[2]; W[3]=M[3]; W[4]=M[4]; W[5]=M[5]; W[6]=M[6]; W[7]=M[7]; W[8]=M[8]; W[9]=M[9]; W[10]=M[10]; W[11]=M[11]; W[12]=M[12]; W[13]=M[13]; W[14]=M[14]; W[15]=M[15];\n"
"  uint a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;\n"
"  S2R(a,b,c,d,e,f,g,h,0x428a2f98u,W[0])\n"
"  S2R(h,a,b,c,d,e,f,g,0x71374491u,W[1])\n"
"  S2R(g,h,a,b,c,d,e,f,0xb5c0fbcfu,W[2])\n"
"  S2R(f,g,h,a,b,c,d,e,0xe9b5dba5u,W[3])\n"
"  S2R(e,f,g,h,a,b,c,d,0x3956c25bu,W[4])\n"
"  S2R(d,e,f,g,h,a,b,c,0x59f111f1u,W[5])\n"
"  S2R(c,d,e,f,g,h,a,b,0x923f82a4u,W[6])\n"
"  S2R(b,c,d,e,f,g,h,a,0xab1c5ed5u,W[7])\n"
"  S2R(a,b,c,d,e,f,g,h,0xd807aa98u,W[8])\n"
"  S2R(h,a,b,c,d,e,f,g,0x12835b01u,W[9])\n"
"  S2R(g,h,a,b,c,d,e,f,0x243185beu,W[10])\n"
"  S2R(f,g,h,a,b,c,d,e,0x550c7dc3u,W[11])\n"
"  S2R(e,f,g,h,a,b,c,d,0x72be5d74u,W[12])\n"
"  S2R(d,e,f,g,h,a,b,c,0x80deb1feu,W[13])\n"
"  S2R(c,d,e,f,g,h,a,b,0x9bdc06a7u,W[14])\n"
"  S2R(b,c,d,e,f,g,h,a,0xc19bf174u,W[15])\n"
"  S2R(a,b,c,d,e,f,g,h,0xe49b69c1u,S2W(16))\n"
"  S2R(h,a,b,c,d,e,f,g,0xefbe4786u,S2W(17))\n"
"  S2R(g,h,a,b,c,d,e,f,0x0fc19dc6u,S2W(18))\n"
"  S2R(f,g,h,a,b,c,d,e,0x240ca1ccu,S2W(19))\n"
"  S2R(e,f,g,h,a,b,c,d,0x2de92c6fu,S2W(20))\n"
"  S2R(d,e,f,g,h,a,b,c,0x4a7484aau,S2W(21))\n"
"  S2R(c,d,e,f,g,h,a,b,0x5cb0a9dcu,S2W(22))\n"
"  S2R(b,c,d,e,f,g,h,a,0x76f988dau,S2W(23))\n"
"  S2R(a,b,c,d,e,f,g,h,0x983e5152u,S2W(24))\n"
"  S2R(h,a,b,c,d,e,f,g,0xa831c66du,S2W(25))\n"
"  S2R(g,h,a,b,c,d,e,f,0xb00327c8u,S2W(26))\n"
"  S2R(f,g,h,a,b,c,d,e,0xbf597fc7u,S2W(27))\n"
"  S2R(e,f,g,h,a,b,c,d,0xc6e00bf3u,S2W(28))\n"
"  S2R(d,e,f,g,h,a,b,c,0xd5a79147u,S2W(29))\n"
"  S2R(c,d,e,f,g,h,a,b,0x06ca6351u,S2W(30))\n"
"  S2R(b,c,d,e,f,g,h,a,0x14292967u,S2W(31))\n"
"  S2R(a,b,c,d,e,f,g,h,0x27b70a85u,S2W(32))\n"
"  S2R(h,a,b,c,d,e,f,g,0x2e1b2138u,S2W(33))\n"
"  S2R(g,h,a,b,c,d,e,f,0x4d2c6dfcu,S2W(34))\n"
"  S2R(f,g,h,a,b,c,d,e,0x53380d13u,S2W(35))\n"
"  S2R(e,f,g,h,a,b,c,d,0x650a7354u,S2W(36))\n"
"  S2R(d,e,f,g,h,a,b,c,0x766a0abbu,S2W(37))\n"
"  S2R(c,d,e,f,g,h,a,b,0x81c2c92eu,S2W(38))\n"
"  S2R(b,c,d,e,f,g,h,a,0x92722c85u,S2W(39))\n"
"  S2R(a,b,c,d,e,f,g,h,0xa2bfe8a1u,S2W(40))\n"
"  S2R(h,a,b,c,d,e,f,g,0xa81a664bu,S2W(41))\n"
"  S2R(g,h,a,b,c,d,e,f,0xc24b8b70u,S2W(42))\n"
"  S2R(f,g,h,a,b,c,d,e,0xc76c51a3u,S2W(43))\n"
"  S2R(e,f,g,h,a,b,c,d,0xd192e819u,S2W(44))\n"
"  S2R(d,e,f,g,h,a,b,c,0xd6990624u,S2W(45))\n"
"  S2R(c,d,e,f,g,h,a,b,0xf40e3585u,S2W(46))\n"
"  S2R(b,c,d,e,f,g,h,a,0x106aa070u,S2W(47))\n"
"  S2R(a,b,c,d,e,f,g,h,0x19a4c116u,S2W(48))\n"
"  S2R(h,a,b,c,d,e,f,g,0x1e376c08u,S2W(49))\n"
"  S2R(g,h,a,b,c,d,e,f,0x2748774cu,S2W(50))\n"
"  S2R(f,g,h,a,b,c,d,e,0x34b0bcb5u,S2W(51))\n"
"  S2R(e,f,g,h,a,b,c,d,0x391c0cb3u,S2W(52))\n"
"  S2R(d,e,f,g,h,a,b,c,0x4ed8aa4au,S2W(53))\n"
"  S2R(c,d,e,f,g,h,a,b,0x5b9cca4fu,S2W(54))\n"
"  S2R(b,c,d,e,f,g,h,a,0x682e6ff3u,S2W(55))\n"
"  S2R(a,b,c,d,e,f,g,h,0x748f82eeu,S2W(56))\n"
"  S2R(h,a,b,c,d,e,f,g,0x78a5636fu,S2W(57))\n"
"  S2R(g,h,a,b,c,d,e,f,0x84c87814u,S2W(58))\n"
"  S2R(f,g,h,a,b,c,d,e,0x8cc70208u,S2W(59))\n"
"  S2R(e,f,g,h,a,b,c,d,0x90befffau,S2W(60))\n"
"  S2R(d,e,f,g,h,a,b,c,0xa4506cebu,S2W(61))\n"
"  S2R(c,d,e,f,g,h,a,b,0xbef9a3f7u,S2W(62))\n"
"  S2R(b,c,d,e,f,g,h,a,0xc67178f2u,S2W(63))\n"
"  H8[0]=a+0x6a09e667u; H8[1]=b+0xbb67ae85u; H8[2]=c+0x3c6ef372u; H8[3]=d+0xa54ff53au; H8[4]=e+0x510e527fu; H8[5]=f+0x9b05688cu; H8[6]=g+0x1f83d9abu; H8[7]=h+0x5be0cd19u;\n"
"}\n"
"#undef S2W\n"
"#undef S2R\n"
"// ---- in-kernel candidate generation ------------------------------------\n"
"// The candidate for a global keyspace index is mixed-radix: position\n"
"// wordLen-1 is the fastest-moving digit. That mapping is a contract shared\n"
"// with the CPU (--skip/--limit slicing depends on it) and is preserved\n"
"// exactly here; only how it is computed changed.\n"
"//   * digits are peeled with 64-bit division only while the remaining index\n"
"//     still needs 64 bits, then in 32-bit (GPUs emulate 64-bit divide);\n"
"//   * the position loop is unrolled to the host's maximum candidate length so\n"
"//     every m[] word index is an immediate and the block stays in registers;\n"
"//   * the 0x80 pad byte is folded into the same unrolled walk.\n"
"// wordLen is uniform across the grid, so the per-position guards are uniform\n"
"// branches, not divergence.\n"
"#define MIX_BEGIN(ix) ulong _t=(ix); uint _t32=(uint)(ix); bool _big=((ix)>(ulong)0xffffffffu);\n"
"#define MIX_DIGIT(dst,szv) { uint _s=(szv); \\\n"
"  if (_big){ dst=(uint)(_t%(ulong)_s); _t/=(ulong)_s; if (_t<=(ulong)0xffffffffu){ _big=false; _t32=(uint)_t; } } \\\n"
"  else { dst=_t32%_s; _t32/=_s; } }\n"
"#define MZERO m[0]=0u; m[1]=0u; m[2]=0u; m[3]=0u; m[4]=0u; m[5]=0u; m[6]=0u; m[7]=0u; m[8]=0u; m[9]=0u; m[10]=0u; m[11]=0u; m[12]=0u; m[13]=0u; m[14]=0u; m[15]=0u;\n"
"#define POS_LE(p) if ((uint)(p)<wordLen){ uint _o=setOff[p]; uint _d; MIX_DIGIT(_d,setOff[(p)+1]-_o) \\\n"
"    m[(p)>>2] |= (uint)sets[_o+_d] << (((p)&3)*8); } \\\n"
"  else if ((uint)(p)==wordLen){ m[(p)>>2] |= 0x80u << (((p)&3)*8); }\n"
"HSINL void build_mask_le(constant uchar* sets, constant uint* setOff, uint wordLen, ulong idx, thread uint* m){\n"
"  MZERO\n"
"  MIX_BEGIN(idx)\n"
"  POS_LE(55) POS_LE(54) POS_LE(53) POS_LE(52) POS_LE(51) POS_LE(50) POS_LE(49) POS_LE(48)\n"
"  POS_LE(47) POS_LE(46) POS_LE(45) POS_LE(44) POS_LE(43) POS_LE(42) POS_LE(41) POS_LE(40)\n"
"  POS_LE(39) POS_LE(38) POS_LE(37) POS_LE(36) POS_LE(35) POS_LE(34) POS_LE(33) POS_LE(32)\n"
"  POS_LE(31) POS_LE(30) POS_LE(29) POS_LE(28) POS_LE(27) POS_LE(26) POS_LE(25) POS_LE(24)\n"
"  POS_LE(23) POS_LE(22) POS_LE(21) POS_LE(20) POS_LE(19) POS_LE(18) POS_LE(17) POS_LE(16)\n"
"  POS_LE(15) POS_LE(14) POS_LE(13) POS_LE(12) POS_LE(11) POS_LE(10) POS_LE(9) POS_LE(8)\n"
"  POS_LE(7) POS_LE(6) POS_LE(5) POS_LE(4) POS_LE(3) POS_LE(2) POS_LE(1) POS_LE(0)\n"
"  m[14] = wordLen*8u;\n"
"}\n"
"#undef POS_LE\n"
"#define POS_BE(p) if ((uint)(p)<wordLen){ uint _o=setOff[p]; uint _d; MIX_DIGIT(_d,setOff[(p)+1]-_o) \\\n"
"    m[(p)>>2] |= (uint)sets[_o+_d] << (24-(((p)&3)*8)); } \\\n"
"  else if ((uint)(p)==wordLen){ m[(p)>>2] |= 0x80u << (24-(((p)&3)*8)); }\n"
"HSINL void build_mask_be(constant uchar* sets, constant uint* setOff, uint wordLen, ulong idx, thread uint* m){\n"
"  MZERO\n"
"  MIX_BEGIN(idx)\n"
"  POS_BE(55) POS_BE(54) POS_BE(53) POS_BE(52) POS_BE(51) POS_BE(50) POS_BE(49) POS_BE(48)\n"
"  POS_BE(47) POS_BE(46) POS_BE(45) POS_BE(44) POS_BE(43) POS_BE(42) POS_BE(41) POS_BE(40)\n"
"  POS_BE(39) POS_BE(38) POS_BE(37) POS_BE(36) POS_BE(35) POS_BE(34) POS_BE(33) POS_BE(32)\n"
"  POS_BE(31) POS_BE(30) POS_BE(29) POS_BE(28) POS_BE(27) POS_BE(26) POS_BE(25) POS_BE(24)\n"
"  POS_BE(23) POS_BE(22) POS_BE(21) POS_BE(20) POS_BE(19) POS_BE(18) POS_BE(17) POS_BE(16)\n"
"  POS_BE(15) POS_BE(14) POS_BE(13) POS_BE(12) POS_BE(11) POS_BE(10) POS_BE(9) POS_BE(8)\n"
"  POS_BE(7) POS_BE(6) POS_BE(5) POS_BE(4) POS_BE(3) POS_BE(2) POS_BE(1) POS_BE(0)\n"
"  m[15] = wordLen*8u;\n"
"}\n"
"#undef POS_BE\n"
"// NTLM: character p lands at byte 2p (UTF-16LE); wordLen is capped at 27 by\n"
"// the host so the padded message still fits one block.\n"
"#define POS_NT(p) if ((uint)(p)<wordLen){ uint _o=setOff[p]; uint _d; MIX_DIGIT(_d,setOff[(p)+1]-_o) \\\n"
"    m[(2*(p))>>2] |= (uint)sets[_o+_d] << ((((2*(p))&3))*8); } \\\n"
"  else if ((uint)(p)==wordLen){ m[(2*(p))>>2] |= 0x80u << ((((2*(p))&3))*8); }\n"
"HSINL void build_mask_ntlm(constant uchar* sets, constant uint* setOff, uint wordLen, ulong idx, thread uint* m){\n"
"  MZERO\n"
"  MIX_BEGIN(idx)\n"
"  POS_NT(27) POS_NT(26) POS_NT(25) POS_NT(24) POS_NT(23) POS_NT(22) POS_NT(21) POS_NT(20)\n"
"  POS_NT(19) POS_NT(18) POS_NT(17) POS_NT(16) POS_NT(15) POS_NT(14) POS_NT(13) POS_NT(12)\n"
"  POS_NT(11) POS_NT(10) POS_NT(9) POS_NT(8) POS_NT(7) POS_NT(6) POS_NT(5) POS_NT(4)\n"
"  POS_NT(3) POS_NT(2) POS_NT(1) POS_NT(0)\n"
"  m[14] = wordLen*16u;\n"
"}\n"
"#undef POS_NT\n"
"#define POS_BR(p) if ((uint)(p)<wordLen){ uint _d; MIX_DIGIT(_d,csLen) \\\n"
"    m[(p)>>2] |= (uint)charset[_d] << (((p)&3)*8); } \\\n"
"  else if ((uint)(p)==wordLen){ m[(p)>>2] |= 0x80u << (((p)&3)*8); }\n"
"HSINL void build_brute_le(constant uchar* charset, uint csLen, uint wordLen, ulong idx, thread uint* m){\n"
"  MZERO\n"
"  MIX_BEGIN(idx)\n"
"  POS_BR(55) POS_BR(54) POS_BR(53) POS_BR(52) POS_BR(51) POS_BR(50) POS_BR(49) POS_BR(48)\n"
"  POS_BR(47) POS_BR(46) POS_BR(45) POS_BR(44) POS_BR(43) POS_BR(42) POS_BR(41) POS_BR(40)\n"
"  POS_BR(39) POS_BR(38) POS_BR(37) POS_BR(36) POS_BR(35) POS_BR(34) POS_BR(33) POS_BR(32)\n"
"  POS_BR(31) POS_BR(30) POS_BR(29) POS_BR(28) POS_BR(27) POS_BR(26) POS_BR(25) POS_BR(24)\n"
"  POS_BR(23) POS_BR(22) POS_BR(21) POS_BR(20) POS_BR(19) POS_BR(18) POS_BR(17) POS_BR(16)\n"
"  POS_BR(15) POS_BR(14) POS_BR(13) POS_BR(12) POS_BR(11) POS_BR(10) POS_BR(9) POS_BR(8)\n"
"  POS_BR(7) POS_BR(6) POS_BR(5) POS_BR(4) POS_BR(3) POS_BR(2) POS_BR(1) POS_BR(0)\n"
"  m[14] = wordLen*8u;\n"
"}\n"
"#undef POS_BR\n"
"// Batch kernel: pack the candidate straight from device memory into the 16\n"
"// message words. Word index and byte shift are immediates; only the length\n"
"// guards are per-thread.\n"
"#define MKW(k) { uint _w=0u; \\\n"
"  if (4*(k)+0<len) _w |= (uint)data[start+4*(k)+0]; \\\n"
"  if (4*(k)+1<len) _w |= (uint)data[start+4*(k)+1]<<8; \\\n"
"  if (4*(k)+2<len) _w |= (uint)data[start+4*(k)+2]<<16; \\\n"
"  if (4*(k)+3<len) _w |= (uint)data[start+4*(k)+3]<<24; \\\n"
"  if ((len>>2)==(k)) _w |= 0x80u << ((len&3)*8); \\\n"
"  m[k]=_w; }\n"
"kernel void md5k(device const uchar* data [[buffer(0)]],\n"
"                 device const uint* offsets [[buffer(1)]],\n"
"                 device uchar* out [[buffer(2)]],\n"
"                 constant uint& n [[buffer(3)]],\n"
"                 uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= n) return;\n"
"  uint start = offsets[gid]; uint len = offsets[gid+1]-start;\n"
"  if (len > 55u) len = 55u;   // one-block kernel; longer inputs go to the CPU\n"
"  uint m[16];\n"
"  MKW(0) MKW(1) MKW(2) MKW(3) MKW(4) MKW(5) MKW(6)\n"
"  MKW(7) MKW(8) MKW(9) MKW(10) MKW(11) MKW(12) MKW(13)\n"
"  m[14]=len*8u; m[15]=0u;\n"
"  uint a,b,c,d; md5_compress(m,a,b,c,d);\n"
"  uint o=gid*16;\n"
"  out[o+0]=a&0xff;out[o+1]=(a>>8)&0xff;out[o+2]=(a>>16)&0xff;out[o+3]=(a>>24)&0xff;\n"
"  out[o+4]=b&0xff;out[o+5]=(b>>8)&0xff;out[o+6]=(b>>16)&0xff;out[o+7]=(b>>24)&0xff;\n"
"  out[o+8]=c&0xff;out[o+9]=(c>>8)&0xff;out[o+10]=(c>>16)&0xff;out[o+11]=(c>>24)&0xff;\n"
"  out[o+12]=d&0xff;out[o+13]=(d>>8)&0xff;out[o+14]=(d>>16)&0xff;out[o+15]=(d>>24)&0xff;\n"
"}\n"
"#undef MKW\n"
"#define TGT4_LE uint t0=target[0]|(uint(target[1])<<8)|(uint(target[2])<<16)|(uint(target[3])<<24); \\\n"
"  uint t1=target[4]|(uint(target[5])<<8)|(uint(target[6])<<16)|(uint(target[7])<<24); \\\n"
"  uint t2=target[8]|(uint(target[9])<<8)|(uint(target[10])<<16)|(uint(target[11])<<24); \\\n"
"  uint t3=target[12]|(uint(target[13])<<8)|(uint(target[14])<<16)|(uint(target[15])<<24);\n"
"#define BE32(i) ((uint(target[i])<<24)|(uint(target[(i)+1])<<16)|(uint(target[(i)+2])<<8)|uint(target[(i)+3]))\n"
"kernel void md5brute(constant uchar* charset [[buffer(0)]], constant uint& csLen [[buffer(1)]],\n"
"                     constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]],\n"
"                     constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]],\n"
"                     device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]],\n"
"                     uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_brute_le(charset,csLen,wordLen,idx,m);\n"
"  uint a,b,c,d; md5_compress(m,a,b,c,d);\n"
"  TGT4_LE\n"
"  if (a==t0 && b==t1 && c==t2 && d==t3){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void md5mask(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]], device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_le(sets,setOff,wordLen,idx,m);\n"
"  uint a,b,c,d; md5_compress(m,a,b,c,d);\n"
"  TGT4_LE\n"
"  if (a==t0 && b==t1 && c==t2 && d==t3){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void md5maskmulti(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_le(sets,setOff,wordLen,idx,m);\n"
"  uint a,b,c,d; md5_compress(m,a,b,c,d);\n"
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
"kernel void ntlmmask(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]], device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_ntlm(sets,setOff,wordLen,idx,m);\n"
"  uint a,b,c,d; md4_compress(m,a,b,c,d);\n"
"  TGT4_LE\n"
"  if (a==t0 && b==t1 && c==t2 && d==t3){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void ntlmmaskmulti(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_ntlm(sets,setOff,wordLen,idx,m);\n"
"  uint a,b,c,d; md4_compress(m,a,b,c,d);\n"
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
"kernel void md4maskmulti(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_le(sets,setOff,wordLen,idx,m);\n"
"  uint a,b,c,d; md4_compress(m,a,b,c,d);\n"
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
"kernel void sha256mask(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]], device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);\n"
"  uint H8[8]; sha256_compress(m,H8);\n"
"  uint t0=BE32(0); uint t1=BE32(4); uint t2=BE32(8); uint t3=BE32(12); uint t4=BE32(16); uint t5=BE32(20); uint t6=BE32(24); uint t7=BE32(28);\n"
"  if (H8[0]==t0&&H8[1]==t1&&H8[2]==t2&&H8[3]==t3&&H8[4]==t4&&H8[5]==t5&&H8[6]==t6&&H8[7]==t7){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void sha256maskmulti(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);\n"
"  uint H8[8]; sha256_compress(m,H8);\n"
"  int lo=0, hi=(int)nTargets-1;\n"
"  while (lo<=hi){\n"
"    int mid=(lo+hi)>>1; int cmp=0;\n"
"    uint v0=targets[mid*8+0]; uint v1=targets[mid*8+1]; uint v2=targets[mid*8+2]; uint v3=targets[mid*8+3]; uint v4=targets[mid*8+4]; uint v5=targets[mid*8+5]; uint v6=targets[mid*8+6]; uint v7=targets[mid*8+7];\n"
"    if (H8[0]!=v0) cmp=(H8[0]<v0)?-1:1;\n"
"    else if (H8[1]!=v1) cmp=(H8[1]<v1)?-1:1;\n"
"    else if (H8[2]!=v2) cmp=(H8[2]<v2)?-1:1;\n"
"    else if (H8[3]!=v3) cmp=(H8[3]<v3)?-1:1;\n"
"    else if (H8[4]!=v4) cmp=(H8[4]<v4)?-1:1;\n"
"    else if (H8[5]!=v5) cmp=(H8[5]<v5)?-1:1;\n"
"    else if (H8[6]!=v6) cmp=(H8[6]<v6)?-1:1;\n"
"    else if (H8[7]!=v7) cmp=(H8[7]<v7)?-1:1;\n"
"    if (cmp==0){ if (atomic_fetch_or_explicit(&foundFlag[mid],1u,memory_order_relaxed)==0u) foundIdx[mid]=idx; break; }\n"
"    else if (cmp<0) hi=mid-1; else lo=mid+1;\n"
"  }\n"
"}\n"
"kernel void sha1mask(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uchar* target [[buffer(5)]], device atomic_uint* found [[buffer(6)]], device ulong* foundIdx [[buffer(7)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);\n"
"  uint H5[5]; sha1_compress(m,H5);\n"
"  uint t0=BE32(0); uint t1=BE32(4); uint t2=BE32(8); uint t3=BE32(12); uint t4=BE32(16);\n"
"  if (H5[0]==t0&&H5[1]==t1&&H5[2]==t2&&H5[3]==t3&&H5[4]==t4){ atomic_store_explicit(found,1u,memory_order_relaxed); *foundIdx=idx; }\n"
"}\n"
"kernel void sha1maskmulti(constant uchar* sets [[buffer(0)]], constant uint* setOff [[buffer(1)]], constant uint& wordLen [[buffer(2)]], constant ulong& startIdx [[buffer(3)]], constant uint& count [[buffer(4)]], device const uint* targets [[buffer(5)]], constant uint& nTargets [[buffer(6)]], device atomic_uint* foundFlag [[buffer(7)]], device ulong* foundIdx [[buffer(8)]], uint gid [[thread_position_in_grid]]) {\n"
"  if (gid >= count) return;\n"
"  ulong idx = startIdx + (ulong)gid;\n"
"  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);\n"
"  uint H5[5]; sha1_compress(m,H5);\n"
"  int lo=0, hi=(int)nTargets-1;\n"
"  while (lo<=hi){\n"
"    int mid=(lo+hi)>>1; int cmp=0;\n"
"    uint v0=targets[mid*5+0]; uint v1=targets[mid*5+1]; uint v2=targets[mid*5+2]; uint v3=targets[mid*5+3]; uint v4=targets[mid*5+4];\n"
"    if (H5[0]!=v0) cmp=(H5[0]<v0)?-1:1;\n"
"    else if (H5[1]!=v1) cmp=(H5[1]<v1)?-1:1;\n"
"    else if (H5[2]!=v2) cmp=(H5[2]<v2)?-1:1;\n"
"    else if (H5[3]!=v3) cmp=(H5[3]<v3)?-1:1;\n"
"    else if (H5[4]!=v4) cmp=(H5[4]<v4)?-1:1;\n"
"    if (cmp==0){ if (atomic_fetch_or_explicit(&foundFlag[mid],1u,memory_order_relaxed)==0u) foundIdx[mid]=idx; break; }\n"
"    else if (cmp<0) hi=mid-1; else lo=mid+1;\n"
"  }\n"
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
    id<MTLComputePipelineState> pipeMd4MaskMulti;
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
        id<MTLComputePipelineState> p11 = mkpipe(dev, lib, @"md4maskmulti", errbuf, errlen);
        if (!p11) return NULL;
        hs_ctx *ctx = (hs_ctx *)calloc(1, sizeof(hs_ctx));
        ctx->dev = dev; ctx->queue = [dev newCommandQueue]; ctx->pipe = p1; ctx->pipeBrute = p2; ctx->pipeMask = p3; ctx->pipeMaskMulti = p4;
        ctx->pipeNtlmMask = p5; ctx->pipeNtlmMaskMulti = p6; ctx->pipeShaMask = p7; ctx->pipeShaMaskMulti = p8;
        ctx->pipeSha1Mask = p9; ctx->pipeSha1MaskMulti = p10;
        ctx->pipeMd4MaskMulti = p11;
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
            case 4: pipe = ctx->pipeMd4MaskMulti; break;
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
