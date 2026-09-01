// Portable OpenCL kernels for Hashsmith GPU acceleration (MD5, MD4, NTLM,
// SHA-256, SHA-1). Candidates are generated in-kernel from a keyspace index;
// targets are matched on-device. Runs on any OpenCL GPU (NVIDIA / AMD / Intel /
// Apple), so nothing here may depend on one vendor's compiler behaviour.
//
// Kernel shapes:
//   md5k       - hash a batch of host-provided candidates (transfer-bound)
//   *mask      - generate each candidate from its keyspace index IN-KERNEL with
//                a per-position charset, hash, and compare on-device, so no
//                candidates cross the bus and only a match flag returns
//   *maskmulti - same, binary-searching a sorted target list on-device
//
// Two rules govern everything in here, and breaking either one costs an order
// of magnitude:
//
//  1. No __private array may ever be indexed by a runtime value. Such an array
//     cannot live in registers, so it is spilled to private memory - which on
//     every current GPU is backed by device memory (NVIDIA "local" memory, AMD
//     scratch) - and every access becomes a memory round trip. That is why the
//     compression functions, the message-schedule windows and the candidate
//     walk are all fully unrolled: every index, rotation and round constant
//     below is an immediate.
//
//  2. 64-bit integer division is emulated in software on all three vendors.
//     The mixed-radix index decode drops to 32-bit arithmetic the moment the
//     remaining index fits, which for realistic keyspaces is after at most a
//     couple of digits.
//
// The index -> candidate mapping is a contract shared with the CPU engine
// (--skip/--limit slicing relies on it being the same pure function on both
// sides); it is preserved exactly here. Only how it is computed changed.
//
// Portability notes: helpers are plain `inline` (OpenCL C is C99-based and
// forbids recursion and function pointers, so implementations inline leaf
// helpers regardless); no vendor intrinsics, no `__attribute__` beyond what
// the OpenCL C spec defines, and the charset buffers stay in __global rather
// than __constant so no device's constant-memory budget can reject them.
#define ROTL(x,s) (((x)<<(s))|((x)>>(32u-(s))))
#define MD5F(a,b,c,d,x,s,t) a = b + ROTL(a + (((b)&(c))|((~(b))&(d))) + (x) + (t), s);
#define MD5G(a,b,c,d,x,s,t) a = b + ROTL(a + (((d)&(b))|((~(d))&(c))) + (x) + (t), s);
#define MD5H(a,b,c,d,x,s,t) a = b + ROTL(a + ((b)^(c)^(d)) + (x) + (t), s);
#define MD5I(a,b,c,d,x,s,t) a = b + ROTL(a + ((c)^((b)|(~(d)))) + (x) + (t), s);
inline void md5_compress(uint* M, uint* a0, uint* b0, uint* c0, uint* d0){
  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
  MD5F(a,b,c,d,M[0],7,0xd76aa478u)
  MD5F(d,a,b,c,M[1],12,0xe8c7b756u)
  MD5F(c,d,a,b,M[2],17,0x242070dbu)
  MD5F(b,c,d,a,M[3],22,0xc1bdceeeu)
  MD5F(a,b,c,d,M[4],7,0xf57c0fafu)
  MD5F(d,a,b,c,M[5],12,0x4787c62au)
  MD5F(c,d,a,b,M[6],17,0xa8304613u)
  MD5F(b,c,d,a,M[7],22,0xfd469501u)
  MD5F(a,b,c,d,M[8],7,0x698098d8u)
  MD5F(d,a,b,c,M[9],12,0x8b44f7afu)
  MD5F(c,d,a,b,M[10],17,0xffff5bb1u)
  MD5F(b,c,d,a,M[11],22,0x895cd7beu)
  MD5F(a,b,c,d,M[12],7,0x6b901122u)
  MD5F(d,a,b,c,M[13],12,0xfd987193u)
  MD5F(c,d,a,b,M[14],17,0xa679438eu)
  MD5F(b,c,d,a,M[15],22,0x49b40821u)
  MD5G(a,b,c,d,M[1],5,0xf61e2562u)
  MD5G(d,a,b,c,M[6],9,0xc040b340u)
  MD5G(c,d,a,b,M[11],14,0x265e5a51u)
  MD5G(b,c,d,a,M[0],20,0xe9b6c7aau)
  MD5G(a,b,c,d,M[5],5,0xd62f105du)
  MD5G(d,a,b,c,M[10],9,0x02441453u)
  MD5G(c,d,a,b,M[15],14,0xd8a1e681u)
  MD5G(b,c,d,a,M[4],20,0xe7d3fbc8u)
  MD5G(a,b,c,d,M[9],5,0x21e1cde6u)
  MD5G(d,a,b,c,M[14],9,0xc33707d6u)
  MD5G(c,d,a,b,M[3],14,0xf4d50d87u)
  MD5G(b,c,d,a,M[8],20,0x455a14edu)
  MD5G(a,b,c,d,M[13],5,0xa9e3e905u)
  MD5G(d,a,b,c,M[2],9,0xfcefa3f8u)
  MD5G(c,d,a,b,M[7],14,0x676f02d9u)
  MD5G(b,c,d,a,M[12],20,0x8d2a4c8au)
  MD5H(a,b,c,d,M[5],4,0xfffa3942u)
  MD5H(d,a,b,c,M[8],11,0x8771f681u)
  MD5H(c,d,a,b,M[11],16,0x6d9d6122u)
  MD5H(b,c,d,a,M[14],23,0xfde5380cu)
  MD5H(a,b,c,d,M[1],4,0xa4beea44u)
  MD5H(d,a,b,c,M[4],11,0x4bdecfa9u)
  MD5H(c,d,a,b,M[7],16,0xf6bb4b60u)
  MD5H(b,c,d,a,M[10],23,0xbebfbc70u)
  MD5H(a,b,c,d,M[13],4,0x289b7ec6u)
  MD5H(d,a,b,c,M[0],11,0xeaa127fau)
  MD5H(c,d,a,b,M[3],16,0xd4ef3085u)
  MD5H(b,c,d,a,M[6],23,0x04881d05u)
  MD5H(a,b,c,d,M[9],4,0xd9d4d039u)
  MD5H(d,a,b,c,M[12],11,0xe6db99e5u)
  MD5H(c,d,a,b,M[15],16,0x1fa27cf8u)
  MD5H(b,c,d,a,M[2],23,0xc4ac5665u)
  MD5I(a,b,c,d,M[0],6,0xf4292244u)
  MD5I(d,a,b,c,M[7],10,0x432aff97u)
  MD5I(c,d,a,b,M[14],15,0xab9423a7u)
  MD5I(b,c,d,a,M[5],21,0xfc93a039u)
  MD5I(a,b,c,d,M[12],6,0x655b59c3u)
  MD5I(d,a,b,c,M[3],10,0x8f0ccc92u)
  MD5I(c,d,a,b,M[10],15,0xffeff47du)
  MD5I(b,c,d,a,M[1],21,0x85845dd1u)
  MD5I(a,b,c,d,M[8],6,0x6fa87e4fu)
  MD5I(d,a,b,c,M[15],10,0xfe2ce6e0u)
  MD5I(c,d,a,b,M[6],15,0xa3014314u)
  MD5I(b,c,d,a,M[13],21,0x4e0811a1u)
  MD5I(a,b,c,d,M[4],6,0xf7537e82u)
  MD5I(d,a,b,c,M[11],10,0xbd3af235u)
  MD5I(c,d,a,b,M[2],15,0x2ad7d2bbu)
  MD5I(b,c,d,a,M[9],21,0xeb86d391u)
  *a0=a+0x67452301; *b0=b+0xefcdab89; *c0=c+0x98badcfe; *d0=d+0x10325476;
}
#undef MD5F
#undef MD5G
#undef MD5H
#undef MD5I
inline void md4_compress(uint* M, uint* a0, uint* b0, uint* c0, uint* d0){
  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
#define FF(a,b,c,d,k,s) a=ROTL(a+(((b)&(c))|((~(b))&(d)))+M[k], s)
  FF(a,b,c,d,0,3); FF(d,a,b,c,1,7); FF(c,d,a,b,2,11); FF(b,c,d,a,3,19);
  FF(a,b,c,d,4,3); FF(d,a,b,c,5,7); FF(c,d,a,b,6,11); FF(b,c,d,a,7,19);
  FF(a,b,c,d,8,3); FF(d,a,b,c,9,7); FF(c,d,a,b,10,11); FF(b,c,d,a,11,19);
  FF(a,b,c,d,12,3); FF(d,a,b,c,13,7); FF(c,d,a,b,14,11); FF(b,c,d,a,15,19);
#define GG(a,b,c,d,k,s) a=ROTL(a+(((b)&(c))|((b)&(d))|((c)&(d)))+M[k]+0x5a827999u, s)
  GG(a,b,c,d,0,3); GG(d,a,b,c,4,5); GG(c,d,a,b,8,9); GG(b,c,d,a,12,13);
  GG(a,b,c,d,1,3); GG(d,a,b,c,5,5); GG(c,d,a,b,9,9); GG(b,c,d,a,13,13);
  GG(a,b,c,d,2,3); GG(d,a,b,c,6,5); GG(c,d,a,b,10,9); GG(b,c,d,a,14,13);
  GG(a,b,c,d,3,3); GG(d,a,b,c,7,5); GG(c,d,a,b,11,9); GG(b,c,d,a,15,13);
#define HH(a,b,c,d,k,s) a=ROTL(a+((b)^(c)^(d))+M[k]+0x6ed9eba1u, s)
  HH(a,b,c,d,0,3); HH(d,a,b,c,8,9); HH(c,d,a,b,4,11); HH(b,c,d,a,12,15);
  HH(a,b,c,d,2,3); HH(d,a,b,c,10,9); HH(c,d,a,b,6,11); HH(b,c,d,a,14,15);
  HH(a,b,c,d,1,3); HH(d,a,b,c,9,9); HH(c,d,a,b,5,11); HH(b,c,d,a,13,15);
  HH(a,b,c,d,3,3); HH(d,a,b,c,11,9); HH(c,d,a,b,7,11); HH(b,c,d,a,15,15);
#undef FF
#undef GG
#undef HH
  *a0=a+0x67452301; *b0=b+0xefcdab89; *c0=c+0x98badcfe; *d0=d+0x10325476;
}
// SHA-1, fully unrolled over a 16-word rolling schedule window (W[] indices
// are constant, so no 80-word spilled array).
#define S1W(i) (W[(i)&15] = ROTL(W[((i)+13)&15]^W[((i)+8)&15]^W[((i)+2)&15]^W[(i)&15],1))
#define S1R(a,b,c,d,e,f,k,w) e += ROTL(a,5) + (f) + (k) + (w); b = ROTL(b,30);
inline void sha1_compress(uint* M, uint* H5){
  uint W[16];
  W[0]=M[0]; W[1]=M[1]; W[2]=M[2]; W[3]=M[3]; W[4]=M[4]; W[5]=M[5]; W[6]=M[6]; W[7]=M[7]; W[8]=M[8]; W[9]=M[9]; W[10]=M[10]; W[11]=M[11]; W[12]=M[12]; W[13]=M[13]; W[14]=M[14]; W[15]=M[15];
  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476,e=0xc3d2e1f0;
  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[0])
  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,W[1])
  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,W[2])
  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,W[3])
  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,W[4])
  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[5])
  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,W[6])
  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,W[7])
  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,W[8])
  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,W[9])
  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[10])
  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,W[11])
  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,W[12])
  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,W[13])
  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,W[14])
  S1R(a,b,c,d,e,((b&c)|((~b)&d)),0x5a827999u,W[15])
  S1R(e,a,b,c,d,((a&b)|((~a)&c)),0x5a827999u,S1W(16))
  S1R(d,e,a,b,c,((e&a)|((~e)&b)),0x5a827999u,S1W(17))
  S1R(c,d,e,a,b,((d&e)|((~d)&a)),0x5a827999u,S1W(18))
  S1R(b,c,d,e,a,((c&d)|((~c)&e)),0x5a827999u,S1W(19))
  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(20))
  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(21))
  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(22))
  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(23))
  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(24))
  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(25))
  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(26))
  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(27))
  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(28))
  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(29))
  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(30))
  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(31))
  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(32))
  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(33))
  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(34))
  S1R(a,b,c,d,e,(b^c^d),0x6ed9eba1u,S1W(35))
  S1R(e,a,b,c,d,(a^b^c),0x6ed9eba1u,S1W(36))
  S1R(d,e,a,b,c,(e^a^b),0x6ed9eba1u,S1W(37))
  S1R(c,d,e,a,b,(d^e^a),0x6ed9eba1u,S1W(38))
  S1R(b,c,d,e,a,(c^d^e),0x6ed9eba1u,S1W(39))
  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(40))
  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(41))
  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(42))
  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(43))
  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(44))
  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(45))
  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(46))
  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(47))
  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(48))
  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(49))
  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(50))
  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(51))
  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(52))
  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(53))
  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(54))
  S1R(a,b,c,d,e,((b&c)|(b&d)|(c&d)),0x8f1bbcdcu,S1W(55))
  S1R(e,a,b,c,d,((a&b)|(a&c)|(b&c)),0x8f1bbcdcu,S1W(56))
  S1R(d,e,a,b,c,((e&a)|(e&b)|(a&b)),0x8f1bbcdcu,S1W(57))
  S1R(c,d,e,a,b,((d&e)|(d&a)|(e&a)),0x8f1bbcdcu,S1W(58))
  S1R(b,c,d,e,a,((c&d)|(c&e)|(d&e)),0x8f1bbcdcu,S1W(59))
  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(60))
  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(61))
  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(62))
  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(63))
  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(64))
  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(65))
  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(66))
  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(67))
  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(68))
  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(69))
  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(70))
  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(71))
  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(72))
  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(73))
  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(74))
  S1R(a,b,c,d,e,(b^c^d),0xca62c1d6u,S1W(75))
  S1R(e,a,b,c,d,(a^b^c),0xca62c1d6u,S1W(76))
  S1R(d,e,a,b,c,(e^a^b),0xca62c1d6u,S1W(77))
  S1R(c,d,e,a,b,(d^e^a),0xca62c1d6u,S1W(78))
  S1R(b,c,d,e,a,(c^d^e),0xca62c1d6u,S1W(79))
  H5[0]=a+0x67452301; H5[1]=b+0xefcdab89; H5[2]=c+0x98badcfe; H5[3]=d+0x10325476; H5[4]=e+0xc3d2e1f0;
}
#undef S1W
#undef S1R
// SHA-256, fully unrolled over a 16-word rolling schedule window.
#define ROTR(x,s) (((x)>>(s))|((x)<<(32u-(s))))
#define S2S0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define S2S1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))
#define S2W(i) (W[(i)&15] += S2S1(W[((i)+14)&15]) + W[((i)+9)&15] + S2S0(W[((i)+1)&15]))
#define S2R(a,b,c,d,e,f,g,h,k,w) { uint _t1 = h + (ROTR(e,6)^ROTR(e,11)^ROTR(e,25)) + (((e)&(f))^((~(e))&(g))) + (k) + (w); \
  uint _t2 = (ROTR(a,2)^ROTR(a,13)^ROTR(a,22)) + (((a)&(b))^((a)&(c))^((b)&(c))); d += _t1; h = _t1 + _t2; }
inline void sha256_compress(uint* M, uint* H8){
  uint W[16];
  W[0]=M[0]; W[1]=M[1]; W[2]=M[2]; W[3]=M[3]; W[4]=M[4]; W[5]=M[5]; W[6]=M[6]; W[7]=M[7]; W[8]=M[8]; W[9]=M[9]; W[10]=M[10]; W[11]=M[11]; W[12]=M[12]; W[13]=M[13]; W[14]=M[14]; W[15]=M[15];
  uint a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
  S2R(a,b,c,d,e,f,g,h,0x428a2f98u,W[0])
  S2R(h,a,b,c,d,e,f,g,0x71374491u,W[1])
  S2R(g,h,a,b,c,d,e,f,0xb5c0fbcfu,W[2])
  S2R(f,g,h,a,b,c,d,e,0xe9b5dba5u,W[3])
  S2R(e,f,g,h,a,b,c,d,0x3956c25bu,W[4])
  S2R(d,e,f,g,h,a,b,c,0x59f111f1u,W[5])
  S2R(c,d,e,f,g,h,a,b,0x923f82a4u,W[6])
  S2R(b,c,d,e,f,g,h,a,0xab1c5ed5u,W[7])
  S2R(a,b,c,d,e,f,g,h,0xd807aa98u,W[8])
  S2R(h,a,b,c,d,e,f,g,0x12835b01u,W[9])
  S2R(g,h,a,b,c,d,e,f,0x243185beu,W[10])
  S2R(f,g,h,a,b,c,d,e,0x550c7dc3u,W[11])
  S2R(e,f,g,h,a,b,c,d,0x72be5d74u,W[12])
  S2R(d,e,f,g,h,a,b,c,0x80deb1feu,W[13])
  S2R(c,d,e,f,g,h,a,b,0x9bdc06a7u,W[14])
  S2R(b,c,d,e,f,g,h,a,0xc19bf174u,W[15])
  S2R(a,b,c,d,e,f,g,h,0xe49b69c1u,S2W(16))
  S2R(h,a,b,c,d,e,f,g,0xefbe4786u,S2W(17))
  S2R(g,h,a,b,c,d,e,f,0x0fc19dc6u,S2W(18))
  S2R(f,g,h,a,b,c,d,e,0x240ca1ccu,S2W(19))
  S2R(e,f,g,h,a,b,c,d,0x2de92c6fu,S2W(20))
  S2R(d,e,f,g,h,a,b,c,0x4a7484aau,S2W(21))
  S2R(c,d,e,f,g,h,a,b,0x5cb0a9dcu,S2W(22))
  S2R(b,c,d,e,f,g,h,a,0x76f988dau,S2W(23))
  S2R(a,b,c,d,e,f,g,h,0x983e5152u,S2W(24))
  S2R(h,a,b,c,d,e,f,g,0xa831c66du,S2W(25))
  S2R(g,h,a,b,c,d,e,f,0xb00327c8u,S2W(26))
  S2R(f,g,h,a,b,c,d,e,0xbf597fc7u,S2W(27))
  S2R(e,f,g,h,a,b,c,d,0xc6e00bf3u,S2W(28))
  S2R(d,e,f,g,h,a,b,c,0xd5a79147u,S2W(29))
  S2R(c,d,e,f,g,h,a,b,0x06ca6351u,S2W(30))
  S2R(b,c,d,e,f,g,h,a,0x14292967u,S2W(31))
  S2R(a,b,c,d,e,f,g,h,0x27b70a85u,S2W(32))
  S2R(h,a,b,c,d,e,f,g,0x2e1b2138u,S2W(33))
  S2R(g,h,a,b,c,d,e,f,0x4d2c6dfcu,S2W(34))
  S2R(f,g,h,a,b,c,d,e,0x53380d13u,S2W(35))
  S2R(e,f,g,h,a,b,c,d,0x650a7354u,S2W(36))
  S2R(d,e,f,g,h,a,b,c,0x766a0abbu,S2W(37))
  S2R(c,d,e,f,g,h,a,b,0x81c2c92eu,S2W(38))
  S2R(b,c,d,e,f,g,h,a,0x92722c85u,S2W(39))
  S2R(a,b,c,d,e,f,g,h,0xa2bfe8a1u,S2W(40))
  S2R(h,a,b,c,d,e,f,g,0xa81a664bu,S2W(41))
  S2R(g,h,a,b,c,d,e,f,0xc24b8b70u,S2W(42))
  S2R(f,g,h,a,b,c,d,e,0xc76c51a3u,S2W(43))
  S2R(e,f,g,h,a,b,c,d,0xd192e819u,S2W(44))
  S2R(d,e,f,g,h,a,b,c,0xd6990624u,S2W(45))
  S2R(c,d,e,f,g,h,a,b,0xf40e3585u,S2W(46))
  S2R(b,c,d,e,f,g,h,a,0x106aa070u,S2W(47))
  S2R(a,b,c,d,e,f,g,h,0x19a4c116u,S2W(48))
  S2R(h,a,b,c,d,e,f,g,0x1e376c08u,S2W(49))
  S2R(g,h,a,b,c,d,e,f,0x2748774cu,S2W(50))
  S2R(f,g,h,a,b,c,d,e,0x34b0bcb5u,S2W(51))
  S2R(e,f,g,h,a,b,c,d,0x391c0cb3u,S2W(52))
  S2R(d,e,f,g,h,a,b,c,0x4ed8aa4au,S2W(53))
  S2R(c,d,e,f,g,h,a,b,0x5b9cca4fu,S2W(54))
  S2R(b,c,d,e,f,g,h,a,0x682e6ff3u,S2W(55))
  S2R(a,b,c,d,e,f,g,h,0x748f82eeu,S2W(56))
  S2R(h,a,b,c,d,e,f,g,0x78a5636fu,S2W(57))
  S2R(g,h,a,b,c,d,e,f,0x84c87814u,S2W(58))
  S2R(f,g,h,a,b,c,d,e,0x8cc70208u,S2W(59))
  S2R(e,f,g,h,a,b,c,d,0x90befffau,S2W(60))
  S2R(d,e,f,g,h,a,b,c,0xa4506cebu,S2W(61))
  S2R(c,d,e,f,g,h,a,b,0xbef9a3f7u,S2W(62))
  S2R(b,c,d,e,f,g,h,a,0xc67178f2u,S2W(63))
  H8[0]=a+0x6a09e667u; H8[1]=b+0xbb67ae85u; H8[2]=c+0x3c6ef372u; H8[3]=d+0xa54ff53au; H8[4]=e+0x510e527fu; H8[5]=f+0x9b05688cu; H8[6]=g+0x1f83d9abu; H8[7]=h+0x5be0cd19u;
}
#undef S2W
#undef S2R
// ---- in-kernel candidate generation ------------------------------------
// The candidate for a global keyspace index is mixed-radix: position
// wordLen-1 is the fastest-moving digit. That mapping is a contract shared
// with the CPU (--skip/--limit slicing depends on it) and is preserved
// exactly here; only how it is computed changed.
//   * digits are peeled with 64-bit division only while the remaining index
//     still needs 64 bits, then in 32-bit (GPUs emulate 64-bit divide);
//   * the position loop is unrolled to the host's maximum candidate length so
//     every m[] word index is an immediate and the block stays in registers;
//   * the 0x80 pad byte is folded into the same unrolled walk.
// wordLen is uniform across the grid, so the per-position guards are uniform
// branches, not divergence.
#define MIX_BEGIN(ix) ulong _t=(ix); uint _t32=(uint)(ix); bool _big=((ix)>(ulong)0xffffffffu);
#define MIX_DIGIT(dst,szv) { uint _s=(szv); \
  if (_big){ ulong _q=_t/(ulong)_s; dst=(uint)(_t-_q*(ulong)_s); _t=_q; \
             if (_t<=(ulong)0xffffffffu){ _big=false; _t32=(uint)_t; } } \
  else { uint _q32=_t32/_s; dst=_t32-_q32*_s; _t32=_q32; } }
#define MZERO m[0]=0u; m[1]=0u; m[2]=0u; m[3]=0u; m[4]=0u; m[5]=0u; m[6]=0u; m[7]=0u; m[8]=0u; m[9]=0u; m[10]=0u; m[11]=0u; m[12]=0u; m[13]=0u; m[14]=0u; m[15]=0u;
#define POS_LE(p) if ((uint)(p)<wordLen){ uint _o=setOff[p]; uint _d; MIX_DIGIT(_d,setOff[(p)+1]-_o) \
    m[(p)>>2] |= (uint)sets[_o+_d] << (((p)&3)*8); } \
  else if ((uint)(p)==wordLen){ m[(p)>>2] |= 0x80u << (((p)&3)*8); }
// wordLen is capped at 55 by the host (maxGPUWordLen), so the walk never
// reaches m[14]/m[15] and the length words below are safe to assign.
inline void build_mask_le(__global const uchar* sets, __global const uint* setOff, uint wordLen, ulong idx, uint* m){
  MZERO
  MIX_BEGIN(idx)
  POS_LE(55) POS_LE(54) POS_LE(53) POS_LE(52) POS_LE(51) POS_LE(50) POS_LE(49) POS_LE(48)
  POS_LE(47) POS_LE(46) POS_LE(45) POS_LE(44) POS_LE(43) POS_LE(42) POS_LE(41) POS_LE(40)
  POS_LE(39) POS_LE(38) POS_LE(37) POS_LE(36) POS_LE(35) POS_LE(34) POS_LE(33) POS_LE(32)
  POS_LE(31) POS_LE(30) POS_LE(29) POS_LE(28) POS_LE(27) POS_LE(26) POS_LE(25) POS_LE(24)
  POS_LE(23) POS_LE(22) POS_LE(21) POS_LE(20) POS_LE(19) POS_LE(18) POS_LE(17) POS_LE(16)
  POS_LE(15) POS_LE(14) POS_LE(13) POS_LE(12) POS_LE(11) POS_LE(10) POS_LE(9) POS_LE(8)
  POS_LE(7) POS_LE(6) POS_LE(5) POS_LE(4) POS_LE(3) POS_LE(2) POS_LE(1) POS_LE(0)
  m[14] = wordLen*8u;
}
#undef POS_LE
#define POS_BE(p) if ((uint)(p)<wordLen){ uint _o=setOff[p]; uint _d; MIX_DIGIT(_d,setOff[(p)+1]-_o) \
    m[(p)>>2] |= (uint)sets[_o+_d] << (24-(((p)&3)*8)); } \
  else if ((uint)(p)==wordLen){ m[(p)>>2] |= 0x80u << (24-(((p)&3)*8)); }
inline void build_mask_be(__global const uchar* sets, __global const uint* setOff, uint wordLen, ulong idx, uint* m){
  MZERO
  MIX_BEGIN(idx)
  POS_BE(55) POS_BE(54) POS_BE(53) POS_BE(52) POS_BE(51) POS_BE(50) POS_BE(49) POS_BE(48)
  POS_BE(47) POS_BE(46) POS_BE(45) POS_BE(44) POS_BE(43) POS_BE(42) POS_BE(41) POS_BE(40)
  POS_BE(39) POS_BE(38) POS_BE(37) POS_BE(36) POS_BE(35) POS_BE(34) POS_BE(33) POS_BE(32)
  POS_BE(31) POS_BE(30) POS_BE(29) POS_BE(28) POS_BE(27) POS_BE(26) POS_BE(25) POS_BE(24)
  POS_BE(23) POS_BE(22) POS_BE(21) POS_BE(20) POS_BE(19) POS_BE(18) POS_BE(17) POS_BE(16)
  POS_BE(15) POS_BE(14) POS_BE(13) POS_BE(12) POS_BE(11) POS_BE(10) POS_BE(9) POS_BE(8)
  POS_BE(7) POS_BE(6) POS_BE(5) POS_BE(4) POS_BE(3) POS_BE(2) POS_BE(1) POS_BE(0)
  m[15] = wordLen*8u;
}
#undef POS_BE
// NTLM: character p lands at byte 2p (UTF-16LE); wordLen is capped at 27 by
// the host so the padded message still fits one block.
#define POS_NT(p) if ((uint)(p)<wordLen){ uint _o=setOff[p]; uint _d; MIX_DIGIT(_d,setOff[(p)+1]-_o) \
    m[(2*(p))>>2] |= (uint)sets[_o+_d] << ((((2*(p))&3))*8); } \
  else if ((uint)(p)==wordLen){ m[(2*(p))>>2] |= 0x80u << ((((2*(p))&3))*8); }
inline void build_mask_ntlm(__global const uchar* sets, __global const uint* setOff, uint wordLen, ulong idx, uint* m){
  MZERO
  MIX_BEGIN(idx)
  POS_NT(27) POS_NT(26) POS_NT(25) POS_NT(24) POS_NT(23) POS_NT(22) POS_NT(21) POS_NT(20)
  POS_NT(19) POS_NT(18) POS_NT(17) POS_NT(16) POS_NT(15) POS_NT(14) POS_NT(13) POS_NT(12)
  POS_NT(11) POS_NT(10) POS_NT(9) POS_NT(8) POS_NT(7) POS_NT(6) POS_NT(5) POS_NT(4)
  POS_NT(3) POS_NT(2) POS_NT(1) POS_NT(0)
  m[14] = wordLen*16u;
}
#undef POS_NT
// ---- batch kernel ------------------------------------------------------
// Pack the candidate straight from global memory into the 16 message words.
// Word index and byte shift are immediates; only the length guards are
// per-thread, and the 0x80 pad rides along in the same walk.
#define MKW(k) { uint _w=0u; \
  if (4u*(k)+0u<len) _w |= (uint)data[start+4u*(k)+0u]; \
  if (4u*(k)+1u<len) _w |= (uint)data[start+4u*(k)+1u]<<8; \
  if (4u*(k)+2u<len) _w |= (uint)data[start+4u*(k)+2u]<<16; \
  if (4u*(k)+3u<len) _w |= (uint)data[start+4u*(k)+3u]<<24; \
  if ((len>>2)==(k)) _w |= 0x80u << ((len&3u)*8u); \
  m[k]=_w; }
__kernel void md5k(__global const uchar* data, __global const uint* offsets, __global uchar* out, const uint n){
  uint gid=get_global_id(0); if(gid>=n) return;
  uint start=offsets[gid]; uint len=offsets[gid+1]-start;
  if(len>55u) len=55u;   // one-block kernel; longer inputs go to the CPU
  uint m[16];
  MKW(0) MKW(1) MKW(2) MKW(3) MKW(4) MKW(5) MKW(6)
  MKW(7) MKW(8) MKW(9) MKW(10) MKW(11) MKW(12) MKW(13)
  m[14]=len*8u; m[15]=0u;
  uint a,b,c,d; md5_compress(m,&a,&b,&c,&d);
  uint o=gid*16;
  out[o+0]=a&0xff;out[o+1]=(a>>8)&0xff;out[o+2]=(a>>16)&0xff;out[o+3]=(a>>24)&0xff;
  out[o+4]=b&0xff;out[o+5]=(b>>8)&0xff;out[o+6]=(b>>16)&0xff;out[o+7]=(b>>24)&0xff;
  out[o+8]=c&0xff;out[o+9]=(c>>8)&0xff;out[o+10]=(c>>16)&0xff;out[o+11]=(c>>24)&0xff;
  out[o+12]=d&0xff;out[o+13]=(d>>8)&0xff;out[o+14]=(d>>16)&0xff;out[o+15]=(d>>24)&0xff;
}
#undef MKW
// ---- mask kernels ------------------------------------------------------
#define TGT4_LE uint t0=(uint)target[0]|((uint)target[1]<<8)|((uint)target[2]<<16)|((uint)target[3]<<24); \
  uint t1=(uint)target[4]|((uint)target[5]<<8)|((uint)target[6]<<16)|((uint)target[7]<<24); \
  uint t2=(uint)target[8]|((uint)target[9]<<8)|((uint)target[10]<<16)|((uint)target[11]<<24); \
  uint t3=(uint)target[12]|((uint)target[13]<<8)|((uint)target[14]<<16)|((uint)target[15]<<24);
#define BE32(i) (((uint)target[i]<<24)|((uint)target[(i)+1]<<16)|((uint)target[(i)+2]<<8)|(uint)target[(i)+3])
__kernel void md5mask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_le(sets,setOff,wordLen,idx,m);
  uint a,b,c,d; md5_compress(m,&a,&b,&c,&d);
  TGT4_LE
  if(a==t0&&b==t1&&c==t2&&d==t3){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void md5maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_le(sets,setOff,wordLen,idx,m);
  uint a,b,c,d; md5_compress(m,&a,&b,&c,&d);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1;
    uint ta=targets[mid*4+0], tb=targets[mid*4+1], tc=targets[mid*4+2], td=targets[mid*4+3];
    int cmp;
    if(a!=ta) cmp=(a<ta)?-1:1;
    else if(b!=tb) cmp=(b<tb)?-1:1;
    else if(c!=tc) cmp=(c<tc)?-1:1;
    else if(d!=td) cmp=(d<td)?-1:1;
    else cmp=0;
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void ntlmmask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_ntlm(sets,setOff,wordLen,idx,m);
  uint a,b,c,d; md4_compress(m,&a,&b,&c,&d);
  TGT4_LE
  if(a==t0&&b==t1&&c==t2&&d==t3){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void ntlmmaskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_ntlm(sets,setOff,wordLen,idx,m);
  uint a,b,c,d; md4_compress(m,&a,&b,&c,&d);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1;
    uint ta=targets[mid*4+0], tb=targets[mid*4+1], tc=targets[mid*4+2], td=targets[mid*4+3];
    int cmp;
    if(a!=ta) cmp=(a<ta)?-1:1;
    else if(b!=tb) cmp=(b<tb)?-1:1;
    else if(c!=tc) cmp=(c<tc)?-1:1;
    else if(d!=td) cmp=(d<td)?-1:1;
    else cmp=0;
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void md4maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_le(sets,setOff,wordLen,idx,m);
  uint a,b,c,d; md4_compress(m,&a,&b,&c,&d);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1;
    uint ta=targets[mid*4+0], tb=targets[mid*4+1], tc=targets[mid*4+2], td=targets[mid*4+3];
    int cmp;
    if(a!=ta) cmp=(a<ta)?-1:1;
    else if(b!=tb) cmp=(b<tb)?-1:1;
    else if(c!=tc) cmp=(c<tc)?-1:1;
    else if(d!=td) cmp=(d<td)?-1:1;
    else cmp=0;
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void sha256mask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);
  uint H8[8]; sha256_compress(m,H8);
  uint t0=BE32(0),t1=BE32(4),t2=BE32(8),t3=BE32(12),t4=BE32(16),t5=BE32(20),t6=BE32(24),t7=BE32(28);
  if(H8[0]==t0&&H8[1]==t1&&H8[2]==t2&&H8[3]==t3&&H8[4]==t4&&H8[5]==t5&&H8[6]==t6&&H8[7]==t7){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void sha256maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);
  uint H8[8]; sha256_compress(m,H8);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    uint v0=targets[mid*8+0],v1=targets[mid*8+1],v2=targets[mid*8+2],v3=targets[mid*8+3];
    uint v4=targets[mid*8+4],v5=targets[mid*8+5],v6=targets[mid*8+6],v7=targets[mid*8+7];
    if(H8[0]!=v0) cmp=(H8[0]<v0)?-1:1;
    else if(H8[1]!=v1) cmp=(H8[1]<v1)?-1:1;
    else if(H8[2]!=v2) cmp=(H8[2]<v2)?-1:1;
    else if(H8[3]!=v3) cmp=(H8[3]<v3)?-1:1;
    else if(H8[4]!=v4) cmp=(H8[4]<v4)?-1:1;
    else if(H8[5]!=v5) cmp=(H8[5]<v5)?-1:1;
    else if(H8[6]!=v6) cmp=(H8[6]<v6)?-1:1;
    else if(H8[7]!=v7) cmp=(H8[7]<v7)?-1:1;
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void sha1mask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);
  uint H5[5]; sha1_compress(m,H5);
  uint t0=BE32(0),t1=BE32(4),t2=BE32(8),t3=BE32(12),t4=BE32(16);
  if(H5[0]==t0&&H5[1]==t1&&H5[2]==t2&&H5[3]==t3&&H5[4]==t4){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void sha1maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uint m[16]; build_mask_be(sets,setOff,wordLen,idx,m);
  uint H5[5]; sha1_compress(m,H5);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    uint v0=targets[mid*5+0],v1=targets[mid*5+1],v2=targets[mid*5+2],v3=targets[mid*5+3],v4=targets[mid*5+4];
    if(H5[0]!=v0) cmp=(H5[0]<v0)?-1:1;
    else if(H5[1]!=v1) cmp=(H5[1]<v1)?-1:1;
    else if(H5[2]!=v2) cmp=(H5[2]<v2)?-1:1;
    else if(H5[3]!=v3) cmp=(H5[3]<v3)?-1:1;
    else if(H5[4]!=v4) cmp=(H5[4]<v4)?-1:1;
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
