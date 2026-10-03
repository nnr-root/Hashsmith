// EXPERIMENTAL scrypt(N, r=1, p=1) feasibility kernel — WP3.2.
//
// NOT wired into opencl.go / opencl_host.c / the production kernel dispatch.
// Standalone file, not embedded anywhere, not referenced by any Go code.
// Purpose: let a future session with real GPU access measure whether many
// GPU threads in flight can hide scrypt's sequential memory latency the way
// CPU-side goroutine/lane interleaving failed to (see
// docs/superpowers/notes/2026-09-25's scrypt-AVX2 spike in project history:
// negative result, latency-bound not compute-bound, N/2 sequential
// data-dependent reads into an array too large for cache). A GPU's much
// higher AGGREGATE memory bandwidth, spread across many concurrent threads
// each doing their own sequential walk, is the one lever that CPU spike
// could not test — this kernel exists to test it, once real hardware is
// available.
//
// r is fixed at 1 (not generalized) deliberately: this is a feasibility
// probe for the memory-bandwidth question, not a production kernel, and r=1
// is both scrypt's simplest real case (Cisco $9$ uses it, matching the
// format this project's own CPU spike measured) and the one with a
// published RFC 7914 test vector to verify against.
//
// Every non-OpenCL-specific piece of logic below (Salsa20/8 core, BlockMix
// r=1, ROMix/smix, the Davies-Meyer SHA-256 multi-block compressor, HMAC-
// SHA256, PBKDF2 with 1 iteration) was first written and checked in plain
// Go against RFC 7914's own test vector, x/crypto/scrypt (configured for
// r=1, 5 varied password/salt/N cases up to N=16384), and stdlib
// crypto/hmac + golang.org/x/crypto/pbkdf2 (including a deliberately
// 4-SHA-256-block HMAC message, the hardest case this kernel's own B_final
// step produces) — all matched exactly. This file is a 1:1 transcription of
// that verified logic into OpenCL C. What is NOT verified: that this
// specific OpenCL C source compiles or executes identically on any real
// OpenCL compiler. No OpenCL compiler could be reached this session — see
// docs/superpowers/notes/2026-10-03-wp3-2-scrypt-feasibility-kernel.md for
// why (no GPU hardware, and this machine's CGO toolchain is broken
// independently of that). Treat every line below as unvalidated C syntax
// until a real OpenCL compiler has accepted it.
//
// Scope, deliberately minimal per the task's own framing: candidates are
// supplied as plaintext bytes from the host (packed, fixed length), not
// generated in-kernel from a charset/mask the way the production kernels
// do — that machinery is already solved elsewhere and reusing it here would
// obscure the one question this kernel exists to answer. pwLen and saltLen
// are capped at 55 bytes each, comfortably covering realistic scrypt inputs
// (e.g. Cisco $9$'s 14-byte salt) while keeping every buffer fixed-size.

#define ROTL32(x,s) (((x)<<(s))|((x)>>(32u-(s))))

// ---- Salsa20/8 core -----------------------------------------------------
// Fully unrolled (16-word private array, every index a literal) following
// this project's own house rule for __private arrays, even though a
// constant-trip-count loop here would likely unroll fine on any real
// compiler — kept explicit for consistency and to remove any doubt, since
// no compiler was available this session to confirm either way.
inline void salsa20_8_core(uint* B){
  uint x0=B[0],x1=B[1],x2=B[2],x3=B[3],x4=B[4],x5=B[5],x6=B[6],x7=B[7];
  uint x8=B[8],x9=B[9],x10=B[10],x11=B[11],x12=B[12],x13=B[13],x14=B[14],x15=B[15];
  for(int i=0;i<4;i++){
    x4^=ROTL32(x0+x12,7);   x8^=ROTL32(x4+x0,9);
    x12^=ROTL32(x8+x4,13);  x0^=ROTL32(x12+x8,18);
    x9^=ROTL32(x5+x1,7);    x13^=ROTL32(x9+x5,9);
    x1^=ROTL32(x13+x9,13);  x5^=ROTL32(x1+x13,18);
    x14^=ROTL32(x10+x6,7);  x2^=ROTL32(x14+x10,9);
    x6^=ROTL32(x2+x14,13);  x10^=ROTL32(x6+x2,18);
    x3^=ROTL32(x15+x11,7);  x7^=ROTL32(x3+x15,9);
    x11^=ROTL32(x7+x3,13);  x15^=ROTL32(x11+x7,18);

    x1^=ROTL32(x0+x3,7);    x2^=ROTL32(x1+x0,9);
    x3^=ROTL32(x2+x1,13);   x0^=ROTL32(x3+x2,18);
    x6^=ROTL32(x5+x4,7);    x7^=ROTL32(x6+x5,9);
    x4^=ROTL32(x7+x6,13);   x5^=ROTL32(x4+x7,18);
    x11^=ROTL32(x10+x9,7);  x8^=ROTL32(x11+x10,9);
    x9^=ROTL32(x8+x11,13);  x10^=ROTL32(x9+x8,18);
    x12^=ROTL32(x15+x14,7); x13^=ROTL32(x12+x15,9);
    x14^=ROTL32(x13+x12,13);x15^=ROTL32(x14+x13,18);
  }
  B[0]+=x0; B[1]+=x1; B[2]+=x2; B[3]+=x3; B[4]+=x4; B[5]+=x5; B[6]+=x6; B[7]+=x7;
  B[8]+=x8; B[9]+=x9; B[10]+=x10; B[11]+=x11; B[12]+=x12; B[13]+=x13; B[14]+=x14; B[15]+=x15;
}

// ---- BlockMix, r=1 special case -----------------------------------------
// General BlockMix shuffles even-indexed Y blocks before odd-indexed ones;
// for r=1 there is exactly one of each (Y_0, Y_1), so B' = (Y_0, Y_1) with
// no shuffle needed. B is 32 words: B[0..15]=B_0, B[16..31]=B_1.
inline void blockmix_salsa8_r1(uint* B){
  uint X[16];
  for(int i=0;i<16;i++) X[i]=B[16+i]; // X = B_{2r-1} = B_1
  for(int i=0;i<16;i++) X[i]^=B[i];
  salsa20_8_core(X);
  uint Y0[16];
  for(int i=0;i<16;i++) Y0[i]=X[i];
  for(int i=0;i<16;i++) X[i]^=B[16+i];
  salsa20_8_core(X);
  for(int i=0;i<16;i++){ B[i]=Y0[i]; B[16+i]=X[i]; }
}

// ---- ROMix / smix, r=1 ---------------------------------------------------
// V is this thread's own private scratch region: N*32 words = N*128 bytes,
// in __global memory (N*128 bytes is far too large for __private or __local
// at any realistic N, and global is also the algorithmically correct
// choice here — unlike the mask kernels' m[16], V's whole purpose is
// large, unpredictable random access, so it was never a private-array
// candidate in the first place). j = Integerify(B_1) mod N reduces to
// B[16] & (N-1) because scrypt requires N to be a power of 2 (RFC 7914 §6)
// — this also means no 64-bit division is needed here, consistent with
// this project's house rule for the same reason the mask kernels avoid it.
inline void smix_r1(uint* B, __global uint* V, uint N){
  for(uint i=0;i<N;i++){
    for(int w=0;w<32;w++) V[i*32u+w]=B[w];
    blockmix_salsa8_r1(B);
  }
  uint mask=N-1u;
  for(uint i=0;i<N;i++){
    uint j=B[16]&mask;
    for(int w=0;w<32;w++) B[w]^=V[j*32u+w];
    blockmix_salsa8_r1(B);
  }
}

// ---- SHA-256, Davies-Meyer continuation form -----------------------------
// Unlike this file's sibling opencl_kernels.cl (whose sha256_compress always
// starts from the fixed IV, because every caller there hashes exactly one
// block), HMAC needs to chain across however many blocks a message needs —
// so this version takes H as both input and output state.
inline void sha256_compress_from_state(uint* M, uint* H){
  uint W[16];
  for(int i=0;i<16;i++) W[i]=M[i];
  uint a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
#define S0(x) (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define S1(x) (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define s0(x) (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define s1(x) (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))
#define ROTR32(x,s) (((x)>>(s))|((x)<<(32u-(s))))
#define ROUND(k,w) { uint t1=h+S1(e)+((e&f)^((~e)&g))+(k)+(w); uint t2=S0(a)+((a&b)^(a&c)^(b&c)); \
  h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }
  ROUND(0x428a2f98u,W[0]) ROUND(0x71374491u,W[1]) ROUND(0xb5c0fbcfu,W[2]) ROUND(0xe9b5dba5u,W[3])
  ROUND(0x3956c25bu,W[4]) ROUND(0x59f111f1u,W[5]) ROUND(0x923f82a4u,W[6]) ROUND(0xab1c5ed5u,W[7])
  ROUND(0xd807aa98u,W[8]) ROUND(0x12835b01u,W[9]) ROUND(0x243185beu,W[10]) ROUND(0x550c7dc3u,W[11])
  ROUND(0x72be5d74u,W[12]) ROUND(0x80deb1feu,W[13]) ROUND(0x9bdc06a7u,W[14]) ROUND(0xc19bf174u,W[15])
#define SCHED(i) (W[(i)&15]+=s1(W[((i)+14)&15])+W[((i)+9)&15]+s0(W[((i)+1)&15]))
  ROUND(0xe49b69c1u,SCHED(16)) ROUND(0xefbe4786u,SCHED(17)) ROUND(0x0fc19dc6u,SCHED(18)) ROUND(0x240ca1ccu,SCHED(19))
  ROUND(0x2de92c6fu,SCHED(20)) ROUND(0x4a7484aau,SCHED(21)) ROUND(0x5cb0a9dcu,SCHED(22)) ROUND(0x76f988dau,SCHED(23))
  ROUND(0x983e5152u,SCHED(24)) ROUND(0xa831c66du,SCHED(25)) ROUND(0xb00327c8u,SCHED(26)) ROUND(0xbf597fc7u,SCHED(27))
  ROUND(0xc6e00bf3u,SCHED(28)) ROUND(0xd5a79147u,SCHED(29)) ROUND(0x06ca6351u,SCHED(30)) ROUND(0x14292967u,SCHED(31))
  ROUND(0x27b70a85u,SCHED(32)) ROUND(0x2e1b2138u,SCHED(33)) ROUND(0x4d2c6dfcu,SCHED(34)) ROUND(0x53380d13u,SCHED(35))
  ROUND(0x650a7354u,SCHED(36)) ROUND(0x766a0abbu,SCHED(37)) ROUND(0x81c2c92eu,SCHED(38)) ROUND(0x92722c85u,SCHED(39))
  ROUND(0xa2bfe8a1u,SCHED(40)) ROUND(0xa81a664bu,SCHED(41)) ROUND(0xc24b8b70u,SCHED(42)) ROUND(0xc76c51a3u,SCHED(43))
  ROUND(0xd192e819u,SCHED(44)) ROUND(0xd6990624u,SCHED(45)) ROUND(0xf40e3585u,SCHED(46)) ROUND(0x106aa070u,SCHED(47))
  ROUND(0x19a4c116u,SCHED(48)) ROUND(0x1e376c08u,SCHED(49)) ROUND(0x2748774cu,SCHED(50)) ROUND(0x34b0bcb5u,SCHED(51))
  ROUND(0x391c0cb3u,SCHED(52)) ROUND(0x4ed8aa4au,SCHED(53)) ROUND(0x5b9cca4fu,SCHED(54)) ROUND(0x682e6ff3u,SCHED(55))
  ROUND(0x748f82eeu,SCHED(56)) ROUND(0x78a5636fu,SCHED(57)) ROUND(0x84c87814u,SCHED(58)) ROUND(0x8cc70208u,SCHED(59))
  ROUND(0x90befffau,SCHED(60)) ROUND(0xa4506cebu,SCHED(61)) ROUND(0xbef9a3f7u,SCHED(62)) ROUND(0xc67178f2u,SCHED(63))
#undef S0
#undef S1
#undef s0
#undef s1
#undef ROTR32
#undef ROUND
#undef SCHED
  H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

// ---- Multi-block SHA-256 with standard MD padding ------------------------
// msg lives in __private byte storage (msgLen <= 196 in every call site
// this kernel makes: HMAC's inner call is 64 + up to 132 = 196 bytes, the
// largest), big-endian word packing per byte, matching this project's own
// BE32 convention in opencl_kernels.cl. nBlocks is computed from msgLen,
// which is itself always one of a few fixed call-site values in this
// kernel (64+saltLen+4, or 64+132) — never attacker-controlled or
// unbounded, so the outer block-count loop here has a small, bounded
// trip count in practice even though its bound is a run-time variable.
inline void sha256_hash(uchar* msg, uint msgLen, uint* H){
  H[0]=0x6a09e667u; H[1]=0xbb67ae85u; H[2]=0x3c6ef372u; H[3]=0xa54ff53au;
  H[4]=0x510e527fu; H[5]=0x9b05688cu; H[6]=0x1f83d9abu; H[7]=0x5be0cd19u;
  uint totalBits=msgLen*8u;
  uint nBlocks=(msgLen+9u+63u)/64u;
  for(uint blk=0;blk<nBlocks;blk++){
    uint m[16];
    for(int w=0;w<16;w++) m[w]=0u;
    uint base=blk*64u;
    for(uint b=0;b<64u;b++){
      uint pos=base+b;
      uint byteVal;
      if(pos<msgLen) byteVal=(uint)msg[pos];
      else if(pos==msgLen) byteVal=0x80u;
      else byteVal=0u;
      m[b>>2] |= byteVal << (24u-((b&3u)*8u));
    }
    if(blk==nBlocks-1u){ m[14]=0u; m[15]=totalBits; }
    sha256_compress_from_state(m,H);
  }
}

// ---- HMAC-SHA256, key <= 64 bytes (zero-padded) --------------------------
inline void hmac_sha256(uchar* key, uint keyLen, uchar* msg, uint msgLen, uint* out){
  uchar k[64];
  for(int i=0;i<64;i++) k[i]=(i<(int)keyLen)?key[i]:0u;
  uchar ipadMsg[64+132]; // worst case this kernel ever builds: 64 + 132
  uchar opadMsg[64+32];  // outer call's msg is always a 32-byte inner hash
  for(int i=0;i<64;i++) ipadMsg[i]=k[i]^0x36u;
  for(uint i=0;i<msgLen;i++) ipadMsg[64+i]=msg[i];
  uint inner[8];
  sha256_hash(ipadMsg,64u+msgLen,inner);
  for(int i=0;i<64;i++) opadMsg[i]=k[i]^0x5cu;
  for(int i=0;i<8;i++){
    opadMsg[64+i*4+0]=(uchar)(inner[i]>>24); opadMsg[64+i*4+1]=(uchar)(inner[i]>>16);
    opadMsg[64+i*4+2]=(uchar)(inner[i]>>8);  opadMsg[64+i*4+3]=(uchar)(inner[i]);
  }
  sha256_hash(opadMsg,96u,out);
}

// ---- The probe kernel -----------------------------------------------------
// out[8] per thread holds the 32-byte scrypt(password, salt, N, r=1, p=1,
// dkLen=32) result. scratch must be N*32 words PER THREAD (total buffer
// size = get_global_size(0) * N * 32 * sizeof(uint)) — this is the
// real-world VRAM cost of parallel scrypt cracking that makes it a
// fundamentally different scaling question than the fast hashes: unlike
// md5mask/sha1mask's few bytes of __private state per thread, this kernel
// needs N*128 bytes of __global scratch PER THREAD, so the achievable
// thread count is capped by VRAM divided by N*128, not by occupancy limits
// the way the fast-hash kernels are. That tradeoff is exactly what a real
// GPU run needs to measure — it cannot be estimated from source.
__kernel void scrypt_r1_probe(
    __global const uchar* passwords, uint pwLen,
    __global const uchar* salt, uint saltLen,
    uint N,
    __global uint* scratch,
    __global uint* out)
{
  uint gid=get_global_id(0);
  uchar pw[55];
  for(uint i=0;i<pwLen && i<55u;i++) pw[i]=passwords[gid*pwLen+i];
  uchar saltBuf[55+4];
  for(uint i=0;i<saltLen && i<55u;i++) saltBuf[i]=salt[i];

  // B_init = PBKDF2-HMAC-SHA256(pw, salt, iter=1, 128 bytes) = 4 HMAC calls,
  // each over salt || BE32(blockIndex).
  //
  // h8 holds HMAC-SHA256's own big-endian-packed words. PBKDF2's real
  // output is the BYTE STRING those words serialize to (big-endian,
  // matching SHA-256's own convention) — and scrypt's own, SEPARATE
  // convention (RFC 7914 §3) then reinterprets THAT byte string as 32-bit
  // words using LITTLE-ENDIAN octet-to-integer conversion for every
  // Salsa20/BlockMix operation. The two endiannesses are independent and
  // conflating them (copying h8 into B directly, skipping the byte-string
  // round trip) silently computes the wrong scrypt entirely — caught only
  // by the committed Go reference test (scrypt_r1_reference_test.go),
  // which an earlier draft of both that test and this kernel failed
  // before this fix.
  uint B[32];
  for(uint blkIdx=1;blkIdx<=4u;blkIdx++){
    saltBuf[saltLen+0]=(uchar)(blkIdx>>24); saltBuf[saltLen+1]=(uchar)(blkIdx>>16);
    saltBuf[saltLen+2]=(uchar)(blkIdx>>8);  saltBuf[saltLen+3]=(uchar)(blkIdx);
    uint h8[8];
    hmac_sha256(pw,pwLen,saltBuf,saltLen+4u,h8);
    for(int w=0;w<8;w++){
      uchar b0=(uchar)(h8[w]>>24), b1=(uchar)(h8[w]>>16), b2=(uchar)(h8[w]>>8), b3=(uchar)(h8[w]);
      B[(blkIdx-1u)*8u+w] = (uint)b0 | ((uint)b1<<8) | ((uint)b2<<16) | ((uint)b3<<24);
    }
  }

  __global uint* V=scratch+(size_t)gid*(size_t)N*32u;
  smix_r1(B,V,N);

  // B_final bytes: B's words are scrypt's own little-endian words (see the
  // comment above), so serializing back to bytes for the next PBKDF2 call
  // must use the same little-endian order, not SHA-256's big-endian one.
  uchar bFinalBytes[128+4];
  for(int w=0;w<32;w++){
    bFinalBytes[w*4+0]=(uchar)(B[w]);      bFinalBytes[w*4+1]=(uchar)(B[w]>>8);
    bFinalBytes[w*4+2]=(uchar)(B[w]>>16);  bFinalBytes[w*4+3]=(uchar)(B[w]>>24);
  }
  bFinalBytes[128]=0u; bFinalBytes[129]=0u; bFinalBytes[130]=0u; bFinalBytes[131]=1u; // BE32(1)
  uint outH[8];
  hmac_sha256(pw,pwLen,bFinalBytes,132u,outH);
  for(int w=0;w<8;w++) out[gid*8u+w]=outH[w];
}
