// Portable OpenCL kernels for Hashsmith GPU acceleration (MD5, MD4, NTLM,
// SHA-256, SHA-1). Candidates are generated in-kernel from a keyspace index; targets are
// matched on-device. Runs on any OpenCL GPU (NVIDIA / AMD / Intel / Apple).
#define ROTL(x,s) (((x)<<(s))|((x)>>(32-(s))))
#define ROTR(x,s) (((x)>>(s))|((x)<<(32-(s))))
__constant uint MD5K[64]={0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
__constant uint MD5S[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
__constant uint SK[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

void md5_compress(uint* M, uint* oa, uint* ob, uint* oc, uint* od){
  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
  for(int i=0;i<64;i++){ uint f,g;
    if(i<16){f=(b&c)|(~b&d);g=i;}
    else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)&15;}
    else if(i<48){f=b^c^d;g=(3*i+5)&15;}
    else{f=c^(b|~d);g=(7*i)&15;}
    uint tmp=d;d=c;c=b; uint x=a+f+MD5K[i]+M[g]; uint s=MD5S[i]; b=b+ROTL(x,s); a=tmp; }
  *oa=a+0x67452301;*ob=b+0xefcdab89;*oc=c+0x98badcfe;*od=d+0x10325476;
}
void md4_compress(uint* M, uint* oa, uint* ob, uint* oc, uint* od){
  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
#define F1(a,b,c,d,k,s) a=ROTL(a+((b&c)|((~b)&d))+M[k], s)
  F1(a,b,c,d,0,3);F1(d,a,b,c,1,7);F1(c,d,a,b,2,11);F1(b,c,d,a,3,19);
  F1(a,b,c,d,4,3);F1(d,a,b,c,5,7);F1(c,d,a,b,6,11);F1(b,c,d,a,7,19);
  F1(a,b,c,d,8,3);F1(d,a,b,c,9,7);F1(c,d,a,b,10,11);F1(b,c,d,a,11,19);
  F1(a,b,c,d,12,3);F1(d,a,b,c,13,7);F1(c,d,a,b,14,11);F1(b,c,d,a,15,19);
#define F2(a,b,c,d,k,s) a=ROTL(a+((b&c)|(b&d)|(c&d))+M[k]+0x5a827999u, s)
  F2(a,b,c,d,0,3);F2(d,a,b,c,4,5);F2(c,d,a,b,8,9);F2(b,c,d,a,12,13);
  F2(a,b,c,d,1,3);F2(d,a,b,c,5,5);F2(c,d,a,b,9,9);F2(b,c,d,a,13,13);
  F2(a,b,c,d,2,3);F2(d,a,b,c,6,5);F2(c,d,a,b,10,9);F2(b,c,d,a,14,13);
  F2(a,b,c,d,3,3);F2(d,a,b,c,7,5);F2(c,d,a,b,11,9);F2(b,c,d,a,15,13);
#define F3(a,b,c,d,k,s) a=ROTL(a+(b^c^d)+M[k]+0x6ed9eba1u, s)
  F3(a,b,c,d,0,3);F3(d,a,b,c,8,9);F3(c,d,a,b,4,11);F3(b,c,d,a,12,15);
  F3(a,b,c,d,2,3);F3(d,a,b,c,10,9);F3(c,d,a,b,6,11);F3(b,c,d,a,14,15);
  F3(a,b,c,d,1,3);F3(d,a,b,c,9,9);F3(c,d,a,b,5,11);F3(b,c,d,a,13,15);
  F3(a,b,c,d,3,3);F3(d,a,b,c,11,9);F3(c,d,a,b,7,11);F3(b,c,d,a,15,15);
#undef F1
#undef F2
#undef F3
  *oa=a+0x67452301;*ob=b+0xefcdab89;*oc=c+0x98badcfe;*od=d+0x10325476;
}
void sha256_compress(uint* M, uint* H){
  uint w[64]; for(int i=0;i<16;i++) w[i]=M[i];
  for(int i=16;i<64;i++){ uint x=w[i-15]; uint s0=ROTR(x,7)^ROTR(x,18)^(x>>3); uint y=w[i-2]; uint s1=ROTR(y,17)^ROTR(y,19)^(y>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
  uint a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
  for(int i=0;i<64;i++){ uint S1=ROTR(e,6)^ROTR(e,11)^ROTR(e,25); uint ch=(e&f)^((~e)&g); uint t1=h+S1+ch+SK[i]+w[i]; uint S0=ROTR(a,2)^ROTR(a,13)^ROTR(a,22); uint mj=(a&b)^(a&c)^(b&c); uint t2=S0+mj; h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
  H[0]=a+0x6a09e667;H[1]=b+0xbb67ae85;H[2]=c+0x3c6ef372;H[3]=d+0xa54ff53a;H[4]=e+0x510e527f;H[5]=f+0x9b05688c;H[6]=g+0x1f83d9ab;H[7]=h+0x5be0cd19;
}
void sha1_compress(uint* M, uint* H){
  uint w[80]; for(int i=0;i<16;i++) w[i]=M[i];
  for(int i=16;i<80;i++){ uint x=w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i]=ROTL(x,1); }
  uint a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476,e=0xc3d2e1f0;
  for(int i=0;i<80;i++){ uint f,k;
    if(i<20){f=(b&c)|((~b)&d);k=0x5a827999u;} else if(i<40){f=b^c^d;k=0x6ed9eba1u;}
    else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdcu;} else{f=b^c^d;k=0xca62c1d6u;}
    uint tmp=ROTL(a,5)+f+e+k+w[i]; e=d;d=c;c=ROTL(b,30);b=a;a=tmp; }
  H[0]=a+0x67452301;H[1]=b+0xefcdab89;H[2]=c+0x98badcfe;H[3]=d+0x10325476;H[4]=e+0xc3d2e1f0;
}

// decode keyspace index into msg via per-position charsets (stride=st: 1 raw, 2 utf16le)
#define DECODE(msg, idx, sets, setOff, wordLen, st) { ulong _t=idx; for(int p=(int)wordLen-1;p>=0;p--){ uint _o=setOff[p]; uint _s=setOff[p+1]-_o; msg[p*st]=sets[_o+(uint)(_t%(ulong)_s)]; _t/=(ulong)_s; } }
#define BLK_LE(msg, len) { msg[len]=0x80; uint _bl=(len)*8u; msg[56]=_bl&0xff; msg[57]=(_bl>>8)&0xff; msg[58]=(_bl>>16)&0xff; msg[59]=(_bl>>24)&0xff; }
#define BLK_BE(msg, len) { msg[len]=0x80; uint _bl=(len)*8u; msg[63]=_bl&0xff; msg[62]=(_bl>>8)&0xff; msg[61]=(_bl>>16)&0xff; msg[60]=(_bl>>24)&0xff; }
#define LOAD_LE(M, msg) for(int i=0;i<16;i++) M[i]=msg[i*4]|((uint)msg[i*4+1]<<8)|((uint)msg[i*4+2]<<16)|((uint)msg[i*4+3]<<24);
#define LOAD_BE(M, msg) for(int i=0;i<16;i++) M[i]=((uint)msg[i*4]<<24)|((uint)msg[i*4+1]<<16)|((uint)msg[i*4+2]<<8)|(uint)msg[i*4+3];
#define TGT_LE(target, k) (target[k*4]|((uint)target[k*4+1]<<8)|((uint)target[k*4+2]<<16)|((uint)target[k*4+3]<<24))
__kernel void md5mask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_LE(msg, wordLen*1);
  uint M[16]; LOAD_LE(M, msg);
  uint H[4]; md5_compress(M,&H[0],&H[1],&H[2],&H[3]);
  bool ok=true; for(int j=0;j<4;j++){ uint tv=((uint)target[j*4]<<24)|((uint)target[j*4+1]<<16)|((uint)target[j*4+2]<<8)|(uint)target[j*4+3]; uint tv_le=target[j*4]|((uint)target[j*4+1]<<8)|((uint)target[j*4+2]<<16)|((uint)target[j*4+3]<<24); if(H[j]!=tv_le){ ok=false; break; } }
  if(ok){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void md5maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_LE(msg, wordLen*1);
  uint M[16]; LOAD_LE(M, msg);
  uint H[4]; md5_compress(M,&H[0],&H[1],&H[2],&H[3]);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    for(int j=0;j<4;j++){ uint tv=targets[mid*4+j]; if(H[j]!=tv){ cmp=(H[j]<tv)?-1:1; break; } }
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void ntlmmask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 2);
  BLK_LE(msg, wordLen*2);
  uint M[16]; LOAD_LE(M, msg);
  uint H[4]; md4_compress(M,&H[0],&H[1],&H[2],&H[3]);
  bool ok=true; for(int j=0;j<4;j++){ uint tv=((uint)target[j*4]<<24)|((uint)target[j*4+1]<<16)|((uint)target[j*4+2]<<8)|(uint)target[j*4+3]; uint tv_le=target[j*4]|((uint)target[j*4+1]<<8)|((uint)target[j*4+2]<<16)|((uint)target[j*4+3]<<24); if(H[j]!=tv_le){ ok=false; break; } }
  if(ok){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void ntlmmaskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 2);
  BLK_LE(msg, wordLen*2);
  uint M[16]; LOAD_LE(M, msg);
  uint H[4]; md4_compress(M,&H[0],&H[1],&H[2],&H[3]);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    for(int j=0;j<4;j++){ uint tv=targets[mid*4+j]; if(H[j]!=tv){ cmp=(H[j]<tv)?-1:1; break; } }
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void sha256mask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_BE(msg, wordLen*1);
  uint M[16]; LOAD_BE(M, msg);
  uint H[8]; sha256_compress(M,H);
  bool ok=true; for(int j=0;j<8;j++){ uint tv=((uint)target[j*4]<<24)|((uint)target[j*4+1]<<16)|((uint)target[j*4+2]<<8)|(uint)target[j*4+3]; uint tv_le=target[j*4]|((uint)target[j*4+1]<<8)|((uint)target[j*4+2]<<16)|((uint)target[j*4+3]<<24); if(H[j]!=tv){ ok=false; break; } }
  if(ok){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void sha256maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_BE(msg, wordLen*1);
  uint M[16]; LOAD_BE(M, msg);
  uint H[8]; sha256_compress(M,H);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    for(int j=0;j<8;j++){ uint tv=targets[mid*8+j]; if(H[j]!=tv){ cmp=(H[j]<tv)?-1:1; break; } }
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void sha1mask(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uchar* target, volatile __global uint* found, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_BE(msg, wordLen*1);
  uint M[16]; LOAD_BE(M, msg);
  uint H[5]; sha1_compress(M,H);
  bool ok=true; for(int j=0;j<5;j++){ uint tv=((uint)target[j*4]<<24)|((uint)target[j*4+1]<<16)|((uint)target[j*4+2]<<8)|(uint)target[j*4+3]; uint tv_le=target[j*4]|((uint)target[j*4+1]<<8)|((uint)target[j*4+2]<<16)|((uint)target[j*4+3]<<24); if(H[j]!=tv){ ok=false; break; } }
  if(ok){ atomic_or(found,1u); *foundIdx=idx; }
}
__kernel void sha1maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_BE(msg, wordLen*1);
  uint M[16]; LOAD_BE(M, msg);
  uint H[5]; sha1_compress(M,H);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    for(int j=0;j<5;j++){ uint tv=targets[mid*5+j]; if(H[j]!=tv){ cmp=(H[j]<tv)?-1:1; break; } }
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
__kernel void md5k(__global const uchar* data, __global const uint* offsets, __global uchar* out, const uint n){
  uint gid=get_global_id(0); if(gid>=n) return;
  uint start=offsets[gid]; uint len=offsets[gid+1]-start;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  for(uint i=0;i<len&&i<55;i++) msg[i]=data[start+i];
  BLK_LE(msg,len);
  uint M[16]; LOAD_LE(M,msg);
  uint a,b,c,d; md5_compress(M,&a,&b,&c,&d);
  uint o=gid*16;
  out[o]=a&0xff;out[o+1]=(a>>8)&0xff;out[o+2]=(a>>16)&0xff;out[o+3]=(a>>24)&0xff;
  out[o+4]=b&0xff;out[o+5]=(b>>8)&0xff;out[o+6]=(b>>16)&0xff;out[o+7]=(b>>24)&0xff;
  out[o+8]=c&0xff;out[o+9]=(c>>8)&0xff;out[o+10]=(c>>16)&0xff;out[o+11]=(c>>24)&0xff;
  out[o+12]=d&0xff;out[o+13]=(d>>8)&0xff;out[o+14]=(d>>16)&0xff;out[o+15]=(d>>24)&0xff;
}

__kernel void md4maskmulti(__global const uchar* sets, __global const uint* setOff, const uint wordLen, const ulong startIdx, const uint count, __global const uint* targets, const uint nTargets, volatile __global uint* foundFlag, __global ulong* foundIdx){
  uint gid=get_global_id(0); if(gid>=count) return; ulong idx=startIdx+(ulong)gid;
  uchar msg[64]; for(int i=0;i<64;i++) msg[i]=0;
  DECODE(msg, idx, sets, setOff, wordLen, 1);
  BLK_LE(msg, wordLen);
  uint M[16]; LOAD_LE(M, msg);
  uint H[4]; md4_compress(M,&H[0],&H[1],&H[2],&H[3]);
  int lo=0, hi=(int)nTargets-1;
  while(lo<=hi){ int mid=(lo+hi)>>1; int cmp=0;
    for(int j=0;j<4;j++){ uint tv=targets[mid*4+j]; if(H[j]!=tv){ cmp=(H[j]<tv)?-1:1; break; } }
    if(cmp==0){ if(atomic_or(&foundFlag[mid],1u)==0u) foundIdx[mid]=idx; break; }
    else if(cmp<0) hi=mid-1; else lo=mid+1; }
}
