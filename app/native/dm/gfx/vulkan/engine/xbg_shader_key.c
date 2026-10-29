#ifndef _GNU_SOURCE
#define _GNU_SOURCE   // process_vm_readv（安全读取客机控制段，见下）
#endif
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(__ANDROID__)
#include <unistd.h>
#include <sys/uio.h>
#endif
static uint32_t rotate(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
// ★ 2026-10-29 真机：control 指针来自客机，可能已经悬空（资源块被提前释放）。
//   直接 memcpy 0x880 字节会在 libc 的 memcpy 里 SIGSEGV/SIGBUS 打死宿主
//   （实测崩点：nvn_shader_selfcheck+308 → h_nvnProgramSetShadersExt）。
//   改成先整块探读：Android 上用 process_vm_readv（读不到只返回短读、不会崩），
//   其他平台是同一进程内的真实指针，memcpy 即可。
// The control pointer comes from the guest and may already be dangling (its
// resource block was freed early). Copy it through a fault-free probe read.
static int copy_guest(void *dst,const void *src,size_t n){
    if(!src)return 0;
#if defined(__ANDROID__)
    struct iovec lo={dst,n},ro={(void *)(uintptr_t)src,n};
    return process_vm_readv(getpid(),&lo,1,&ro,1,0)==(ssize_t)n;
#else
    memcpy(dst,src,n);return 1;
#endif
}
int xbg_shader_control_key(const void *data,char out[17]){
    if(!data || !out)return -1;
    static const uint32_t k[]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t bytes[0x8c0]={0};if(!copy_guest(bytes,data,0x880))return -1;bytes[0x880]=0x80;bytes[sizeof(bytes)-2]=0x44; // 0x880 * 8 = 0x4400
    for(size_t off=0;off<sizeof(bytes);off+=64){uint32_t w[64];for(unsigned i=0;i<16;i++){const uint8_t *p=bytes+off+4*i;w[i]=(uint32_t)(p[0])<<24|(uint32_t)(p[1])<<16|(uint32_t)(p[2])<<8|p[3];}for(unsigned i=16;i<64;i++)w[i]=w[i-16]+(rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10));
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];for(unsigned i=0;i<64;i++){uint32_t t=z+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i],u=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));z=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;}
    static const char hex[]="0123456789abcdef";for(unsigned i=0;i<16;i++)out[i]=hex[(h[i/8]>>(28-4*(i%8)))&15];out[16]=0;return 0;
}
