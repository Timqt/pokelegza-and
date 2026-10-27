// 自动生成：tools/patch_tls_base.py —— 别手改
// 1) 客机写 TPIDR_EL0 ⇒ 会把 bionic 的 TLS 指针冲掉 ⇒ 后续 libc 调用必崩。
//    全部 NOP 掉（客机 TLS 走影子描述符，不依赖这个寄存器）。
// 2) SDK 的 2 处真·TLS 基址读（musl __tls_get_addr 快速路径）
//    改读「SDK 自己的一页 TLS 上下文」。
#ifndef ZA_TLSBASE_PATCH_H
#define ZA_TLSBASE_PATCH_H

#define ZA_SDK_TLSCTX_OFF   0xf10000ul   /* SDK 的 TLS 上下文页 */
#define ZA_SDK_TLSCTX_SIZE 0x1000ul
#define ZA_SDK_TLSTAB_OFF   0xf11000ul   /* 动态 TLS 表 */
#define ZA_SDK_TLSTAB_SIZE 0x1000ul
#define ZA_TLSBASE_READ_COUNT  2
#define ZA_TLSBASE_SDK_WRITE_COUNT  4
#define ZA_TLSBASE_MAIN_WRITE_COUNT 1

typedef struct { unsigned int off; unsigned int w; } za_tlsbase_patch_t;

static const za_tlsbase_patch_t za_tlsbase_reads[] = {
    {0x9751cu, 0xb00073c3u},
    {0x975b0u, 0xb00073c3u},
};

static const za_tlsbase_patch_t za_tlsbase_sdk_writes[] = {
    {0x99220u, 0xd503201fu},
    {0x99224u, 0xd503201fu},
    {0x144620u, 0xd503201fu},
    {0x144a90u, 0xd503201fu},
};

static const za_tlsbase_patch_t za_tlsbase_main_writes[] = {
    {0x1a0a85cu, 0xd503201fu},
};

// musl __tls_get_addr 快速路径末尾的 `sub x0,x0,x3`：
// 它把「变量绝对地址」变成「相对 TLS 基址的偏移」，但调用方要的是地址
// （SDK 里已经没有别的 mrs TPIDR_EL0 了）⇒ 客机拿野偏移当地址用 ⇒ 跳飞。
static const za_tlsbase_patch_t za_tlsbase_subfix[] = {
    {0x40bd8u, 0xd503201fu},
    {0x97538u, 0xd503201fu},
};

#endif
