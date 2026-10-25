// Nintendo SDK NSO（entry_32848007）的装载器 —— 对外接口。
#ifndef ZA_SDK_H
#define ZA_SDK_H

#include <stddef.h>
#include <stdint.h>

#include "za_mod.h"

// SDK 的段布局（tools/extract_nso_mod.py 的输出）
// SDK NSO 的**链接基址**是 0x100000000（和 main 一样）。
// ⇒ SDK text 里的 adrp 是按「0x100000000 + 段内偏移」编码的，
//   所以 SDK 映像**必须**映射在 4GB 对齐的地址上，
//   否则每一个 adrp 都偏 4GB，读到的全是无关内存。
// main 占 0x100000000，SDK 放 0x200000000。
#define ZA_SDK_BASE_ADDR  0x200000000ul
// 客机地址空间（ASLR/alias/stack/heap 四块）的预留基址
// （同样要避开 0x200000000，别盖住 SDK 映像）
#define ZA_MEM_BASE_ADDR  0x400000000ull
#define ZA_SDK_TEXT_OFF    0x0ul
#define ZA_SDK_TEXT_SIZE   0x64E230ul
#define ZA_SDK_RODATA_OFF  0x64F000ul
#define ZA_SDK_RODATA_SIZE 0x4EC000ul
#define ZA_SDK_DATA_OFF    0xB3B000ul
#define ZA_SDK_DATA_SIZE   0x544E0ul
#define ZA_SDK_BSS_SIZE    0xCEB20ul
#define ZA_SDK_INIT        0x400ul
#define ZA_SDK_INIT_ARRAY  0xB3B000ul
#define ZA_SDK_INIT_ARRSZ  0x2B8ul
// 映像末尾扩展区的总大小：门区（0xC70000 起）+ 只读 TLS 页（0xF00000 起）
//                          + SDK 自己的 TLS 上下文页（0xF10000 起）
#define ZA_SDK_EXT_SIZE    0xF12000ul

// 装载 SDK 映像：映射 + 基址重定位 + ELF 重定位
// （未定义符号依次找：宿主 → main 模块 → SDK 自己的导出表）
int za_sdk_load(za_mod_t *sdk,
                const unsigned char *text, size_t text_size,
                const unsigned char *rodata, size_t rodata_size,
                const unsigned char *data, size_t data_size,
                size_t bss,
                const unsigned char *exp_bin, size_t exp_len,
                const unsigned char *rel_bin, size_t rel_len,
                const unsigned char *gate_bin, size_t gate_len,
                void *(*resolve_host)(const char *name, void *ctx),
                void *(*resolve_main)(const char *name, void *ctx),
                void *ctx);

// 跑 SDK 自己的 _init 与静态构造器（必须先于 main 的 _init）
int za_sdk_run_init(za_mod_t *sdk);

#endif
