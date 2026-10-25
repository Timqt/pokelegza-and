// 「模块导出符号表」—— main NSO 与 SDK NSO 共用。
//
// 一个 NSO 的 dynsym 里，「已定义」的符号就是它导出给别的模块用的。
// 表的格式（tools/gen_sdk_tables.py 生成，二进制资产）：
//   u32 count      导出符号数
//   u32 strtab     dynstr 在本模块映像内的偏移
//   u32 strsz      dynstr 长度
//   (u32 name_off, u32 value)*count   —— 按名字排序，运行时二分查找
#ifndef ZA_MOD_H
#define ZA_MOD_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    unsigned char *base;        // 模块映像基址
    size_t size;
    const char *strtab;         // 本模块映像里的 dynstr
    uint32_t strtab_size;
    const uint32_t *exports;    // (name_off, value) 对，按名字排序
    uint32_t export_count;
    const uint32_t *symtab;     // 本模块映像里的 dynsym（24 字节/条）
} za_mod_t;

// 从导出表资产建立模块视图（不复制任何数据）
int za_mod_from_exports(za_mod_t *m, unsigned char *base,
                        const unsigned char *exp_bin, size_t exp_len);

// 二分查找导出符号，返回绝对地址（未找到返回 NULL）
void *za_mod_lookup(za_mod_t *m, const char *name);

// 从模块映像的 .dynamic 里取 DT_SYMTAB / DT_STRTAB（NSO 没有节表）
int za_mod_read_dynamic(unsigned char *base, uint32_t *symtab, uint32_t *strtab, uint32_t *strsz);

// 符号索引 → 名字（写进 buf，返回 buf）
const char *za_mod_sym_name(za_mod_t *m, uint32_t symidx, char *buf, size_t buflen);

#endif
