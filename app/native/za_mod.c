// 模块导出符号表的通用实现（main NSO 与 SDK NSO 共用）。
#include <string.h>

#include "za_common.h"
#include "za_mod.h"

int za_mod_read_dynamic(unsigned char *base, uint32_t *symtab, uint32_t *strtab,
                        uint32_t *strsz)
{
    uint32_t mod0;
    memcpy(&mod0, base + 4, 4);
    if (mod0 + 28 > 0x10000000u) return -1;
    int32_t disp;
    memcpy(&disp, base + mod0 + 4, 4);
    int64_t dyn = (int64_t)mod0 + disp;
    if (dyn < 0) return -1;
    for (int i = 0; i < 512; i++)
    {
        int64_t off = dyn + (int64_t)i * 16;
        int64_t tag;
        uint64_t val;
        memcpy(&tag, base + off, 8);
        memcpy(&val, base + off + 8, 8);
        if (tag == 0) break;
        if (tag == 6) *symtab = (uint32_t)val;        // DT_SYMTAB
        else if (tag == 5) *strtab = (uint32_t)val;   // DT_STRTAB
        else if (tag == 10) *strsz = (uint32_t)val;   // DT_STRSZ
    }
    return 0;
}

int za_mod_from_exports(za_mod_t *m, unsigned char *base,
                        const unsigned char *exp_bin, size_t exp_len)
{
    memset(m, 0, sizeof *m);
    if (exp_len < 12) return -1;
    uint32_t count, strtab, strsz;
    memcpy(&count, exp_bin, 4);
    memcpy(&strtab, exp_bin + 4, 4);
    memcpy(&strsz, exp_bin + 8, 4);
    m->base = base;
    m->strtab = (const char *)(base + strtab);
    m->strtab_size = strsz;
    m->exports = (const uint32_t *)(exp_bin + 12);
    m->export_count = count;
    uint32_t symtab = 0;
    if (za_mod_read_dynamic(base, &symtab, &strtab, &strsz) == 0)
        m->symtab = (const uint32_t *)(base + symtab);
    return 0;
}

void *za_mod_lookup(za_mod_t *m, const char *name)
{
    if (!m || !m->exports || !name) return NULL;
    uint32_t lo = 0, hi = m->export_count;
    while (lo < hi)
    {
        uint32_t mid = (lo + hi) / 2;
        const char *n = m->strtab + m->exports[mid * 2];
        int c = strcmp(n, name);
        if (c == 0) return (void *)(m->base + m->exports[mid * 2 + 1]);
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

const char *za_mod_sym_name(za_mod_t *m, uint32_t symidx, char *buf, size_t buflen)
{
    if (!m || !m->symtab || !m->strtab) return NULL;
    const unsigned char *ent = (const unsigned char *)m->symtab + (size_t)symidx * 24;
    uint32_t noff;
    memcpy(&noff, ent, 4);
    if (noff >= m->strtab_size) return NULL;
    const char *s = m->strtab + noff;
    size_t n = strlen(s);
    if (n >= buflen) return NULL;
    memcpy(buf, s, n + 1);
    return buf;
}
