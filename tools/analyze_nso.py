#!/usr/bin/env python3
"""分析任意 NSO 的段布局与重定位构成（多模块加载方案要用）。

重点看：RELATIVE(1027) 有没有 —— 有的话，多模块各自映射到不同基址就能靠重定位解决；
没有的话（像 main NSO 那样），每个模块都得自己做「基址重定位」。
"""
import collections
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEFS = os.path.join(ROOT, "work", "base", "exefs2")

R_ABS64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1025, 1026, 1027


def analyze(path):
    d = open(path, "rb").read()
    if d[:4] != b"NSO0":
        print("%s: 不是 NSO" % os.path.basename(path))
        return
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    segd = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        segd.append((mo, sz, raw))
    (tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = segd
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    IMG = bytearray(dmo + dsz + bss)
    for mo, sz, raw in segd:
        IMG[mo:mo + sz] = raw

    def rd(off, n):
        if off < 0 or off + n > len(IMG):
            return None
        return bytes(IMG[off:off + n])

    mod0 = struct.unpack_from("<I", bytes(IMG[4:8]), 0)[0]
    disp = struct.unpack_from("<i", rd(mod0, 28), 4)[0]
    dyn = mod0 + disp
    vals = {}
    for i in range(512):
        b = rd(dyn + i * 16, 16)
        if b is None:
            break
        tag, val = struct.unpack_from("<qQ", b, 0)
        if tag == 0:
            break
        vals[tag] = val

    symtab, strtab, strsz = vals[6], vals[5], vals[10]
    nsym = (strtab - symtab) // 24
    strs = rd(strtab, strsz)

    def sym(i):
        b = rd(symtab + i * 24, 24)
        if not b:
            return None
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        value, size = struct.unpack_from("<QQ", b, 8)
        e = strs.find(b"\0", name)
        return (strs[name:e].decode("ascii", "replace"), value, shndx, size)

    counts = collections.Counter()
    undef = set()
    defined = 0
    for off, size in ((vals.get(7), vals.get(8)), (vals.get(23), vals.get(2))):
        if not off or not size:
            continue
        for i in range(size // 24):
            b = rd(off + i * 24, 24)
            if not b:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            si, typ = r_info >> 32, r_info & 0xFFFFFFFF
            counts[typ] += 1
            s = sym(si)
            if s:
                if s[2] == 0:
                    undef.add(s[0])
                else:
                    defined += 1

    print("== %s ==" % os.path.basename(path))
    print("  段: text %#x+%#x  rodata %#x+%#x  data %#x+%#x  bss %#x" %
          (tmo, tsz, rmo, rsz, dmo, dsz, bss))
    print("  映像大小 %#x" % len(IMG))
    print("  dynsym %d 条（未定义 %d / 已定义 %d）" % (nsym, len(undef), defined))
    print("  重定位类型: %s" % dict(counts))
    print("  DT_INIT=%#x INIT_ARRAY=%#x ARRSZ=%#x" %
          (vals.get(12, 0), vals.get(25, 0), vals.get(27, 0)))
    # 导出的符号样例（已定义且有名字）
    ex = [(s[0], s[1]) for s in (sym(i) for i in range(nsym)) if s and s[2] != 0 and s[0]]
    ex.sort(key=lambda x: x[1])
    print("  导出符号 %d 个，样例:" % len(ex))
    for n, v in ex[:8]:
        print("     %-56s %#x" % (n[:56], v))
    if undef:
        u = sorted(undef)
        print("  未定义(导入)符号 %d 个，样例: %s" % (len(u), ", ".join(u[:6])))
    print()


if __name__ == "__main__":
    names = sys.argv[1:] or ["entry_0", "entry_32839457", "entry_32848007"]
    for n in names:
        p = os.path.join(EXEFS, n)
        if os.path.exists(p):
            analyze(p)
