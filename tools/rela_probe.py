#!/usr/bin/env python3
"""打印 NSO 某个 `.rela` 槽的**原始 r_info**（符号索引 + 重定位类型）。

用途：怀疑「重定位生成器把某一类重定位算错」时，
      看那一格的类型到底是 R_ABS64 / R_GLOB_DAT / R_JUMP_SLOT / R_RELATIVE 还是别的。

用法:
    python tools/rela_probe.py <nso名> <槽偏移> [槽偏移 ...]
例:
    python tools/rela_probe.py entry_32848007 0xb74940 0xb743c0 0xb74980
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEFS = os.path.join(ROOT, "work", "base", "exefs2")

TYPES = {
    257: "R_AARCH64_ABS64",
    258: "R_AARCH64_ABS32",
    1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT",
    1027: "R_AARCH64_RELATIVE",
    1028: "R_AARCH64_TLS_TPREL64",
    256: "R_AARCH64_NONE",
}


def load_img(nso_name):
    d = open(os.path.join(EXEFS, nso_name), "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    img = bytearray(segs[2][1] + segs[2][2] + bss)
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        img[mo:mo + sz] = raw
    return bytes(img), segs, bss


def main():
    nso = sys.argv[1]
    want = {int(x, 0) for x in sys.argv[2:]}
    img, segs, bss = load_img(nso)

    def rd(off, n):
        return img[off:off + n] if 0 <= off and off + n <= len(img) else None

    mod0 = struct.unpack_from("<I", img, 4)[0]
    disp = struct.unpack_from("<i", rd(mod0, 28), 4)[0]
    vals = {}
    for i in range(512):
        b = rd(mod0 + disp + i * 16, 16)
        if b is None:
            break
        tag, val = struct.unpack_from("<qQ", b, 0)
        if tag == 0:
            break
        vals[tag] = val
    symtab, strtab, strsz = vals[6], vals[5], vals[10]
    strs = rd(strtab, strsz)

    def symname(i):
        b = rd(symtab + i * 24, 24)
        if not b:
            return "?"
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        e = strs.find(b"\0", name)
        return strs[name:e].decode("ascii", "replace")

    # 所有 .rela 表（DT_RELA / DT_JMPREL）
    tables = []
    for off_tag, sz_tag, what in ((7, 8, "DT_RELA"), (23, 2, "DT_JMPREL")):
        o, s = vals.get(off_tag), vals.get(sz_tag)
        if o and s:
            tables.append((what, o, s))

    found = 0
    for what, o, s in tables:
        for i in range(s // 24):
            b = rd(o + i * 24, 24)
            if not b:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            if r_off in want:
                si, typ = r_info >> 32, r_info & 0xFFFFFFFF
                found += 1
                print("槽 %#x  (%s 第 %d 条)" % (r_off, what, i))
                print("   r_info: sym=%d  type=%d (%s)"
                      % (si, typ, TYPES.get(typ, "未知")))
                print("   addend=%#x   符号名=%r   符号值=%s"
                      % (r_add & 0xFFFFFFFFFFFFFFFF,
                         symname(si) if si else "(无符号)",
                         hex(struct.unpack_from("<Q", rd(symtab + si * 24 + 8, 8), 0)[0])
                         if si and rd(symtab + si * 24 + 8, 8) else "-"))
                want.discard(r_off)
    if want:
        print("这些槽在 .rela 里**没有条目**（靠别的方式初始化）：",
              [hex(x) for x in sorted(want)])


if __name__ == "__main__":
    main()
