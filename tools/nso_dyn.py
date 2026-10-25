#!/usr/bin/env python3
"""列出 NSO 模块的动态符号（已定义 / 未定义）与段布局。

解析方式与 tools/gen_guest_headers.py 一致（权威）：
    image+4 的 u32 = MOD0 头偏移 → MOD0 头 +4 的位移 → .dynamic（Elf64_Dyn 数组）
    → DT_SYMTAB / DT_STRTAB / DT_RELA / DT_JMPREL

用法:
    python tools/nso_dyn.py work/base/exefs2/entry_32839457
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_nso(path):
    d = open(path, "rb").read()
    i = d.find(b"NSO0")
    if i < 0:
        return None
    flags = struct.unpack_from("<I", d, i + 0x0C)[0]
    segs = [struct.unpack_from("<III", d, i + 0x10 + k * 0x10) for k in range(3)]
    csz = struct.unpack_from("<III", d, i + 0x60)
    segd = []
    for k, (fo, mo, sz) in enumerate(segs):
        raw = d[i + fo:i + fo + csz[k]]
        if flags >> k & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        segd.append((mo, sz, raw))
    (tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = segd
    bss = struct.unpack_from("<I", d, i + 0x3C)[0]
    img = bytearray(dmo + dsz + bss)
    for mo, sz, raw in segd:
        img[mo:mo + sz] = raw
    return img, text, rodata, data, bss


def dynamic(img):
    def rd(off, n):
        if off < 0 or off + n > len(img):
            return None
        return bytes(img[off:off + n])
    mod0 = struct.unpack_from("<I", bytes(img[4:8]), 0)[0]
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
    return vals, rd


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        ROOT, "work", "base", "exefs2", "entry_32839457")
    r = load_nso(path)
    if not r:
        print("不是 NSO")
        return 1
    img, text, rodata, data, bss = r
    print("== %s" % path)
    print("   text=%#x rodata=%#x data=%#x bss=%#x  映像=%#x" %
          (len(text), len(rodata), len(data), bss, len(img)))
    vals, rd = dynamic(img)
    symtab, strtab, strsz = vals.get(6), vals.get(5), vals.get(10)
    if not symtab or not strtab:
        print("   没有动态符号表", vals)
        return 1
    nsym = (strtab - symtab) // 24
    strs = rd(strtab, strsz)

    def sym(k):
        b = rd(symtab + k * 24, 24)
        if not b:
            return None
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        value, size = struct.unpack_from("<QQ", b, 8)
        e = strs.find(b"\0", name)
        return (strs[name:e].decode("ascii", "replace"), info & 0xF, shndx, value, size)

    undef, defs = [], []
    for k in range(nsym):
        s = sym(k)
        if not s or not s[0]:
            continue
        (undef if s[2] == 0 else defs).append(s)

    # 导入（未定义符号）也可能通过 .rela/.jmprel 出现
    import_names = set(s[0] for s in undef)
    rels = []
    for tag_key, size_key, label in ((7, 8, "RELA"), (23, 2, "JMPREL")):
        off, size = vals.get(tag_key), vals.get(size_key)
        if not off or not size:
            continue
        for i in range(size // 24):
            b = rd(off + i * 24, 24)
            if not b:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            si = r_info >> 32
            s = sym(si)
            nm = s[0] if s else "?"
            rels.append((label, r_off, r_info & 0xFFFFFFFF, nm))
            if s and s[2] == 0:
                import_names.add(nm)

    print("   导出 %d 个；导入 %d 个" % (len(defs), len(import_names)))
    print("   --- 导出 ---")
    for s in defs:
        print("     %-56s val=%#x" % (s[0][:56], s[3]))
    print("   --- 导入（未定义）---")
    for nm in sorted(import_names):
        print("     %s" % nm[:90])
    print("   --- 重定位条目 %d 条（前 20）---" % len(rels))
    for r in rels[:20]:
        print("     %s off=%#x type=%d %s" % r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
