#!/usr/bin/env python3
"""在某个 NSO 的**导出符号**（已定义符号）里按关键字查名字。

用法: python tools/grep_sdk_exports.py malloc
      python tools/grep_sdk_exports.py "nn::os" --nso entry_0

为什么需要它：移植时「客机的 malloc 该由谁提供」取决于**模块导出表里有没有它**
（上游是模块导出表优先；本工程原来是 dlsym 优先，落到 bionic 的 malloc）。
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEFS = os.path.join(ROOT, "work", "base", "exefs2")


def load(nso_name):
    d = open(os.path.join(EXEFS, nso_name), "rb").read()
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
    img = bytearray(dmo + dsz + bss)
    for mo, sz, raw in segd:
        img[mo:mo + sz] = raw
    return bytes(img)


def exports(nso_name):
    img = load(nso_name)

    def rd(off, n):
        return bytes(img[off:off + n]) if 0 <= off and off + n <= len(img) else None

    mod0 = struct.unpack_from("<I", img, 4)[0]
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
    out = []
    for i in range(nsym):
        b = rd(symtab + i * 24, 24)
        if not b:
            continue
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        value, size = struct.unpack_from("<QQ", b, 8)
        if not shndx:
            continue
        e = strs.find(b"\0", name)
        out.append((strs[name:e].decode("ascii", "replace"), value))
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    pat = args[0] if args else "malloc"
    nso = "entry_32848007"
    for a in sys.argv[1:]:
        if a.startswith("--nso="):
            nso = a.split("=", 1)[1]
    ex = exports(nso)
    hit = [(n, v) for n, v in ex if pat in n]
    print("%s 导出符号 %d 个，匹配 %r 的 %d 个：" % (nso, len(ex), pat, len(hit)))
    for n, v in sorted(hit):
        print("   %#010x  %s" % (v, n))


if __name__ == "__main__":
    main()
