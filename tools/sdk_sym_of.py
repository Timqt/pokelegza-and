# -*- coding: utf-8 -*-
"""把若干 SDK 偏移翻译成符号名（精确命中或包含该地址的符号）。

用法:
    python tools/sdk_sym_of.py 0x147cf0 0x142248 ...
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")

d = open(NSO, "rb").read()
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
segd = []
for i, (fo, mo, sz) in enumerate(segs):
    raw = d[fo:fo + csz[i]]
    if flags >> i & 1:
        raw = lz4.block.decompress(raw, uncompressed_size=sz)
    segd.append((mo, sz, raw))
dmo, dsz, _x = segd[2]
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
syms = []
for i in range(nsym):
    b = rd(symtab + i * 24, 24)
    if not b:
        break
    name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
    value, size = struct.unpack_from("<QQ", b, 8)
    e = strs.find(b"\0", name)
    syms.append((strs[name:e].decode("ascii", "replace"), value, size))

bysize = sorted(syms, key=lambda s: s[1])

for x in sys.argv[1:]:
    a = int(x, 0)
    exact = [s for s in syms if s[1] == a]
    if exact:
        for nm, v, sz in exact:
            print("%#010x  = %s  (size=%#x)" % (a, nm, sz))
        continue
    # 包含该地址的最大符号
    best = None
    for nm, v, sz in bysize:
        if v <= a and (v + max(sz, 1)) > a:
            if best is None or v > best[1]:
                best = (nm, v, sz)
    if best:
        print("%#010x  in %s  (base=%#x size=%#x, +%#x)"
              % (a, best[0], best[1], best[2], a - best[1]))
    else:
        print("%#010x  (no symbol)" % a)
