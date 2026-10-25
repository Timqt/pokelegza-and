# -*- coding: utf-8 -*-
"""在 SDK NSO 的动态符号表里按名字查符号（子串匹配）。

用法:
    python tools/sdk_sym_named.py _init_libc
    python tools/sdk_sym_named.py nninit nnosInitialize
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
dmo, dsz, _d = segd[2]
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

pats = sys.argv[1:] or ["_init_libc"]
print("dynsym %d 条，匹配 %s" % (nsym, pats))
n = 0
for i in range(nsym):
    b = rd(symtab + i * 24, 24)
    if not b:
        break
    name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
    value, size = struct.unpack_from("<QQ", b, 8)
    e = strs.find(b"\0", name)
    s = strs[name:e].decode("ascii", "replace")
    if any(p in s for p in pats):
        print("   [%d] %-64s value=%#x size=%#x bind=%d type=%d shndx=%d"
              % (i, s[:64], value, size, info & 0xF, (info >> 4) & 3, shndx))
        n += 1
print("命中 %d 条" % n)
