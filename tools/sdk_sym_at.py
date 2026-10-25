# -*- coding: utf-8 -*-
"""在 SDK NSO 的动态符号表里，查找 st_value 落在给定偏移范围的符号。

用途：SDK 里 0x9c510..0x9c560 是一串跳板（PLT/弱符号桩），其中 0x9c560
执行 `svc #0x26` (Break)。想知道它对应哪个导入符号，就查它的 st_value。

用法:
    python tools/sdk_sym_at.py 0x9c560
    python tools/sdk_sym_at.py 0x9c510 0x9c570      # 区间
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
(dmo, dsz, _data) = segd[2]
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
    syms.append((i, strs[name:e].decode("ascii", "replace"), info & 0xF,
                 (info >> 4) & 3, shndx, value, size))

lo = int(sys.argv[1], 0)
hi = int(sys.argv[2], 0) if len(sys.argv) > 2 else lo + 1

print("dynsym 共 %d 条，查询 value in [%#x, %#x)" % (len(syms), lo, hi))
for i, name, bind, typ, shndx, value, size in syms:
    if lo <= value < hi:
        print("   [%d] %-60s value=%#x size=%#x bind=%d type=%d shndx=%d"
              % (i, name[:60], value, size, bind, typ, shndx))

print("\n所有 st_value != 0 且落在 text 段 (< %#x) 的符号（前 80 个）:" % 0x64e230)
cnt = 0
for i, name, bind, typ, shndx, value, size in syms:
    if 0 < value < 0x64e230:
        print("   [%d] %-60s value=%#x size=%#x" % (i, name[:60], value, size))
        cnt += 1
        if cnt >= 80:
            break
