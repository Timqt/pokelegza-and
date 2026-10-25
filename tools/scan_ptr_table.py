# -*- coding: utf-8 -*-
"""在 SDK 映像里搜索 8 字节小端地址，列出命中位置及其邻近表项（函数指针表）。

用法:
    python tools/scan_ptr_table.py 0x14dd50
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
BLOB = bytes(IMG)

target = int(sys.argv[1], 0)
needle = struct.pack("<Q", target)
print("searching %s in %d bytes" % (hex(target), len(BLOB)))

pos = 0
hits = []
while True:
    i = BLOB.find(needle, pos)
    if i < 0:
        break
    hits.append(i)
    pos = i + 1

print("hit %d" % len(hits))
for h in hits:
    print("\n=== offset %#x (%s) ===" % (
        h,
        "rodata" if 0x64f000 <= h < 0xb3b000 else
        "data" if 0xb3b000 <= h < 0xb8f4e0 else
        "text" if h < 0x64e230 else "bss"))
    lo = max(0, (h - 0x40) & ~7)
    for off in range(lo, min(len(BLOB) - 8, h + 0x48), 8):
        v = struct.unpack_from("<Q", BLOB, off)[0]
        mark = " <== target" if off == h else ""
        if 0x10000 < v < 0x64e230:
            print("   %#010x: %#018x  (text+?)%s" % (off, v, mark))
        else:
            print("   %#010x: %#018x%s" % (off, v, mark))
