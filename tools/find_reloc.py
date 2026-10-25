# -*- coding: utf-8 -*-
"""查 SDK 重定位表里某个槽的条目。

用法:
    python tools/find_reloc.py 0xbac9f0
    python tools/find_reloc.py --near 0xbac9f0 0x40   # 查附近一段
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELS = os.path.join(ROOT, "work", "nso_sdk", "sdk_relocs.bin")

rel = open(RELS, "rb").read()
n = struct.unpack_from("<I", rel, 0)[0]
print("重定位 %d 条" % n)

if sys.argv[1] == "--near":
    lo = int(sys.argv[2], 0)
    hi = lo + int(sys.argv[3], 0)
else:
    lo = int(sys.argv[1], 0)
    hi = lo + 1

for i in range(n):
    slot, kind, sym, add = struct.unpack_from("<IIII", rel, 4 + i * 16)
    if lo <= slot < hi:
        print("  [%d] slot=%#x kind=%d sym=%d add=%#x" % (i, slot, kind, sym, add))
