# -*- coding: utf-8 -*-
"""调试：打印 SDK NSO 里某地址的原始指令字，以及 PLT 识别过程。"""
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
    print("seg%d memOff=%#x size=%#x rawlen=%#x" % (i, mo, sz, len(raw)))

dmo, dsz, _x = segd[2]
bss = struct.unpack_from("<I", d, 0x3C)[0]
IMG = bytearray(dmo + dsz + bss)
for mo, sz, raw in segd:
    IMG[mo:mo + sz] = raw

a = int(sys.argv[1], 0)
print("IMG len=%#x  text 末尾=%#x" % (len(IMG), segd[0][1]))
for k in range(6):
    w = struct.unpack_from("<I", bytes(IMG[a + k * 4:a + k * 4 + 4]), 0)[0]
    print("  %+#06x : %08x" % (k * 4, w))
