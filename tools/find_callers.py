#!/usr/bin/env python3
"""找客机里调用某个函数的全部位置（反查 `bl` 目标）。

用法: python tools/find_callers.py 0x24f20
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = os.path.join(ROOT, "work", "nso", "text.bin")

target = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x24F20

d = open(TEXT, "rb").read()
n = len(d) // 4
words = struct.unpack_from("<%dI" % n, d, 0)

hits = []
for i in range(n):
    w = words[i]
    if (w & 0xFC000000) == 0x94000000:          # BL imm26
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        dst = (i * 4) + (imm << 2)
        if dst == target:
            hits.append(i * 4)
    elif (w & 0xFC000000) == 0x14000000:        # B imm26
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        dst = (i * 4) + (imm << 2)
        if dst == target:
            hits.append(i * 4)

print("调用 %s 的位置 %d 处：" % (hex(target), len(hits)))
for off in hits:
    ctx = []
    for k in range(-6, 7):
        j = off // 4 + k
        if 0 <= j < n:
            ctx.append("%+d:%08x" % (k * 4, words[j]))
    print("  text+%#x  %s" % (off, " ".join(ctx)))
