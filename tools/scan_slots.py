#!/usr/bin/env python3
"""扫 SDK text  0xb74000 页的槽用法（adrp xN,0xb74000 / ldr xM,[xN,#imm]）。"""
import struct, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
blob = open(TEXT, "rb").read()
n = len(blob) // 4
w = struct.unpack_from("<%dI" % n, blob, 0)

PAGE = 0xb74000
hits = {}
for i in range(n - 1):
    w0 = w[i]
    if (w0 & 0x9F000000) != 0x90000000:     # ADRP
        continue
    rd = w0 & 0x1F
    imm = ((w0 >> 5) & 0x7FFFF) << 12
    if (w0 >> 31):
        imm -= 1 << 33
    page = (i * 4 & ~0xFFF) + imm
    if page != PAGE:
        continue
    # 往后找 6 条指令里的 ldr/str [xN,#imm]
    for j in range(1, 7):
        if i + j >= n:
            break
        wj = w[i + j]
        if (wj & 0xFFC00000) != 0xF9400000 and (wj & 0xFFC00000) != 0xF9000000:
            continue
        rn = (wj >> 5) & 0x1F
        if rn != rd:
            continue
        off = ((wj >> 10) & 0xFFF) * 8
        op = "ldr" if (wj & 0xFFC00000) == 0xF9400000 else "str"
        hits.setdefault(off, []).append((i * 4, op))

for off in sorted(hits):
    lst = hits[off]
    if off in (0x120, 0x128, 0x130, 0x78, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0):
        print("=== 槽 0xb%05x （+%#x） %d 处 ===" % (PAGE + off, off, len(lst)))
        for at, op in lst[:14]:
            print("   %#08x %s [x%d,#%#x]" % (at, op, rd if False else 0, off))
