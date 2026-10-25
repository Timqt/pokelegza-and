#!/usr/bin/env python3
"""查 main NSO 的 .data 里「0x1xxxxxxx」指针：它们指向 main 自己还是 SDK？

跨模块指针决定了两个模块的基址怎么安排：
- main 必须在 0x100000000（SDK 反过来引用它）；
- 如果 main 也用 0x1xxxxxxx 指向 SDK，那 SDK 的基址也是写死的 ⇒ 两个模块不能同址。
"""
import collections
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_DATA = os.path.join(ROOT, "work", "nso", "data.bin")
MAIN_IMG = 0x5F7B000
SDK_IMG = 0xC5E000

d = open(MAIN_DATA, "rb").read()
hits = []
for off in range(0, len(d) - 7, 8):
    v = struct.unpack_from("<Q", d, off)[0]
    if 0x100000000 <= v < 0x200000000:
        hits.append((0x39E1000 + off, v))

print("main .data 里的 0x1xxxxxxx 指针 %d 个" % len(hits))
c = collections.Counter()
for off, v in hits:
    rel = v - 0x100000000
    tag = "main 自己范围" if rel < MAIN_IMG else "其它"
    c[tag] += 1
print("   %s" % dict(c))
print("   样例：")
for off, v in hits[:10]:
    rel = v - 0x100000000
    print("      映像%#x -> %#x  相对=%#x %s" % (off, v, rel, "(main 内)" if rel < MAIN_IMG else ""))

# 这些值的分布：相对偏移落在 main 的哪一段
segs = collections.Counter()
for off, v in hits:
    rel = v - 0x100000000
    if rel < 0x2FC7250:
        segs["main.text"] += 1
    elif rel < 0x39E1000:
        segs["main.rodata"] += 1
    elif rel < 0x39E1000 + 0x39E1C0:
        segs["main.data"] += 1
    elif rel < MAIN_IMG:
        segs["main.bss"] += 1
    else:
        segs["不在 main 内"] += 1
print("   落点分布: %s" % dict(segs))
