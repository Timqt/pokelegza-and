#!/usr/bin/env python3
"""查 SDK NSO 里「0x1xxxxxxx」形态的指针：它们指向 main 模块还是 SDK 自己？

这决定两个模块的基址能不能都是 0x100000000（不能重合）。
"""
import os
import struct
import collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_DIR = os.path.join(ROOT, "work", "nso_32848007")
SDK_TEXT, SDK_RO, SDK_DATA = 0x0, 0x64F000, 0xB3B000
SDK_IMG = 0xC5E000
MAIN_IMG = 0x5F7B000

d = open(os.path.join(SDK_DIR, "data.bin"), "rb").read()
hits = []
for off in range(0, len(d) - 7, 8):
    v = struct.unpack_from("<Q", d, off)[0]
    if 0x100000000 <= v < 0x200000000:
        hits.append((SDK_DATA + off, v))

print("SDK .data 里的 0x1xxxxxxx 指针 %d 个：" % len(hits))
c = collections.Counter()
for off, v in hits:
    rel = v - 0x100000000
    tag = "main 模块范围" if rel < MAIN_IMG else ("SDK 自己范围" if rel < SDK_IMG else "超出两者")
    c[tag] += 1
print("   %s" % dict(c))
for off, v in hits[:12]:
    print("   映像%#x -> %#x  (相对 0x100000000 = %#x)" % (off, v, v - 0x100000000))

# SDK 的 text 里有没有硬编码 0x100000000（movz/movk 序列或 literal）
text = open(os.path.join(SDK_DIR, "text.bin"), "rb").read()
cnt = 0
pat = struct.pack("<Q", 0x100000000)
pos = 0
while True:
    i = text.find(pat, pos)
    if i < 0:
        break
    cnt += 1
    if cnt <= 6:
        print("   text+%#x 存着字面量 0x100000000" % i)
    pos = i + 1
print("SDK .text 里的 0x100000000 字面量: %d 处" % cnt)

# main 的 text 里同样查（对照）
mtext = open(os.path.join(ROOT, "work", "nso", "text.bin"), "rb").read()
cnt2 = mtext.count(pat)
print("main .text 里的 0x100000000 字面量: %d 处" % cnt2)
