#!/usr/bin/env python3
"""统计 .text 里 bl 的目标分布，找「每个只被调用一次」的聚集区 = 导入桩。"""
import os, struct, sys, collections
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

d = open(NSO, "rb").read()
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
raw = d[segs[0][0]:segs[0][0] + csz[0]]
if flags & 1:
    raw = lz4.block.decompress(raw, uncompressed_size=segs[0][2])
text = raw
n = len(text) // 4
words = struct.unpack_from("<%dI" % n, text, 0)

targets = collections.Counter()
for i in range(n):
    w = words[i]
    if (w >> 26) == 0x25:          # BL
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        targets[(i * 4 + imm * 4) & 0xFFFFFFFF] += 1

print("text %d 字节，bl 目标 %d 个不同" % (len(text), len(targets)))
once = [t for t, c in targets.items() if c == 1]
print("只被调用一次的 bl 目标：%d 个" % len(once))
once.sort()
# 找这些目标地址的聚集（连续 12 字节一个桩）
runs = []
cur = [once[0]]
for t in once[1:]:
    if t - cur[-1] <= 16:
        cur.append(t)
    else:
        runs.append(cur); cur = [t]
runs.append(cur)
runs.sort(key=len, reverse=True)
print("最大聚集：%d 个桩，地址 %#x..%#x" % (len(runs[0]), runs[0][0], runs[0][-1]))
for r in runs[:3]:
    print("  聚集 %d 个，%#x..%#x" % (len(r), r[0], r[-1]))
# 每个聚集里的桩间隔
if len(runs[0]) > 2:
    gaps = collections.Counter(b - a for a, b in zip(runs[0], runs[0][1:]))
    print("  桩间隔分布:", gaps.most_common(5))
