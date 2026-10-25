#!/usr/bin/env python3
"""扫 .text 里的导入桩三连：adr/adrp xA ; ldr xB,[xA,#off] ; br xB。

命中数应与导入数（1001）同量级。
"""
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

def is_adr(w):  return (w & 0x9F000000) == 0x10000000
def is_adrp(w): return (w & 0x9F000000) == 0x90000000
def is_ldr64(w):return (w & 0xFFC00000) == 0xF9400000
def is_br(w):   return (w & 0xFFFFFC1F) == 0xD61F0000
def is_blr(w):  return (w & 0xFFFFFC1F) == 0xD63F0000

hits = []
for i in range(n - 2):
    w0, w1, w2 = words[i], words[i + 1], words[i + 2]
    if not (is_adr(w0) or is_adrp(w0)):
        continue
    if not is_ldr64(w1):
        continue
    rn = (w1 >> 5) & 0x1F
    rt = w1 & 0x1F
    if rn != (w0 & 0x1F):
        continue
    if not (is_br(w2) and (w2 & 0x1F) == rt):
        continue
    hits.append((i * 4, rn, rt, (w1 >> 10) & 0xFFF))

print("三连命中：%d" % len(hits))
if hits:
    # 聚集
    runs = []
    cur = [hits[0]]
    for h in hits[1:]:
        if h[0] - cur[-1][0] <= 32:
            cur.append(h)
        else:
            runs.append(cur); cur = [h]
    runs.append(cur); runs.sort(key=len, reverse=True)
    print("最大聚集 %d 个 @%#x" % (len(runs[0]), runs[0][0][0]))
    for r in runs[:3]:
        print("  聚集 %d 个：%#x .. %#x" % (len(r), r[0][0], r[-1][0]))
    # 每个聚集里算一下 adrp/adr 的目标页是否都落在 data 段
    for r in runs[:2]:
        pages = collections.Counter()
        for off, rn, rt, imm in r[:2000]:
            w0 = words[off // 4]
            if is_adrp(w0):
                immlo = (w0 >> 29) & 3
                immhi = (w0 >> 5) & 0x7FFFF
                page = (((immhi << 2) | immlo) << 12) + (off & ~0xFFF)
            else:
                immlo = (w0 >> 29) & 3
                immhi = (w0 >> 5) & 0x7FFFF
                page = ((immhi << 2) | immlo) + off
            pages[page] += 1
        print("  聚集的目标页 top5:", [(hex(p), c) for p, c in pages.most_common(5)])
