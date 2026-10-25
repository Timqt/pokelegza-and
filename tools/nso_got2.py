#!/usr/bin/env python3
"""GOT 可能是 32 位 text 偏移：按 4 字节粒度扫 .data / .rodata 里的稠密小值区。"""
import os, struct, sys, collections
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")
BASE = 0x140000000

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
(tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = segd

def dense4(blob, name):
    """找 4 字节值都落在 text 范围内的连续区。"""
    hits = []
    for off in range(0, len(blob) - 4, 4):
        v = struct.unpack_from("<I", blob, off)[0]
        if v < tsz:
            hits.append(off)
    if not hits:
        print("[%s] 没有 4 字节 text 偏移" % name)
        return
    runs = []
    for h in hits:
        if runs and h == runs[-1][-1] + 4:
            runs[-1].append(h)
        else:
            runs.append([h])
    runs.sort(key=len, reverse=True)
    print("[%s] 4 字节 text 偏移命中 %d，最长连续 %d" % (name, len(hits), len(runs[0])))
    for r in runs[:3]:
        vals = [struct.unpack_from("<I", blob, o)[0] for o in r[:8]]
        print("   连续 %d 条 @%#x（段内）  值: %s" % (len(r), r[0], ", ".join("%#x" % v for v in vals)))

dense4(data, "data")
dense4(rodata, "rodata")

# 再看 .data 里 8 字节对齐、值也像 text 偏移的表
print("\n--- .data 里 8 字节步进的小值区（<0x100000）---")
runs = []
cur = []
for off in range(0, len(data) - 8, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    if v < 0x100000:
        cur.append(off)
    else:
        if len(cur) > 8:
            runs.append(cur)
        cur = []
if len(cur) > 8:
    runs.append(cur)
runs.sort(key=len, reverse=True)
for r in runs[:3]:
    vals = [struct.unpack_from("<Q", data, o)[0] for o in r[:8]]
    print("   连续 %d 条 @%#x  值: %s" % (len(r), r[0], ", ".join("%#x" % v for v in vals)))
