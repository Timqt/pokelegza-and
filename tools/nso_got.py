#!/usr/bin/env python3
"""在 .data / .rodata 里找「指向 text 段的 0x140000000+偏移」的密集表（GOT 或 api_info）。"""
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

for seg_name, blob, seg_off in (("data", data, dmo), ("rodata", rodata, rmo)):
    hits = []
    for off in range(0, len(blob) - 8, 8):
        v = struct.unpack_from("<Q", blob, off)[0]
        if BASE <= v < BASE + tsz:
            hits.append((off, v - BASE))
    print("[%s] 指向 text 的指针 %d 个" % (seg_name, len(hits)))
    if not hits:
        continue
    # 密集区
    runs = []
    for h in hits:
        if runs and h[0] == runs[-1][-1][0] + 8:
            runs[-1].append(h)
        else:
            runs.append([h])
    runs.sort(key=len, reverse=True)
    for r in runs[:3]:
        print("   连续 %d 条 @段内 %#x（映像内 %#x）" % (len(r), r[0][0], seg_off + r[0][0]))
        for off, t in r[:6]:
            print("      段内+%#x → text+%#x" % (off, t))
    if runs:
        r = runs[0]
        # 打印这块表前面的若干 u32（可能是名字偏移/标志）
        st = r[0][0]
        print("   表前 48 字节：")
        base = max(0, st - 48)
        for k in range(0, 48, 4):
            v = struct.unpack_from("<I", blob, base + k)[0]
            print("      +%#x: %d (%#x)" % (base + k - st, v, v))
