#!/usr/bin/env python3
"""按「导入名在 dynstr 里的偏移」定位导入表：全段扫 4 字节对齐的 u32，
看哪个值命中导入名集合，再看它前后的字段（桩地址/标志）。"""
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

DYNSTR_OFF, DYNSTR_SZ = struct.unpack_from("<II", d, 0x90)
DYNSYM_OFF, DYNSYM_SZ = struct.unpack_from("<II", d, 0x98)
strs = rodata[DYNSTR_OFF:DYNSTR_OFF + DYNSTR_SZ]
syms = rodata[DYNSYM_OFF:DYNSYM_OFF + DYNSYM_SZ]

def name_at(off):
    if off >= len(strs):
        return None
    e = strs.find(b"\0", off)
    s = strs[off:e]
    if not s or len(s) > 200:
        return None
    try:
        t = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(32 <= ord(c) < 127 for c in t) else None

imports = {}
for i in range(len(syms) // 24):
    name, info, other, shndx = struct.unpack_from("<IBBH", syms, i * 24)
    if shndx == 0:
        n = name_at(name)
        if n:
            imports[name] = name      # 名字 -> dynstr 偏移
offsets = set(imports.values())
print("导入 %d 个，dynstr 偏移集合 %d 个" % (len(imports), len(offsets)))

for seg_name, blob, seg_off in (("rodata", rodata, rmo), ("data", data, dmo), ("text", text, tmo)):
    hits = []
    for off in range(0, len(blob) - 4, 4):
        v = struct.unpack_from("<I", blob, off)[0]
        if v in offsets:
            hits.append(off)
    print("\n[%s] 命中 %d 处" % (seg_name, len(hits)))
    if not hits:
        continue
    # 找连续段（步长 4/8/12/16）
    for stride in (4, 8, 12, 16):
        runs = []
        for h in hits:
            if runs and h == runs[-1][-1] + stride:
                runs[-1].append(h)
            else:
                runs.append([h])
        runs.sort(key=len, reverse=True)
        if runs and len(runs[0]) >= 30:
            r = runs[0]
            print("  步长 %d 连续 %d 条，起点 %#x（段内）" % (stride, len(r), r[0]))
            for h in r[:5]:
                nameoff = struct.unpack_from("<I", blob, h)[0]
                pre = struct.unpack_from("<Q", blob, max(0, h - 8))[0] if h >= 8 else 0
                post = struct.unpack_from("<Q", blob, h + 4)[0] if h + 12 <= len(blob) else 0
                print("     off=%#x nameoff=%#x %s | 前8=%#x 后8=%#x" % (h, nameoff, name_at(nameoff), pre, post))
            break
