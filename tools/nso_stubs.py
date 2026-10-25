#!/usr/bin/env python3
"""在 rodata / data / text 里找 NSO 的导入桩表。

强约束：记录里的名字必须正好是 dynsym 中的某个导入名（1001 个之一），
这样可以排除巧合匹配。尝试多种记录布局。
"""
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
            imports.setdefault(n, name)   # 名字 -> dynstr 偏移
print("导入名 %d 个，dynstr 长度 %#x" % (len(imports), DYNSTR_SZ))

def scan(blob, blob_name):
    """扫 16 字节记录，两种字段顺序。"""
    found = {}
    for off in range(0, len(blob) - 16, 4):
        a, b = struct.unpack_from("<II", blob, off)
        c, e = struct.unpack_from("<II", blob, off + 8)
        # 布局1: {u32 nameoff, u32 pad, u64 stub}
        if a in imports.values() and BASE <= c < BASE + tsz:
            found.setdefault((1, off), (c, a))
        # 布局2: {u64 stub, u32 nameoff, u32 flags}
        if b in imports.values() and BASE <= a < BASE + tsz:
            found.setdefault((2, off), (a, b))
    return found

for blob, blob_name in ((rodata, "rodata"), (data, "data")):
    hits = scan(blob, blob_name)
    if not hits:
        print("[%s] 无命中" % blob_name)
        continue
    print("\n[%s] 命中 %d" % (blob_name, len(hits)))
    # 连续段
    byoff = collections.defaultdict(list)
    for (lay, off), (stub, noff) in hits.items():
        byoff[lay].append((off, stub, noff))
    for lay, lst in byoff.items():
        lst.sort()
        runs = []
        for item in lst:
            if runs and item[0] == runs[-1][-1][0] + 16:
                runs[-1].append(item)
            else:
                runs.append([item])
        runs.sort(key=len, reverse=True)
        for r in runs[:2]:
            print("  布局%d 连续 %d 条 @%#x" % (lay, len(r), r[0][0]))
            for off, stub, noff in r[:8]:
                print("     stub=%#x  %s" % (stub, name_at(noff)))
