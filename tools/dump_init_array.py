#!/usr/bin/env python3
"""dump NSO 的 .init_array 原始内容 + 若干关键指针，判断客机映像的寻址方式。

要回答的问题：init_array 里存的是「模块内偏移」还是「绝对虚拟地址」？
  - 若是模块内偏移 → 装载时必须 base + value（而且这些槽没有重定位覆盖）
  - 若是绝对地址（0x1xxxxxxxx）→ 映像必须装在固定基址
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

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
bss = struct.unpack_from("<I", d, 0x3C)[0]
IMG = bytearray(dmo + dsz + bss)
for mo, sz, raw in segd:
    IMG[mo:mo + sz] = raw


def rd(off, n):
    if off < 0 or off + n > len(IMG):
        return None
    return bytes(IMG[off:off + n])


mod0 = struct.unpack_from("<I", bytes(IMG[4:8]), 0)[0]
disp = struct.unpack_from("<i", rd(mod0, 28), 4)[0]
dyn = mod0 + disp
vals = {}
for i in range(512):
    b = rd(dyn + i * 16, 16)
    if b is None:
        break
    tag, val = struct.unpack_from("<qQ", b, 0)
    if tag == 0:
        break
    vals[tag] = val

print("段: text %#x+%#x  rodata %#x+%#x  data %#x+%#x  bss %#x" %
      (tmo, tsz, rmo, rsz, dmo, dsz, bss))
print("DT_INIT=%#x DT_INIT_ARRAY=%#x DT_INIT_ARRAYSZ=%#x DT_FINI_ARRAY=%#x" %
      (vals.get(12, 0), vals.get(25, 0), vals.get(27, 0), vals.get(26, 0)))

ia = vals.get(25, 0)
isz = vals.get(27, 0)
if ia and isz:
    n = isz // 8
    print("\n.init_array %d 项，前 12 项原始值：" % n)
    vals_list = []
    for i in range(n):
        v = struct.unpack_from("<Q", bytes(rd(ia + i * 8, 8)), 0)[0]
        vals_list.append(v)
    for i, v in enumerate(vals_list[:12]):
        print("   [%3d] %#018x" % (i, v))
    # 统计：这些值落在哪个区间
    buckets = {"0（空）": 0, "<0x100000000（模块内偏移）": 0,
               "0x100000000~0x1ffffffff（Switch 固定基址）": 0,
               ">=0x200000000（其它）": 0}
    for v in vals_list:
        if v == 0:
            buckets["0（空）"] += 1
        elif v < 0x100000000:
            buckets["<0x100000000（模块内偏移）"] += 1
        elif v < 0x200000000:
            buckets["0x100000000~0x1ffffffff（Switch 固定基址）"] += 1
        else:
            buckets[">=0x200000000（其它）"] += 1
    print("\n分布：%s" % buckets)
    nz = [v for v in vals_list if v]
    if nz:
        print("非零项范围: %#x .. %#x" % (min(nz), max(nz)))

# .dynamic 里有没有「已经带绝对地址」的字段
print("\n.dynamic 关键项：")
for tag, name in ((1, "NEEDED"), (2, "PLTRELSZ"), (3, "PLTGOT"), (5, "STRTAB"),
                  (6, "SYMTAB"), (7, "RELA"), (8, "RELASZ"), (12, "INIT"),
                  (13, "FINI"), (25, "INIT_ARRAY"), (26, "FINI_ARRAY"), (27, "INIT_ARRAYSZ")):
    if tag in vals:
        print("   %-12s %#x" % (name, vals[tag]))
