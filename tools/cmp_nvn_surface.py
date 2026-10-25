#!/usr/bin/env python3
"""对比 Z-A 与 D2R 的 NVN 调用面：Z-A 用到哪些 nvn* 名字，D2R 实现了哪些。

这是判断「现成的 NVN HLE 层够不够」的最直接指标。
"""
import re
import struct
from pathlib import Path

import lz4.block

NSO = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\base\exefs2\entry_0")
D2R_NAMES = Path(r"D:\feiniukexinhome\Code\d2r-and\repo\d2r-android-public\upstream\dm\gfx\nvn\names.txt")
D2R_SLOTS = Path(r"D:\feiniukexinhome\Code\d2r-and\repo\d2r-android-public\upstream\dm\gfx\nvn\nvn_slots.tsv")

d = NSO.read_bytes()
text_off, _, text_size = struct.unpack_from("<III", d, 0x10)
ro_off, _, ro_size = struct.unpack_from("<III", d, 0x20)
tfs, rfs, _ = struct.unpack_from("<III", d, 0x60)
rodata = lz4.block.decompress(d[ro_off:ro_off + rfs], uncompressed_size=ro_size)

# .rodata 里的全部 nvn* 字符串（游戏按名字取址的都在这）
za_nvn = sorted(set(m.decode() for m in re.findall(rb"nvn[A-Za-z0-9_]{2,60}", rodata)))

d2r_all = set()
for line in D2R_NAMES.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if line and not line.startswith("#"):
        d2r_all.add(line.split()[0])

d2r_slots = set()
for line in D2R_SLOTS.read_text(encoding="utf-8", errors="replace").splitlines():
    if line.strip() and not line.startswith("#"):
        parts = line.split("\t")
        if len(parts) > 1:
            d2r_slots.add(parts[0].strip())

print(f"Z-A .rodata 里的 nvn* 名字: {len(za_nvn)}")
print(f"D2R names.txt（Ryujinx 全表）: {len(d2r_all)}")
print(f"D2R nvn_slots.tsv（游戏真有调用点的）: {len(d2r_slots)}")

covered = [n for n in za_nvn if n in d2r_slots]
missing = [n for n in za_nvn if n not in d2r_slots]
unknown = [n for n in za_nvn if n not in d2r_all]
print(f"\nZ-A 用到、且 D2R 也用到（有调用点）: {len(covered)}")
print(f"Z-A 用到、D2R 没调用过（可能是新特性）: {len(missing)}")
print(f"Z-A 用到、D2R 的名字表里完全没有: {len(unknown)}")

if missing:
    print("\n--- D2R 没实现过的 Z-A NVN 特性 ---")
    for n in missing:
        print("   ", n)
if unknown:
    print("\n--- D2R 名字表里没有的 Z-A NVN 名字（Ryujinx 也未必有）---")
    for n in unknown:
        print("   ", n)
