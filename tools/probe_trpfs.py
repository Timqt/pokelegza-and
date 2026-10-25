#!/usr/bin/env python3
"""TRPFS 结构探针：不用猜，直接用 TRPFD 的哈希数组做指纹在 data.trpfs 里反查。"""

import mmap
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from onepack import Trpfd  # noqa: E402

trpfs = sys.argv[1]
trpfd = sys.argv[2]

tfd = Trpfd(trpfd)
hashes = tfd.file_hashes
n = len(hashes)
print("TRPFD file_hashes: %d" % n)
print("  first 4: %s" % ["%016x" % h for h in hashes[:4]])

f = open(trpfs, "rb")
size = os.path.getsize(trpfs)
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

# 1) 用前 16 字节做指纹找位置
fp = struct.pack("<4Q", *hashes[:4])
pos = 0
hits = []
while True:
    i = mm.find(fp, pos)
    if i < 0:
        break
    hits.append(i)
    pos = i + 1
    if len(hits) > 20:
        break
print("指纹命中: %s" % hits)

for h in hits:
    if h + 8 * n > size:
        print("  @%d 越界（数组放不下 %d 项）" % (h, n))
        continue
    ok = True
    for idx in (0, 1, 2, 100, 1000, 50000, n - 1):
        v = struct.unpack_from("<Q", mm, h + 8 * idx)[0]
        if v != hashes[idx]:
            ok = False
            break
    print("  @%d 数组校验 %s" % (h, "OK" if ok else "不符"))
    if ok:
        print("  ==> hashes 向量位于文件偏移 %d (0x%x)" % (h, h))
        # 2) 找紧邻的 file_offsets 数组（先看数组之后 / 之前）
        for probe in (h + 8 * n, h - 8 * n, h - 16, h + 8 * n + 8):
            if probe < 0 or probe + 8 * n > size:
                continue
            vals = struct.unpack_from("<8Q", mm, probe)
            inc = all(vals[i] <= vals[i + 1] for i in range(7))
            print("     邻居 @%d (0x%x): %s 递增=%s"
                  % (probe, probe, ["%d" % v for v in vals], inc))

# 3) 扫文件末尾 1MB 内是否有 u64 递增数组的起点（offset 起点应是文件内小偏移）
tail = size - (1 << 20)
print("--- 尾部 1MB 扫描：寻找 length=178109 的 u64 向量头 ---")
for off in range(tail, size - 16, 4):
    cnt = struct.unpack_from("<I", mm, off)[0]
    if cnt == n:
        v0 = struct.unpack_from("<Q", mm, off + 4)[0]
        print("  @%d (0x%x) count=%d 首个值=%d" % (off, off, cnt, v0))
mm.close()
f.close()
