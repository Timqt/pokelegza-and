#!/usr/bin/env python3
"""扫描客机 text 段里的「TLS 取值 helper」，并给出可改写的信息。

实测 helper 的机器码（text 偏移 0x87FC）：
    0x87FC: d53bd048   mrs  x8, TPIDR_EL0
    0x8800: f273c908   ubfm x8, x8, #51, #14      ; 等价于 ands x8, x8, #0xffffffffffffe000
    0x8804: 540000e0   b.eq  <慢路径>
    0x8808: f9404d09   ldr  x9, [x8, #0x98]       ; 模块 TLS 块偏移
    0x880C: b40000a9   cbz  x9, <慢路径>
    0x8810: 8b090d08   add  x8, x8, x9, lsl #3
    0x8814: f9400900   ldr  x0, [x8, #2]          ; 变量值（立即数 ×8 = 0x10）
    0x8818: b4000040   cbz  x0, <慢路径>
    0x881C: d65f03c0   ret

判据：mrs tpidr_el0 之后紧跟那条 ubfm（immr/imms 固定 51/14，只换寄存器）。
输出每个 helper 的：位置、入口指令、变量内偏移（立即数×8）。
"""
import collections
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = os.path.join(ROOT, "work", "nso", "text.bin")

d = open(TEXT, "rb").read()
n = len(d) // 4
words = list(struct.unpack_from("<%dI" % n, d, 0))

MRS = 0xD53BD040          # mrs Xt, TPIDR_EL0（Rt 变）
UBFM_E000 = 0xF273C800    # ubfm Xd, Xn, #51, #14（Rd/Rn 变；掩码后）


def is_mrs(w):
    return (w & 0xFFFFFFE0) == MRS


def is_ubfm_mask(w):
    return (w & 0xFFFFFC00) == UBFM_E000


hits = []
for i in range(n - 1):
    if not is_mrs(words[i]):
        continue
    if not is_ubfm_mask(words[i + 1]):
        continue
    # 从 i+2 起找：ldr [x?, #0x98]（描述符）与最后的 ldr（变量值）
    desc_at = var_at = None
    var_off = None
    for j in range(i + 2, min(i + 12, n)):
        w = words[j]
        if (w & 0xFFFFFC00) == 0xF9404C00:      # ldr Xt, [Xn, #0x13]（= 字节偏移 0x98）
            desc_at = j
            continue
        if desc_at is not None and (w & 0xFFC00000) == 0xF9400000:
            var_at = j
            var_off = ((w >> 10) & 0xFFF) * 8
            break
    if desc_at is None:
        continue
    hits.append((i * 4, (words[i] & 31), var_off, var_at * 4 if var_at else None))

print("TLS 取值 helper：%d 个" % len(hits))
c = collections.Counter(h[2] for h in hits)
print("变量内偏移分布（%s）：" % ", ".join("%#x×%d" % (k, v) for k, v in c.most_common(12)))
print("\n前 20 个：")
for off, rt, vo, va in hits[:20]:
    print("   text+%#x  mrs x%d  变量偏移=%s  末条ldr@%s" % (off, rt, ("%#x" % vo) if vo is not None else "?", ("%#x" % va) if va else "?"))

if hits:
    buckets = collections.Counter(off >> 16 for off, *_ in hits)
    print("\n分布：跨 %d 个 64KB 段" % len(buckets))
    for k in sorted(buckets)[:10]:
        print("   %#x0000..  %d 个" % (k, buckets[k]))
    # 改写可行性：helper 入口改成 b <stub>，需要 b 的 ±128MB 范围
    print("\n改写可行性（b 指令 ±128MB）：")
    for area in (0x6000000, 0x4000000, 0x2000000):
        lo, hi = area - (1 << 27), area + (1 << 27)
        ok = sum(1 for off, *_ in hits if lo <= off <= hi)
        print("   补丁区放 %#x：覆盖 %d/%d 个 helper" % (area, ok, len(hits)))
