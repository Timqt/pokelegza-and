#!/usr/bin/env python3
"""在 NSO 的 .text 里找导入桩（PLT），解出每个桩用的 GOT 槽地址。

桩的形状（aarch64）：
    adrp  xN, page        0x9000_0000 | (immhi<<5) | (immlo<<29) | N
    ldr   xN, [xN, #off]  0xF940_0000 | (imm12<<10) | N<<5 | N
    br    xN              0xD61F_0000 | N
GOT 槽 = (page + off) - 0x140000000   ← 换成映像内偏移
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

def sign_ext(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m

def decode_stub(off):
    """off 指向 adrp。返回 (GOT绝对地址, 寄存器) 或 None。"""
    if off + 12 > len(text):
        return None
    w0, w1, w2 = struct.unpack_from("<III", text, off)
    if w0 & 0x9F000000 != 0x90000000:
        return None
    rd = w0 & 0x1F
    immlo = (w0 >> 29) & 0x3
    immhi = (w0 >> 5) & 0x7FFFF
    page = (sign_ext((immhi << 2) | immlo, 21) << 12)
    if w1 & 0xFFC00000 != 0xF9400000:
        return None
    if (w1 >> 5) & 0x1F != rd or (w1 & 0x1F) != rd:
        return None
    off12 = ((w1 >> 10) & 0xFFF) * 8
    if w2 != 0xD61F0000 | rd:
        return None
    return (page + off12) & 0xFFFFFFFFFFFFFFFF, rd

stubs = []
for off in range(0, len(text) - 12, 4):
    r = decode_stub(off)
    if r:
        stubs.append((off, r[0], r[1]))

print(".text %d 字节，扫到 %d 个 PLT 桩" % (len(text), len(stubs)))
if not stubs:
    sys.exit(0)

# 找最密集的连续区（桩通常连续）
best = None
i = 0
while i < len(stubs):
    j = i
    while j + 1 < len(stubs) and stubs[j + 1][0] == stubs[j][0] + 12:
        j += 1
    if best is None or j - i > best[1] - best[0]:
        best = (i, j)
    i = j + 1
i, j = best
run = stubs[i:j + 1]
print("最大连续桩区：%d 个，text 偏移 %#x..%#x" % (len(run), run[0][0], run[-1][0] + 12))
for k, (off, got, reg) in enumerate(run[:10]):
    print("   [%4d] text+%#x  GOT=%#x (映像内 %#x) reg=x%d" % (k, off, got, (got - BASE) & 0xFFFFFFFFFFFFFFFF, reg))

# GOT 槽是否连续
slots = [(got - BASE) & 0xFFFFFFFFFFFFFFFF for _, got, _ in run]
diffs = collections.Counter(b - a for a, b in zip(slots, slots[1:]))
print("GOT 槽相邻差值分布:", diffs.most_common(5))
print("GOT 槽范围: %#x .. %#x" % (min(slots), max(slots)))
print("这些槽落在 data 段内吗: data memOff=%#x size=%#x" % (dmo, dsz))
if dmo <= min(slots) < dmo + dsz:
    print("  → 落在 data 段，data 内偏移 = %#x" % (min(slots) - dmo))
