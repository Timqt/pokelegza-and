"""看失败样本里几个 SPH 位置的原始字节，判断是「真 SPH 但布局不同」还是「误命中的魔数」。"""
import os, struct, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
F = os.path.join(ROOT, "work", "shaders_all",
                 "fieldmodelt1t1_evt1_ev004t1_ev004_cockpit_cage.trmdl__003_1405040.bin")

def hexdump(b, base, width=16):
    out = []
    for i in range(0, len(b), width):
        c = b[i:i + width]
        out.append("%08x  %-*s |%s|" % (base + i, width * 3,
                     " ".join("%02x" % x for x in c),
                     "".join(chr(x) if 32 <= x < 127 else "." for x in c)))
    return "\n".join(out)

data = open(F, "rb").read()
print("文件 %s  %d 字节 (0x%X)" % (os.path.basename(F), len(data), len(data)))
print("BNSH 起点:", [hex(i) for i in [data.find(b"BNSH")]])

for off in (0x6471C, 0x6863C, 0x6871C):
    print("\n=== 0x%X ===" % off)
    print(hexdump(data[off:off + 0x60], off))
    w30 = struct.unpack_from("<I", data, off + 0x30)[0] if off + 0x34 <= len(data) else 0
    print("  +0x30 字 = 0x%08X -> bits10..13 = %d" % (w30, (w30 >> 10) & 0xF))

# 全文件里所有 0x12345678 的位置与它们的阶段字取值
SPH = bytes.fromhex("78563412")
pos = 0
rows = []
while True:
    i = data.find(SPH, pos)
    if i < 0:
        break
    pos = i + 1
    w = struct.unpack_from("<I", data, i + 0x30)[0] if i + 0x34 <= len(data) else 0
    rows.append((i, (w >> 10) & 0xF, w))
print("\n本文件共 %d 个 0x12345678：" % len(rows))
for i, st, w in rows:
    print("   0x%06X  阶段字=0x%08X -> %d %s" % (i, w, st, {1: "vs", 5: "ps"}.get(st, "?? 不像 SPH")))
