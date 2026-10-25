#!/usr/bin/env python3
"""在一段 text 里找「ldr xN, [xM, #off] 之后跟着 blr xN」的组合。

这是客机移植里定位「从结构体取函数指针然后调用」的标准手法：
崩在 pc=0 时，这些点就是「哪个字段本该非空」的候选。

用法:
    python tools/find_indirect_calls.py <text.bin> <起始偏移> <长度>
例:
    python tools/find_indirect_calls.py work/nso_32848007/text.bin 0x145a30 0x260
"""
import struct
import sys


def ldr_imm(w):
    # LDR (immediate, unsigned offset) 64-bit: 0xF9400000 | imm12<<10 | rn<<5 | rt
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return ((w >> 10) & 0xFFF) * 8, (w >> 5) & 0x1F, w & 0x1F


def blr_reg(w):
    # BLR Xn : 1101011000111111000000 Rn 000000
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return (w >> 5) & 0x1F
    return None


def main():
    path = sys.argv[1]
    start = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0)
    t = open(path, "rb").read()
    end = min(start + size, len(t))
    # 记录每个寄存器最近一次 ldr 的来源，遇到 blr 就报
    last = {}
    for off in range(start, end - 4, 4):
        w = struct.unpack_from("<I", t, off)[0]
        d = ldr_imm(w)
        if d:
            imm, rn, rt = d
            last[rt] = (off, rn, imm)
            continue
        r = blr_reg(w)
        if r is not None:
            src = last.get(r)
            if src:
                where, rn, imm = src
                print("   +%#010x  blr x%-2d  ← 取自 [x%d + %#x]（在 +%#010x）"
                      % (off, r, rn, imm, where))
            else:
                print("   +%#010x  blr x%-2d  ← 来源不在本段（可能是参数传入）" % (off, r))


if __name__ == "__main__":
    main()
