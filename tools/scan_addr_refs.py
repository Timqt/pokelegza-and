#!/usr/bin/env python3
"""在一段 text 里找「引用某地址」的所有指令（adrp + ldr/str/add 立即数）。

比 scan_refs.py 更通用：支持 ldr/str 的 unsigned-offset 形式与 add 形式。

用法:
    python tools/scan_addr_refs.py <text.bin> <映像基址> <目标地址> [目标地址 ...]
例:
    python tools/scan_addr_refs.py work/nso_32848007/text.bin 0 0xb74150 0xb9c478
"""
import struct
import sys


def adrp_target(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def _imm12(w):
    imm = (w >> 10) & 0xFFF
    return imm


def op_kind(w):
    """返回 (类型, 立即数) 或 None。"""
    # ADD/SUB (immediate), 64-bit
    if (w & 0x7F800000) == 0x11000000 and ((w >> 23) & 0x1F) in (0, 1):
        imm = _imm12(w)
        if (w >> 22) & 1:
            imm <<= 12
        return ("add", imm)
    # LDR/STR (immediate, unsigned offset), 64-bit
    top = w & 0xFFC00000
    if top in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000):
        return ("ldrstr", _imm12(w))
    return None


def main():
    path = sys.argv[1]
    base = int(sys.argv[2], 0)
    targets = {int(x, 0): int(x, 0) for x in sys.argv[3:]}
    blob = open(path, "rb").read()
    for i in range(0, len(blob) - 8, 4):
        w1 = struct.unpack_from("<I", blob, i)[0]
        if (w1 & 0x9F000000) != 0x90000000:
            continue
        page = adrp_target(i, w1)
        rd = w1 & 0x1F
        w2 = struct.unpack_from("<I", blob, i + 4)[0]
        rn = (w2 >> 5) & 0x1F
        if rn != rd:
            continue
        k = op_kind(w2)
        if not k:
            continue
        kind, imm = k
        tgt = base + page + imm
        if tgt in targets:
            print("   +%#010x  %-6s -> %#x" % (i, kind, tgt))


if __name__ == "__main__":
    main()
