#!/usr/bin/env python3
"""在一段 text 里找「引用某个映像偏移」的指令（adrp + add 组合）。

移植客机时经常要回答「某个字符串/结构/全局被谁引用了」。
本工具扫 aarch64 指令，匹配 `adrp Xn, <page>` 后紧跟 `add Xn, Xn, #imm`
且合起来正好落在目标映像偏移的指令对。

用法:
    python tools/scan_refs.py <text.bin> <映像基址> <目标偏移> [目标偏移 ...]
例:
    python tools/scan_refs.py work/nso_32839457/text.bin 0 0x23ce 0x22d6
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


def add_imm(w):
    # ADD (immediate): sf op S 10001 shift imm12 Rn Rd
    if (w & 0x7F800000) != 0x11000000:
        return None
    if ((w >> 23) & 0x1F) not in (0, 1):
        return None
    imm = (w >> 10) & 0xFFF
    if imm & 0x800:
        imm -= 0x1000
    if (w >> 22) & 1:
        imm <<= 12
    return imm


def main():
    path = sys.argv[1]
    base = int(sys.argv[2], 0)
    targets = {int(x, 0) for x in sys.argv[3:]}
    blob = open(path, "rb").read()
    for i in range(0, len(blob) - 8, 4):
        w1 = struct.unpack_from("<I", blob, i)[0]
        if (w1 & 0x9F000000) != 0x90000000:
            continue
        page = adrp_target(i, w1)
        rd = w1 & 0x1F
        w2 = struct.unpack_from("<I", blob, i + 4)[0]
        if (w2 & 0xFF800000) != 0x91000000:
            continue
        if (w2 & 0x1F) != rd:
            continue
        a = add_imm(w2)
        if a is None:
            continue
        tgt = base + page + a
        if tgt in targets:
            print("   +%#x  引用 映像偏移 %#x" % (i, tgt))


if __name__ == "__main__":
    main()
