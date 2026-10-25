#!/usr/bin/env python3
"""在一段 text 里找「立即数等于某个值」的指令（movz/movk/add 等）。

用途：反推 SDK 怎么构造某个结构（把结构里的常量当锚点）。

用法:
    python tools/scan_imm.py <text.bin> <值> [值 ...]
"""
import struct
import sys


def movz_imm(w):
    if (w & 0x7F800000) != 0x52800000:
        return None
    return ((w >> 5) & 0xFFFF) << ((w >> 21) & 0x3) * 16


def main():
    path = sys.argv[1]
    vals = {int(x, 0) for x in sys.argv[2:]}
    blob = open(path, "rb").read()
    for i in range(0, len(blob) - 4, 4):
        w = struct.unpack_from("<I", blob, i)[0]
        v = movz_imm(w)
        if v is not None and v in vals:
            print("   +%#x  movz #%#x" % (i, v))
        # add/sub 立即数
        if (w & 0x7F800000) == 0x11000000 and ((w >> 23) & 0x1F) in (0, 1):
            imm = (w >> 10) & 0xFFF
            if imm & 0x800:
                imm -= 0x1000
            if (w >> 22) & 1:
                imm <<= 12
            if imm in vals:
                print("   +%#x  add/sub #%#x" % (i, imm))


if __name__ == "__main__":
    main()
