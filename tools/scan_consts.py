#!/usr/bin/env python3
"""在一段 text 里找「由 movz + movk 拼出来的 32/64 位常量」，并与给定集合比对。

用途：反推 SDK 怎么拿到自己的段大小等常量（是编译期常量还是从 MOD0 读）。

用法:
    python tools/scan_consts.py <text.bin> <值> [值 ...]
"""
import struct
import sys


def movz(w):
    if (w & 0x7F800000) != 0x52800000:
        return None
    return ((w >> 5) & 0xFFFF) << (((w >> 21) & 3) * 16), (w & 0x1F)


def movk(w):
    if (w & 0x7F800000) != 0x72800000:
        return None
    return ((w >> 5) & 0xFFFF), ((w >> 21) & 3), (w & 0x1F)


def main():
    path = sys.argv[1]
    targets = {int(x, 0) for x in sys.argv[2:]}
    t = open(path, "rb").read()
    for i in range(0, len(t) - 16, 4):
        m = movz(struct.unpack_from("<I", t, i)[0])
        if not m:
            continue
        val, reg = m
        j = i + 4
        nk = 0
        while j + 4 <= len(t) and nk < 4:
            k = movk(struct.unpack_from("<I", t, j)[0])
            if not k:
                break
            imm, sh, r = k
            if r != reg or sh != nk + 1:
                break
            val |= imm << (sh * 16)
            j += 4
            nk += 1
        if val in targets:
            print("   +%#010x  常量 %#x  (movz + %d movk)" % (i, val, nk))


if __name__ == "__main__":
    main()
