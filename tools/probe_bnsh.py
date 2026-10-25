#!/usr/bin/env python3
"""摸清 Z-A BNSH 内部：控制段位置、SASS 区域、grsc 段含义。"""

import os
import struct
import sys

ZA = r"D:\feiniukexinhome\Code\pokeLegza-and\work\shaders\system_resourcegfx2shaderNX64env_ikkakumaterialstandard.bnsh\000_18467832.bnsh"
CTL = bytes.fromhex("34127698")


def hexdump(b, off, n, label=""):
    print("  --- %s @0x%08x ---" % (label, off))
    for i in range(0, n, 16):
        row = b[off + i:off + i + 16]
        print("   %08x  %s  %s" % (off + i, row.hex(" "),
                                   "".join(chr(x) if 32 <= x < 127 else "." for x in row)))


def main():
    b = open(ZA, "rb").read()
    print("文件 %d 字节" % len(b))

    ctls = []
    pos = 0
    while True:
        i = b.find(CTL, pos)
        if i < 0:
            break
        ctls.append(i)
        pos = i + 1
    print("控制段 %d 个: 前 10 个 %s" % (len(ctls), ctls[:10]))
    print("相邻间隔: %s" % [ctls[i + 1] - ctls[i] for i in range(9)])

    # 每个控制段头部结构
    for ci in ctls[:3]:
        print("\n控制段 @0x%08x:" % ci)
        for k in range(0, 0x28, 4):
            v = struct.unpack_from("<I", b, ci + k)[0]
            print("   +%02x = %-12d (0x%08x)" % (k, v, v))
        # 控制段大小？
        print("   0x28 处 u32 = %d" % struct.unpack_from("<I", b, ci + 0x28)[0])

    # 控制段之前的代码区
    ci = ctls[0]
    seg = b[0x38:ci]
    nz = sum(1 for x in seg if x)
    print("\n0x38..第一个控制段: 长度 %d 非零 %d (%.1f%%)" % (len(seg), nz, 100.0 * nz / max(1, len(seg))))
    # 第一段非零
    first = 0x38
    while first < ci and b[first] == 0:
        first += 1
    print("第一段非零起始: 0x%x" % first)
    hexdump(b, first, 64, "代码区起始")
    hexdump(b, ci - 64, 128, "第一个控制段前后")

    # 文件头 0x00-0x60 的解释
    print("\n文件头:")
    for k in range(0, 0x60, 4):
        v = struct.unpack_from("<I", b, k)[0]
        print("   +%02x = %-12d (0x%08x)" % (k, v, v))


if __name__ == "__main__":
    main()
