#!/usr/bin/env python3
"""对比 D2R 的 Switch 着色器包 .bin 与 Z-A 的 .bnsh：记录结构、控制段、SASS 位置。"""

import os
import struct
import sys

D2R_DIR = r"D:\feiniukexinhome\Code\d2r-and\pack-workspace\produce\shaders\work"
ZA_DIR = r"D:\feiniukexinhome\Code\pokeLegza-and\work\shaders"

REC_SEP = b"BTCDBTCD"
CTL_MAGIC = bytes.fromhex("34127698")


def analyze(data, name):
    print("=== %s (%d 字节) ===" % (name, len(data)))
    print("   头 16 字节: %s" % data[:16].hex(" "))
    seps = [m.start() for m in __import__("re").finditer(REC_SEP, data)]
    print("   BTCDBTCD 分隔符出现 %d 次" % len(seps))
    # 找所有控制段魔数
    ctls = []
    pos = 0
    while True:
        i = data.find(CTL_MAGIC, pos)
        if i < 0:
            break
        ctls.append(i)
        pos = i + 1
    print("   控制段魔数 0x98761234 出现 %d 次，前几个: %s" % (len(ctls), ctls[:6]))
    if ctls:
        ci = ctls[0]
        csz = struct.unpack_from("<I", data, 0x28)[0]
        print("   0x28 处的大小字段 = %d (0x%x)" % (csz, csz))
        print("   记录0: code = data[0x38:%d] 长度 %d" % (ci, ci - 0x38))
        print("   code 前 32 字节: %s" % data[0x38:0x58].hex(" "))
        print("   控制段前 32 字节: %s" % data[ci:ci + 32].hex(" "))
    return seps, ctls


def main():
    # D2R 样本
    d2r_files = [f for f in os.listdir(D2R_DIR) if f.endswith(".bin")]
    print("D2R .bin 数量: %d" % len(d2r_files))
    for f in d2r_files[:2]:
        with open(os.path.join(D2R_DIR, f), "rb") as g:
            analyze(g.read(), "D2R " + f)
        print()

    # Z-A 样本
    za = []
    for root, _, files in os.walk(ZA_DIR):
        for f in files:
            if f.endswith(".bnsh"):
                za.append(os.path.join(root, f))
    za.sort(key=lambda p: os.path.getsize(p))
    print("Z-A .bnsh 数量: %d" % len(za))
    for p in za[:2] + za[-1:]:
        with open(p, "rb") as g:
            analyze(g.read(), "Z-A " + os.path.basename(p) + " (" + os.path.basename(os.path.dirname(p)) + ")")
        print()


if __name__ == "__main__":
    main()
