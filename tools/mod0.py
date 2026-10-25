#!/usr/bin/env python3
"""解出 NSO 的 MOD0 头，并把各字段换算成「相对映像基址」的绝对偏移。

⚠ MOD0 的所有字段都是**相对 magic 字段**的有符号 32 位。magic 的地址存在
   「映像基址 + 4」那个 u32 里。别把字段当相对映像基址用（实测踩过）。

用法:
    python tools/mod0.py entry_0
    python tools/mod0.py entry_32848007
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEFS = os.path.join(ROOT, "work", "base", "exefs2")

FIELDS = [
    (0x00, "magic"),
    (0x04, ".dynamic"),
    (0x08, ".bss start"),
    (0x0C, ".bss end"),
    (0x10, ".eh_frame_hdr start"),
    (0x14, ".eh_frame_hdr end"),
    (0x18, "**runtime module object**"),
    (0x1C, "(+0x1c)"),
    (0x20, "(+0x20)"),
    (0x24, "(+0x24)"),
    (0x28, "(+0x28)"),
    (0x2C, "(+0x2c)"),
]


def load(nso_name):
    d = open(os.path.join(EXEFS, nso_name), "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    imgsize = segs[2][1] + segs[2][2] + bss
    img = bytearray(imgsize)
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        img[mo:mo + sz] = raw
    return d, img, segs, bss, imgsize


def main():
    name = sys.argv[1]
    d, img, segs, bss, imgsize = load(name)
    mod0 = struct.unpack_from("<I", img, 4)[0]
    print("%s: 映像大小 %#x（bss %#x）  MOD0 magic 在 映像偏移 %#x" % (name, imgsize, bss, mod0))
    print("   （「映像基址+4」那个 u32 = %#x，它必须指向 magic）" % mod0)
    if img[mod0:mod0 + 4] != b"MOD0":
        print("   ⚠ magic 处不是 'MOD0'：%r" % bytes(img[mod0:mod0 + 4]))
        return
    print("   字段（都是**相对 magic** 的有符号 32 位）：")
    for off, label in FIELDS:
        v = struct.unpack_from("<i", img, mod0 + off)[0]
        abs_off = mod0 + v
        flag = ""
        if 0 <= abs_off < imgsize:
            flag = "-> 映像 %#x" % abs_off
        else:
            flag = "-> 映像外（%d）" % abs_off
        print("      +%#04x %-24s rel=%#011x %s" % (off, label, v & 0xFFFFFFFF, flag))


if __name__ == "__main__":
    main()
