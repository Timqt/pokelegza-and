#!/usr/bin/env python3
"""在 NSO 的各段里按 8 字节对齐搜一个 64 位值。

用途：客机崩溃到野指针时，找出「那个值到底是从哪读出来的」。

用法:
    python tools/find_value.py <nso名> <值(十六进制)>
例:
    python tools/find_value.py entry_32848007 0x6c00000000
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEFS = os.path.join(ROOT, "work", "base", "exefs2")


def load(nso_name):
    d = open(os.path.join(EXEFS, nso_name), "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    out = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        out.append((["text", "rodata", "data"][i], mo, sz, raw))
    return out


def main():
    nso = sys.argv[1]
    val = int(sys.argv[2], 0)
    b = val.to_bytes(8, "little")
    for name, mo, sz, raw in load(nso):
        hits = []
        for i in range(0, len(raw) - 7, 8):
            if raw[i:i + 8] == b:
                hits.append(mo + i)
        print("%-7s 段（内存偏移 %#x，大小 %#x）：%d 处 %s"
              % (name, mo, sz, len(hits), [hex(x) for x in hits[:12]]))


if __name__ == "__main__":
    main()
