#!/usr/bin/env python3
"""在 SDK 的 .rodata 里找「跳表」，定位某个 default 分支的 switch。

aarch64 的 switch 跳表是一串 32 位有符号偏移，目标是 table_base + offset。
用法：python tools/find_jumptable.py 0x1c38bc
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
RODATA_OFF, RODATA_SZ = 0x64F000, 0x4EC000
TEXT_SZ = 0x64E230


def load():
    d = open(NSO, "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    out = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        out.append((mo, sz, raw))
    (tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = out
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    IMG = bytearray(dmo + dsz + bss)
    for mo, sz, raw in out:
        IMG[mo:mo + sz] = raw
    return IMG


def main():
    targets = [int(a, 0) for a in sys.argv[1:]] or [0x1c38bc]
    IMG = load()
    ro = bytes(IMG[RODATA_OFF:RODATA_OFF + RODATA_SZ])
    for tgt in targets:
        print("=== 目标 %#x ===" % tgt)
        hits = []
        for i in range(0, len(ro) - 4, 4):
            v = struct.unpack_from("<i", ro, i)[0]
            base = RODATA_OFF + i
            if base + v == tgt:
                hits.append(base)
        for h in hits:
            print("  跳表项在 %#x（rodata+%#x）" % (h, h - RODATA_OFF))
            # 跳表通常从某个索引开始，往前看几项
            for k in range(-8, 8):
                idx = (h - RODATA_OFF) // 4 + k
                if 0 <= idx < len(ro) // 4:
                    v = struct.unpack_from("<i", ro, idx * 4)[0]
                    t = RODATA_OFF + idx * 4 + v
                    if 0 <= t < TEXT_SZ:
                        print("     [%+d] → text+%#x" % (k, t))
        if not hits:
            print("  没找到（也许不是 ADR 跳表，或偏移基准不同）")


if __name__ == "__main__":
    main()
