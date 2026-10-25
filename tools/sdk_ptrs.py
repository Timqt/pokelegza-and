#!/usr/bin/env python3
"""在 SDK 映像里搜「指向某个偏移的指针」，用来反查 vtable / 全局表。

用法：python tools/sdk_ptrs.py 0x146040
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
SEG = [("text", 0x0, 0x64E230), ("rodata", 0x64F000, 0x4EC000), ("data", 0xB3B000, 0x544E0)]


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
    target = int(sys.argv[1], 0)
    IMG = load()
    needle = struct.pack("<Q", target)
    print("=== 搜索指向 %#x 的指针 ===" % target)
    for name, off, size in SEG:
        blob = bytes(IMG[off:off + size])
        pos = 0
        found = 0
        while True:
            i = blob.find(needle, pos)
            if i < 0:
                break
            print("  %s+%#x（映像偏移 %#x）" % (name, i, off + i))
            found += 1
            pos = i + 1
            if found > 40:
                print("  ...（太多）")
                break
        if found == 0:
            print("  %s: 无" % name)

    # 反过来：vtable 指针常常是一串连续函数指针。看目标地址周围
    print("\n=== 目标地址附近的连续指针（找 vtable） ===")
    for name, off, size in SEG:
        blob = bytes(IMG[off:off + size])
        pos = 0
        while True:
            i = blob.find(needle, pos)
            if i < 0:
                break
            lo = max(0, i - 0x40)
            print("  --- %s+%#x 附近的表 ---" % (name, i))
            for j in range(lo, min(len(blob) - 8, i + 0x40), 8):
                v = struct.unpack_from("<Q", blob, j)[0]
                mark = "  <<<" if j == i else ""
                print("    %s+%#x = %#018x%s" % (name, j, v, mark))
            pos = i + 1
            break


if __name__ == "__main__":
    main()
