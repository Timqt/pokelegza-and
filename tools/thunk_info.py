#!/usr/bin/env python3
"""解出 SDK 跳板（adrp+ldr+add+br）指向的 GOT 槽，并查出该槽的重定位目标。

用法:
    python tools/thunk_info.py <text.bin> <relocs.bin> <跳板地址> [...]
例:
    python tools/thunk_info.py work/nso_32848007/text.bin work/nso_sdk/sdk_relocs.bin 0x636ba0 0x636f60
"""
import struct
import sys


def adrp_t(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def main():
    text_path, rel_path = sys.argv[1], sys.argv[2]
    addrs = [int(x, 0) for x in sys.argv[3:]]
    t = open(text_path, "rb").read()
    rel = open(rel_path, "rb").read()
    n = struct.unpack_from("<I", rel, 0)[0]
    rmap = {}
    for i in range(n):
        slot, kind, sym, add = struct.unpack_from("<IIII", rel, 4 + i * 16)
        rmap[slot] = (kind, add)

    for a in addrs:
        w1, w2, w3, w4 = struct.unpack_from("<IIII", t, a)
        page = adrp_t(a, w1)
        ldr_imm = ((w2 >> 10) & 0xFFF) * 8
        slot = page + ldr_imm
        r = rmap.get(slot)
        if r is None:
            tgt = "（该槽无重定位条目）"
        elif r[0] == 0:
            tgt = "需要宿主解析（导入）"
        else:
            tgt = "base+%#x" % r[1]
        print("跳板 %#x -> 槽 %#x  %s" % (a, slot, tgt))


if __name__ == "__main__":
    main()
