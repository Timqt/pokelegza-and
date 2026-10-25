#!/usr/bin/env python3
"""找出「引用某个只读页内偏移」的所有指令（adrp + add / adrp + ldr 两种形态）。

用途：定位只读 TLS 页里某个槽被谁读了，尤其是「读出来当函数指针 blr」的那一处。

用法:
    python tools/find_ro_slot.py <text.bin> <页基址> <页内偏移>
例:
    python tools/find_ro_slot.py work/nso_32848007/text.bin 0xf00000 0x1f0
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


def add_i(w):
    if (w & 0x7F800000) != 0x91000000:
        return None
    imm = (w >> 10) & 0xFFF
    if (w >> 22) & 1:
        imm <<= 12
    return imm, (w >> 5) & 0x1F, w & 0x1F


def ldr_u(w):
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return ((w >> 10) & 0xFFF) * 8, (w >> 5) & 0x1F, w & 0x1F


def blr(w):
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return (w >> 5) & 0x1F
    return None


def main():
    path, page_base, slot = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
    t = open(path, "rb").read()
    target = page_base + slot
    print("目标 %#x（页 %#x + 槽 %#x）" % (target, page_base, slot))
    n = 0
    for i in range(0, len(t) - 16, 4):
        w1 = struct.unpack_from("<I", t, i)[0]
        if (w1 & 0x9F000000) != 0x90000000:
            continue
        page = adrp_t(i, w1)
        rd = w1 & 0x1F
        w2 = struct.unpack_from("<I", t, i + 4)[0]
        a = add_i(w2)
        if a and a[1] == rd and page + a[0] == target:
            n += 1
            print("   +%#010x  adrp+add  -> x%d" % (i, a[2]))
            continue
        d = ldr_u(w2)
        if d and d[1] == rd and page + d[0] == target:
            n += 1
            reg = d[2]
            # 往后 5 条里找 blr 同一寄存器
            tail = ""
            for k in (8, 12, 16, 20):
                wk = struct.unpack_from("<I", t, i + k)[0]
                if blr(wk) == reg:
                    tail = "   <== 之后 blr x%d（当函数指针用！）" % reg
                    break
            print("   +%#010x  adrp+ldr  -> x%d%s" % (i, reg, tail))
    if not n:
        print("   没有指令直接引用它（可能经 mrs TPIDRRO_EL0 间接访问，或被我们改写后指向别处）")


if __name__ == "__main__":
    main()
