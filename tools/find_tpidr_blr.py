#!/usr/bin/env python3
"""找「mrs xN, TPIDR_EL0 / TPIDRRO_EL0 之后，把 xN 当函数指针 blr」的位置。

客机崩在 pc=0、且崩溃时 x8 == TPIDR_EL0 的值时，这就是罪魁。

用法:
    python tools/find_tpidr_blr.py <text.bin>
"""
import struct
import sys

MRS_TPIDR_EL0 = 0xD53BD040
MRS_TPIDRRO_EL0 = 0xD53BD060


def mrs_tpidr(w):
    if w == MRS_TPIDR_EL0:
        return ("TPIDR_EL0", w & 0x1F)
    if w == MRS_TPIDRRO_EL0:
        return ("TPIDRRO_EL0", w & 0x1F)
    # MRS 编码：1101 0101 0011 1011 0100 0000 Rm Rt —— 用掩码兼容不同寄存器号
    if (w & 0xFFFFFFE0) == MRS_TPIDR_EL0:
        return ("TPIDR_EL0", w & 0x1F)
    if (w & 0xFFFFFFE0) == MRS_TPIDRRO_EL0:
        return ("TPIDRRO_EL0", w & 0x1F)
    return None


def blr(w):
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return (w >> 5) & 0x1F
    return None


def main():
    t = open(sys.argv[1], "rb").read()
    hits = 0
    for i in range(0, len(t) - 64, 4):
        w = struct.unpack_from("<I", t, i)[0]
        m = mrs_tpidr(w)
        if not m:
            continue
        which, rt = m
        # 往后 16 条里找 blr 同一寄存器（中间可能穿插 ldr/add）
        for k in range(1, 17):
            off = i + k * 4
            wk = struct.unpack_from("<I", t, off)[0]
            b = blr(wk)
            if b is not None and b == rt:
                hits += 1
                print("   +%#010x  mrs %s -> x%d ... +%#010x blr x%d"
                      % (i, which, rt, off, rt))
                break
    if not hits:
        print("没找到「mrs TPIDR* 之后直接 blr 同一寄存器」")


if __name__ == "__main__":
    main()
