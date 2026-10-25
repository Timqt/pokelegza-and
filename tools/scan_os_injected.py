#!/usr/bin/env python3
"""扫出 SDK 里所有「OS 注入的函数指针槽」。

模式：`adrp xM, <页> ; ldr xN, [xM, #off] ; br/blr xN`
—— 槽里放的是 Switch OS 在装载 NSO 时填进来的函数地址。
文件里这些槽全是 0 ⇒ 我们这边必须自己填，否则 SDK 一调用就跳 0。

输出：槽地址（映像偏移）+ 引用它的指令位置。
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
TEXT_SZ = 0x64E230
DATA_OFF, DATA_SZ = 0xB3B000, 0x544E0
BSS_OFF, BSS_SZ = 0xB8F4E0, 0xCEB20
IMG_SIZE = DATA_OFF + DATA_SZ + BSS_SZ


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


def adrp_target(off, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def main():
    IMG = load()
    W = struct.unpack_from("<%dI" % (len(IMG) // 4), bytes(IMG), 0)
    # 记录每个寄存器最近一次「adrp」得到的页
    slots = {}
    for i in range(TEXT_SZ // 4):
        off = i * 4
        w = W[i]
        if (w & 0x9F000000) == 0x90000000:
            rd = w & 31
            slots[("page", rd)] = (off, adrp_target(off, w))
        elif (w & 0xFFC00000) == 0xF9400000:      # LDR Xt, [Xn, #imm]
            rt = w & 31
            rn = (w >> 5) & 31
            imm = ((w >> 10) & 0xFFF) * 8
            key = ("page", rn)
            if key in slots and slots[key][0] >= off - 0x40:
                _, page = slots[key]
                slots[("val", rt)] = (off, page + imm)
        elif (w & 0xFFFFFC1F) == 0xD61F0000 or (w & 0xFFFFFC1F) == 0xD63F0000:  # BR / BLR
            rn = (w >> 5) & 31
            key = ("val", rn)
            if key in slots and slots[key][0] >= off - 0x40:
                _, addr = slots[key]
                if DATA_OFF <= addr < IMG_SIZE:
                    val = struct.unpack_from("<Q", bytes(IMG[addr:addr + 8]), 0)[0]
                    slots.setdefault(("slot", addr), []).append((off, val))
    print("=== .data/.bss 里被 br/blr 间接调用的槽 ===")
    zero = []
    for (kind, addr), refs in sorted(slots.items()):
        if kind != "slot":
            continue
        val = struct.unpack_from("<Q", bytes(IMG[addr:addr + 8]), 0)[0]
        refs_s = ", ".join("%#x" % r[0] for r in refs[:6])
        if val == 0:
            zero.append(addr)
        print("  槽 %#010x（文件值=%#x）被 %d 处调用：%s" % (addr, val, len(refs), refs_s))
    print("\n文件值为 0（= 需要 OS 注入）的槽：%d 个" % len(zero))
    for a in zero:
        print("   %#x" % a)


if __name__ == "__main__":
    main()
