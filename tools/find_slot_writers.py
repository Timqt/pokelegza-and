#!/usr/bin/env python3
"""找 SDK 里「谁在写 0xb73898 那 21 个槽」。

思路：目标表在 .data 的 0xb73898..0xb73938。
  1) 先看 SDK 的 87 个 init_array 构造器里有没有它；
  2) 全 text 扫「ADRP 到 0xb73000 页 + ADD #0x898..0x938 + STR」的写入序列。
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
GOT0 = 0xB73898
NSLOT = 21
TEXT_SZ = 0x64E230
DATA_OFF = 0xB3B000
INIT_ARRAY = 0xB3B000
INIT_ARRSZ = 0x2B8


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


def add_imm(w):
    """ADD (immediate) 的 imm12（不含 shift）。"""
    if (w & 0x7F800000) != 0x11000000:
        return None
    sh = (w >> 22) & 1
    imm = (w >> 10) & 0xFFF
    return imm << (12 if sh else 0)


def str_imm(w):
    """STR (unsigned imm) 的字节偏移。"""
    if (w & 0x3B000000) != 0x39000000:
        return None
    size = (w >> 30) & 3
    imm = (w >> 10) & 0xFFF
    return imm << size


def main():
    IMG = load()
    W = struct.unpack_from("<%dI" % (len(IMG) // 4), bytes(IMG), 0)

    print("=== SDK 的 87 个 init_array 构造器 ===")
    n = INIT_ARRSZ // 8
    for i in range(n):
        f = struct.unpack_from("<Q", bytes(IMG[INIT_ARRAY + i * 8:INIT_ARRAY + i * 8 + 8]), 0)[0]
        print("  [%2d] %#x" % (i, f))

    # 全 text 扫：ADRP->0xb73000 页，随后 ADD #0x898..0x938，再 STR
    print("\n=== 扫 text 里对 0xb73000 页的引用 + 偏移 0x898..0x938 的写 ===")
    PAGE = GOT0 & ~0xFFF
    hits = []
    for i in range(TEXT_SZ // 4):
        off = i * 4
        w = W[i]
        if (w & 0x9F000000) != 0x90000000:
            continue
        if adrp_target(off, w) != PAGE:
            continue
        rd = w & 0x1F
        # 往后 6 条里找 add xM, x_rd, #imm（imm 在 0x898..0x938）
        for j in range(1, 8):
            if i + j >= TEXT_SZ // 4:
                break
            w2 = W[i + j]
            if (w2 & 0xFFE00000) == 0x91000000:      # ADD immediate
                rn = (w2 >> 5) & 0x1F
                rd2 = w2 & 0x1F
                imm = add_imm(w2)
                if rn == rd and imm is not None and 0x898 <= imm <= 0x938:
                    # 找后面的 STR
                    for k in range(j + 1, j + 8):
                        if i + k >= TEXT_SZ // 4:
                            break
                        w3 = W[i + k]
                        rn3 = (w3 >> 5) & 0x1F
                        if (w3 & 0x3B000000) == 0x39000000 and rn3 == rd2:
                            hits.append((off, i + j * 4, i + k * 4, imm))
                            break
    print("命中 %d 处" % len(hits))
    for a, b, c, imm in hits[:60]:
        print("  adrp@%#x add@%#x(#%#x) str@%#x  => 写 0x%x 附近" % (a, b, imm, c, PAGE + imm))

    if not hits:
        print("\n（没有任何代码写这张表 ⇒ 它是**静态初始化**的，5 个 NULL 就是文件里本来的值）")
        print("⇒ 那么在真机上它们也该是 0，除非 OS 装载器会补 —— 需要再查。")


if __name__ == "__main__":
    main()
