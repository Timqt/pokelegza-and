#!/usr/bin/env python3
"""把 aarch64 的「adrp + 后续访存指令」正确解成目标地址。

⚠ 关键：aarch64 的 `ldr xN, [xM, #imm]` 里 **imm12 会被按访问宽度缩放**
   64 位访存 ×8、32 位 ×4、字节访存 ×1。不缩放就会把偏移算错
   （实测踩过：把 #0x150 当成 0x150 字节，实际是 0x150*8 = 0xa80）。

用法:
    # 列出某函数里所有 adrp+ldr/str/add 解出的目标地址
    python tools/arm64_refs.py <text.bin> <映像基址> <起始偏移> <长度>
"""
import struct
import sys


def adrp_target(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def decode_mem(w):
    """返回 (助记符, imm12, 缩放, rn, rt)；不是访存/加减立即数则 None。"""
    # LDR/STR (immediate, unsigned offset)
    # 64-bit: 0xF9400000 LDR / 0xF9000000 STR ; 32-bit: 0xB9400000 / 0xB9000000
    # byte:   0x39400000 / 0x39000000
    for mask, scale, name in ((0xFFC00000, 8, "ldr/str64"),
                              (0xFFC00000, 4, "ldr/str32"),
                              (0xFFC00000, 1, "ldr/str8")):
        top = w & 0xFFC00000
        if scale == 8 and top in (0xF9400000, 0xF9000000):
            return ("ldr/str64", (w >> 10) & 0xFFF, 8, (w >> 5) & 0x1F, w & 0x1F)
        if scale == 4 and top in (0xB9400000, 0xB9000000):
            return ("ldr/str32", (w >> 10) & 0xFFF, 4, (w >> 5) & 0x1F, w & 0x1F)
        if scale == 1 and top in (0x39400000, 0x39000000):
            return ("ldr/str8", (w >> 10) & 0xFFF, 1, (w >> 5) & 0x1F, w & 0x1F)
    # ADD (immediate), 64-bit: 不缩放（除非 shift=1，则 <<12）
    if (w & 0x7F800000) == 0x91000000:
        imm = (w >> 10) & 0xFFF
        if (w >> 22) & 1:
            imm <<= 12
        return ("add", imm, 1, (w >> 5) & 0x1F, w & 0x1F)
    return None


def main():
    path = sys.argv[1]
    base = int(sys.argv[2], 0)
    start = int(sys.argv[3], 0)
    size = int(sys.argv[4], 0)
    blob = open(path, "rb").read()
    page = None
    page_reg = None
    for off in range(start, min(start + size, len(blob)), 4):
        w = struct.unpack_from("<I", blob, off)[0]
        if (w & 0x9F000000) == 0x90000000:
            page = adrp_target(off, w)
            page_reg = w & 0x1F
            continue
        d = decode_mem(w)
        if not d or page is None:
            continue
        name, imm, scale, rn, rt = d
        if rn != page_reg:
            continue
        eff = imm * scale if name != "add" else imm
        print("   +%#010x  %-10s x%-2d <- [x%d + %#x]  =>  映像 %#x"
              % (off, name, rt, rn, eff, base + page + eff))


if __name__ == "__main__":
    main()
