#!/usr/bin/env python3
"""把一段客机代码里所有 `bl` 的**跳板最终目标**解出来。

用途：SDK 里几乎全是 `bl <跳板>`，跳板再 `adrp+ldr+br` 到 GOT 槽。
光看 `bl 0x636ba0` 毫无意义，必须解到「槽 → 重定位 → 真正函数」。

用法:
    python tools/resolve_calls.py <text.bin> <data.bin> <relocs.bin> <起始> <长度>
"""
import struct
import sys


def ldr_u(w):
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return ((w >> 10) & 0xFFF) * 8, (w >> 5) & 0x1F, w & 0x1F


def adrp_t(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def bl_target(off, w):
    if (w & 0xFC000000) != 0x94000000:
        return None
    d = w & 0x3FFFFFF
    if d & (1 << 25):
        d -= 1 << 26
    return off + d * 4


def main():
    text_path, data_path, rel_path = sys.argv[1], sys.argv[2], sys.argv[3]
    start, size = int(sys.argv[4], 0), int(sys.argv[5], 0)
    t = open(text_path, "rb").read()
    d = open(data_path, "rb").read()
    rel = open(rel_path, "rb").read()
    n = struct.unpack_from("<I", rel, 0)[0]
    rmap = {}
    for i in range(n):
        slot, kind, sym, add = struct.unpack_from("<IIII", rel, 4 + i * 16)
        rmap[slot] = (kind, add)

    # 数据段的内存偏移（从 layout 推：SDK = 0xb3b000）
    data_mem = 0xB3B000
    text_size = 0x64E230

    def resolve(slot):
        r = rmap.get(slot)
        if not r:
            return "（槽无重定位）"
        kind, add = r
        return "%s base+%#x" % ("导入" if kind == 0 else "内部", add)

    for off in range(start, start + size, 4):
        if off + 4 > len(t):
            break
        w = struct.unpack_from("<I", t, off)[0]
        tg = bl_target(off, w)
        if tg is None:
            continue
        # 目标是不是跳板？
        if tg + 12 <= len(t):
            w1 = struct.unpack_from("<I", t, tg)[0]
            if (w1 & 0x9F000000) == 0x90000000:
                page = adrp_t(tg, w1)
                rd = w1 & 0x1F
                w2 = struct.unpack_from("<I", t, tg + 4)[0]
                dd = ldr_u(w2)
                w3 = struct.unpack_from("<I", t, tg + 8)[0]
                w4 = struct.unpack_from("<I", t, tg + 12)[0] if tg + 16 <= len(t) else 0
                # 跳板 = adrp + ldr + add + br（第 3 条是 add，第 4 条才是 br）
                if dd and dd[1] == rd and (w4 & 0xFFFFFC1F) == 0xD63F0000:
                    slot = page + dd[0]
                    print("   sdk+%#-8x bl %#-8x 跳板→槽 %#-8x %s"
                          % (off, tg, slot, resolve(slot)))
                    continue
        print("   sdk+%#-8x bl %#-8x （直接调用，目标在 %s）"
              % (off, tg, "text" if tg < text_size else "其它段"))


if __name__ == "__main__":
    main()
