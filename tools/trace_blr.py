#!/usr/bin/env python3
"""从某个 SDK 函数出发，BFS 找「第一个含 ldr+blr 组合」的函数。

用途：客机崩在 pc=0（间接调用跳到 0）时，从崩溃点的返回地址所在函数往外扩，
      定位真正执行 `blr` 的那一层，并给出「从结构体哪个偏移取的函数指针」。

用法:
    python tools/trace_blr.py <text.bin> <起始偏移> [最大深度]
例:
    python tools/trace_blr.py work/nso_32848007/text.bin 0x13ed64 4
"""
import struct
import sys
from collections import deque

# 函数边界不用精确判定：只用「bl 目标的入口」当起点，各自扫 0x400 字节窗口。
WINDOW = 0x400


def ldr_imm(w):
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return ((w >> 10) & 0xFFF) * 8, (w >> 5) & 0x1F, w & 0x1F


def blr_reg(w):
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return (w >> 5) & 0x1F
    return None


def bl_target(off, w):
    if (w & 0xFC000000) != 0x94000000:
        return None
    d = w & 0x3FFFFFF
    if d & (1 << 25):
        d -= 1 << 26
    return off + d * 4


def scan(blob, entry, length):
    """返回 (blr列表, callees)。blr列表元素=(指令偏移, 寄存器, 来源(偏移,基址寄存器,偏移量))。"""
    end = min(entry + length, len(blob))
    last = {}
    blrs, callees = [], []
    for off in range(entry, end - 4, 4):
        w = struct.unpack_from("<I", blob, off)[0]
        d = ldr_imm(w)
        if d:
            imm, rn, rt = d
            last[rt] = (off, rn, imm)
            continue
        r = blr_reg(w)
        if r is not None:
            blrs.append((off, r, last.get(r)))
            continue
        t = bl_target(off, w)
        if t is not None and 0 <= t < len(blob):
            callees.append(t)
    return blrs, callees


def main():
    path = sys.argv[1]
    start = int(sys.argv[2], 0)
    depth = int(sys.argv[3], 0) if len(sys.argv) > 3 else 3
    blob = open(path, "rb").read()

    seen = {start}
    q = deque([(start, 0, [start])])
    found = 0
    while q:
        entry, d, chain = q.popleft()
        blrs, callees = scan(blob, entry, WINDOW)
        for off, reg, src in blrs:
            found += 1
            print("命中：%s" % " -> ".join("%#x" % c for c in chain))
            print("   指令 +%#x  blr x%d" % (off, reg))
            if src:
                print("   函数指针取自 [x%d + %#x]（在 +%#x）" % (src[1], src[2], src[0]))
            else:
                print("   来源不在本函数（参数传入 / 全局加载）")
        if found >= 12:
            break
        if d >= depth:
            continue
        for c in callees:
            if c in seen:
                continue
            seen.add(c)
            q.append((c, d + 1, chain + [c]))
    if not found:
        print("深度 %d 内没找到 ldr+blr 组合（可能用了更复杂的取址方式）" % depth)


if __name__ == "__main__":
    main()
