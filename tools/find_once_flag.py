# -*- coding: utf-8 -*-
"""找 0xb9c5a0 / 0xb9c59c / 0xb9c5a4 的读写点。

背景：SDK 的 nnosInitialize 在 sdk+0x153f50 处做了一次「已初始化」检查：
    153f50: adrp x0,0xb9c000 ; add x0,x0,#0x5a0    => 检查 0xb9c5a0
    153f58: bl 0x631640                            => 读 [x0] 判断
    153f5c: cbz w0, 0x153edc                       => 非 0 才继续
    否则走 assert（0x1543e8 == 断言字符串地址推算源，实际是 udf/abort 路径）
而实机 svc#38 Break reason=0 size=4 值=0 ⇒ 就是这条断言失败。

本脚本列出所有 adrp(0xb9c000)+add 命中 0x59c/0x5a0/0x5a4 的位置，
以及对该页 +0x4b8（另一组 once 标志）的读写点，用来判断谁负责初始化。
"""
import struct

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

PAGE = 0xb9c000
WANT = (0x59c, 0x5a0, 0x5a4, 0x4b8, 0x4bc)


def adrp_target(i):
    x = w[i]
    if (x & 0x9F00001F) != 0x90000000:
        return None
    immlo = (x >> 29) & 3
    immhi = (x >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm >= 1 << 20:
        imm -= 1 << 21
    return ((i * 4) & ~0xFFF) + (imm << 12)


found = []
for i in range(n - 1):
    if adrp_target(i) != PAGE:
        continue
    rd = w[i] & 0x1F
    for j in range(1, 4):
        if i + j >= n:
            break
        y = w[i + j]
        # ADD (immediate), 64-bit, LSL#0
        if (y & 0x7F800000) == 0x11000000:
            imm12 = (y >> 10) & 0xFFF
            shift = (y >> 22) & 3
            rn = (y >> 5) & 0x1F
            if shift == 0 and rn == rd and imm12 in WANT:
                found.append((i * 4, imm12, 'add'))
        # LDRB/STRB (unsigned imm) : size=00 -> 0x39400000 / 0x39000000
        for base, kind in ((0x39400000, 'ldrb'), (0x39000000, 'strb'),
                           (0x39800000, 'ldrsw'), (0xB9400000, 'ldrw')):
            if (y & 0xFFC00000) == base:
                imm12 = (y >> 10) & 0xFFF
                rn = (y >> 5) & 0x1F
                if rn == rd and imm12 in WANT:
                    found.append((i * 4, imm12, kind))

print('命中 %d 处：' % len(found))
for a, imm, kind in sorted(found):
    print('  %#08x  %-6s +%#x' % (a, kind, imm))
