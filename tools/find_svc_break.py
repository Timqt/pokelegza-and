# -*- coding: utf-8 -*-
"""找 SDK text 里所有 svc #0x26 (Horizon Break=38) 的位置，并给出上下文。

Break 是客机断言/致命错误的最后一步：
    svc #0x26  ->  x0=reason, x1=info(指针), x2=size
info 指向的结构第一句通常就是出错的 Result 或断言 id。

用法:
    python tools/find_svc_break.py [imm]
"""
import struct
import sys

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

imm_target = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x26
MASK = 0xFFE0001F
SVC = 0xD4000001

hits = [off * 4 for off in range(n)
        if (w[off] & MASK) == SVC and ((w[off] >> 5) & 0xFFFF) == imm_target]
print('svc #%d (0x%x) 命中 %d 条' % (imm_target, imm_target, len(hits)))
for off in hits:
    print('    text+%#08x' % off)
