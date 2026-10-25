# -*- coding: utf-8 -*-
"""从 abort 的**跳板**倒推调用者。

实测：0x9ac90 / 0x9acb0 没有任何直接 bl/b 调用者 ⇒ 全部经 GOT 跳板间接调用。
客机实际用的两个跳板：
    0x62f3d0  -> 0xb77198 -> base+0x9ac90
    0x631ec0  -> 0xb78710 -> base+0x9acb0   (AbortImpl)

所以「谁 abort 了」= 「谁 bl 了 0x62f3d0 或 0x631ec0」。
本脚本把这两个跳板的所有直接调用者列出来，再标出**落在 _init_libc1 可达范围**内的，
用来定位本次 Break 的真实调用点（不再靠栈上的数据猜）。
"""
import struct

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

THUNKS = {
    0x62F3D0: 'abort_thunk -> base+0x9ac90',
    0x631EC0: 'AbortImpl_thunk -> base+0x9acb0',
}


def bl_target(off):
    x = w[off // 4]
    if (x & 0xFC000000) != 0x94000000:
        return None
    imm = x & 0x3FFFFFF
    if imm >= 1 << 25:
        imm -= 1 << 26
    return off + imm * 4


for tgt, name in THUNKS.items():
    callers = [off for off in range(0, len(t) - 4, 4) if bl_target(off) == tgt]
    print('=== 跳板 %#x (%s)：%d 个直接调用者 ===' % (tgt, name, len(callers)))
    # 只打印落在几个关注区间的，其余只计数
    interesting = [c for c in callers if 0x10D000 <= c < 0x10E000 or
                   0x147000 <= c < 0x148000 or 0x13C000 <= c < 0x13D000 or
                   0x153000 <= c < 0x154000 or 0x3C2000 <= c < 0x3C5000]
    print('  落在关注区间的: %s' % [hex(c) for c in interesting])
    print('  全部前 40 个: %s' % [hex(c) for c in callers[:40]])
    print()
