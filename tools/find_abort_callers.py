# -*- coding: utf-8 -*-
"""从 abort 函数倒推真实调用链（这才是唯一可靠的方向）。

为什么换方向：
  之前我一路顺着栈上的地址往下猜（0x3c3010 -> 0x3c30b0 -> 0x642f90），
  但 tools/trace_abort_source.py 证明：
    · 没有任何 bl/b 指向 0x3c2fc0
    · 0x1a80a 在代码里没有 movz/movk 构造点
  两个证据同时否掉那条链 ⇒ 栈上那些 sdk+0x3cxxxx 是**数据**，不是返回地址。

正确做法：先确认 abort 到底走的是哪个函数，再找**它的调用者**，
一层层倒推上去 —— 每一步都有 bl 指令为证，不靠猜。

已知 abort 候选：
  · 0x9ac90  (adrp "stdio" ; bl 0x632cc0)   <- 后面接 bl 0x62f3d0 的那条
  · 0x631ec0 -> base+0x9acb0                  <- AbortImpl
  · 0x62f3d0 -> base+0x9ac90                  <- 上面那个
"""
import struct

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

TARGETS = {
    0x9AC90: 'abort("stdio") 入口',
    0x9ACB0: 'AbortImpl',
    0x9AC84: '9ac84(前一条)',
}


def bl_target(off):
    x = w[off // 4]
    if (x & 0xFC000000) != 0x94000000:
        return None
    imm = x & 0x3FFFFFF
    if imm >= 1 << 25:
        imm -= 1 << 26
    return off + imm * 4


def b_target(off):
    x = w[off // 4]
    if (x & 0xFC000000) != 0x14000000:
        return None
    imm = x & 0x3FFFFFF
    if imm >= 1 << 25:
        imm -= 1 << 26
    return off + imm * 4


for tgt, name in TARGETS.items():
    callers = []
    for off in range(0, len(t) - 4, 4):
        if bl_target(off) == tgt:
            callers.append(('bl', off))
        elif b_target(off) == tgt:
            callers.append(('b', off))
    print('=== %#x %s ===' % (tgt, name))
    if not callers:
        print('  (无直接 bl/b 调用者 —— 可能只经跳板 GOT 间接调用)')
    for kind, off in callers[:20]:
        print('  %s @ %#08x' % (kind, off))
    print()
