# -*- coding: utf-8 -*-
"""找 svc#33 / svc#34 包装函数的所有调用者，定位真正的 IPC 发送点。

已知包装（实测反汇编）：
    0x170134  svc#0x1f (31 ConnectToNamedPort)  str x0,[sp,#-0x10]! 形态
    0x17014c  svc#0x21 (33 SendSyncRequest)     svc#N; ret 形态（无出参）
    0x170154  svc#0x22 (34 SendSyncRequestWithUserBuffer)

SendSyncRequest 只带 session（x0），应答由内核写进**线程的 IPC 缓冲区**
（switchbrew: 线程 TLS 里有 command buffer 指针）。
所以真正发送点一定在 nn::sf/sm 的 send 逻辑里，找到它就能看清
应答缓冲区是怎么从 TLS 取出来的。
"""
import struct

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

TARGETS = {0x17014C: 'svc#33 SendSyncRequest', 0x170154: 'svc#34 SendSyncRequestWithUserBuffer',
           0x170134: 'svc#31 ConnectToNamedPort'}


def bl_target(off):
    x = w[off // 4]
    if (x & 0xFC000000) != 0x94000000:
        return None
    imm = x & 0x3FFFFFF
    if imm >= 1 << 25:
        imm -= 1 << 26
    return off + imm * 4


for tgt, name in TARGETS.items():
    callers = [off for off in range(0, len(t) - 4, 4) if bl_target(off) == tgt]
    print('=== %#x  %s  -> %d 个调用者' % (tgt, name, len(callers)))
    for c in callers:
        print('    %#08x' % c)
    print()
