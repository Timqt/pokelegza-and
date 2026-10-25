# -*- coding: utf-8 -*-
"""在 0x14e8d0（IPC 请求构造体）范围内找出真正发 IPC 的那条 svc。

范围：0x14e8d0 .. 0x14f200（该函数体，按 0x120 栈帧 + 尾调用估计足够覆盖）
方法：扫范围内的 bl 指令，把目标解析成 GOT 槽 -> 真实函数；
      再在 svc 包装函数里比对是否是 `svc #N` 形态。
"""
import struct

T = 'work/nso_32848007/text.bin'
R = 'work/nso_sdk/sdk_relocs.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

LO, HI = 0x14E8D0, 0x14F200


def bl_target(off):
    x = w[off // 4]
    if (x & 0xFC000000) != 0x94000000:
        return None
    imm = x & 0x3FFFFFF
    if imm >= 1 << 25:
        imm -= 1 << 26
    return off + imm * 4


def is_svc(off):
    x = w[off // 4]
    return (x & 0xFFE0001F) == 0xD4000001


print('=== 0x%x..0x%x 区间内的 bl ===' % (LO, HI))
targets = {}
for off in range(LO, HI, 4):
    d = bl_target(off)
    if d is None:
        continue
    targets.setdefault(d, []).append(off)

# 读 GOT 槽 -> 判断跳板
rel = open(R, 'rb').read()


def thunk_slot(off):
    """若 off 处是 adrp/ldr/add/br 四连跳板，返回 (slot_vaddr)"""
    if off + 12 >= len(t):
        return None
    x0, x1, x2, x3 = struct.unpack_from('<4I', t, off)
    if (x0 & 0x9F00001F) != 0x90000000:
        return None
    if (x3 & 0xFFFFFC1F) != 0xD61F0000:
        return None
    immlo = (x0 >> 29) & 3
    immhi = (x0 >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm >= 1 << 20:
        imm -= 1 << 21
    page = (off & ~0xFFF) + (imm << 12)
    rd = x0 & 0x1F
    # ldr x17,[rd,#imm12*8]
    if (x1 & 0xFFC00000) != 0xF9400000:
        return None
    rt = x1 & 0x1F
    rn = (x1 >> 5) & 0x1F
    off12 = (x1 >> 10) & 0xFFF
    if rn != rd:
        return None
    return page + off12 * 8, rt


def reloc_value(slot):
    """从 sdk_relocs.bin 里查 slot 对应的重定位值（若有）"""
    # reloc 表格式未知 -> 退化：直接返回 None，由调用方用 thunk_info 逻辑
    return None


for d, sites in sorted(targets.items()):
    mark = ' <== SVC' if is_svc(d) else ''
    sl = thunk_slot(d)
    extra = ''
    if sl:
        sv, rt = sl
        extra = '  thunk slot=%#x' % sv
    print('  target %#08x  from %s%s%s' %
          (d, [hex(s) for s in sites], extra, mark))
