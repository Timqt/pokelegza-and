# -*- coding: utf-8 -*-
"""两条精确搜索，用来定案 abort 的真实来源。

① 谁调用 0x3c2fc0（那个 call_once 包装）——
   之前我一直假设 0x3c3010 是栈上的返回地址，但没验证过它到底被谁调。
   若根本没有调用者，说明栈上那个 0x2003c3010 是**数据**，不是返回地址，
   我整条 0x3c30b0 的推断就该推翻。

② 谁构造了 0x1a80a 这个 Result ——
   Switch Result 布局：module = v & 0x1FF，desc = (v>>9) & 0xFFF。
   0x1a80a => module 0xa (PM), desc 0xd4。
   代码里通常写成 `movz wN,#0xa80a` + `movk wN,#0x1,lsl#16`（或合并成 movz+movk 其它切法）。
   找到构造点就等于直接拿到出错的代码位置。
"""
import struct

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)


def bl_target(off):
    """若 off 处是 bl，返回目标；否则 None"""
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


print('=== ① 谁调用 0x3c2fc0 / 跳到它 ===')
callers = []
for off in range(0, len(t) - 4, 4):
    if bl_target(off) == 0x3c2fc0:
        callers.append(('bl', off))
    elif b_target(off) == 0x3c2fc0:
        callers.append(('b', off))
if callers:
    for kind, off in callers:
        print('  %s @ %#08x' % (kind, off))
else:
    print('  (没有任何 bl/b 指向它)')

print()
print('=== ② 谁构造 0x1a80a ===')
# MOVZ Wd, imm16 : 0x52800000 | (hw<<21) | (imm16<<5) | Rd   (32-bit)
# MOVK Wd, imm16 : 0x72800000 | (hw<<21) | (imm16<<5) | Rd
def movz_w(x):
    if (x & 0x7F800000) == 0x52800000:
        return ((x >> 21) & 3, (x >> 5) & 0xFFFF, x & 0x1F)
    return None

def movk_w(x):
    if (x & 0x7F800000) == 0x72800000:
        return ((x >> 21) & 3, (x >> 5) & 0xFFFF, x & 0x1F)
    return None

hits = []
for i in range(n - 1):
    m1 = movz_w(w[i])
    if m1 and m1[1] == 0xA80A and m1[0] == 0:
        m2 = movk_w(w[i + 1])
        if m2 and m2[2] == m1[2] and m2[0] == 0 and m2[1] in (0x1,):
            hits.append((i * 4, 'movz #0xa80a + movk #0x1'))
    # 也接受反向：movz #0x1 (hw0) + movk #0xa80a (hw0) —— 较少见但排一下
    if m1 and m1[1] == 0x1 and m1[0] == 0:
        m2 = movk_w(w[i + 1])
        if m2 and m2[2] == m1[2] and m2[0] == 0 and m2[1] == 0xA80A:
            hits.append((i * 4, 'movz #0x1 + movk #0xa80a'))

if hits:
    for off, how in hits:
        print('  %#08x  %s' % (off, how))
else:
    print('  (没有 movz/movk 组合构造它)')

print()
print('=== ③ 直接找 0x1a80a 作为 32 位字面量出现在 text 里的位置 ===')
pat = struct.pack('<I', 0x1A80A)
found = []
start = 0
while True:
    k = t.find(pat, start)
    if k < 0:
        break
    found.append(k)
    start = k + 1
print('  命中 %d 处 %s' % (len(found), [hex(v) for v in found[:12]]))
