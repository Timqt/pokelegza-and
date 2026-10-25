# -*- coding: utf-8 -*-
"""扫全 SDK text，找所有可能写 0xb9c000 页 +0x5a0 的 STRB/STURB。

之前 tools/find_once_flag.py 只认 `adrp + add + strb` 这种「先算地址」的写法，
漏掉了直接 `strb wN,[xM,#0x5a0]`（基址寄存器已持有页首）的写法。
本脚本改用第二种更可靠的做法：找所有 adrp 目标落在 0xb9c000 页的指令，
把它们前后 8 条都反汇编出来，人工看谁在写 +0x5a0。
"""
import struct
import subprocess
import sys
import os

T = 'work/nso_32848007/text.bin'
t = open(T, 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

PAGE = 0xb9c000


def adrp_page(i):
    x = w[i]
    if (x & 0x9F00001F) != 0x90000000:
        return None
    immlo = (x >> 29) & 3
    immhi = (x >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm >= 1 << 20:
        imm -= 1 << 21
    return ((i * 4) & ~0xFFF) + (imm << 12)


sites = [i * 4 for i in range(n) if adrp_page(i) == PAGE]
print('adrp -> 0xb9c000 的站点: %d 处' % len(sites))

# 对每个站点，扫它之后的 12 条指令，找 STRB/STURB/STR 且立即数或后续 ADD 落在 0x5a0 附近
TARGETS = {0x598, 0x59c, 0x5a0, 0x5a4}


def decode_strb_store(y):
    """返回 (imm12) 若是 STRB (unsigned offset, 基址寄存器同 adrp rd)"""
    if (y & 0xFFC00000) == 0x39000000:      # strb Wt,[Xn,#imm12]
        return (y >> 10) & 0xFFF
    return None


hits = []
for off in sites:
    i = off // 4
    rd = w[i] & 0x1F
    base_reg = rd
    base_add = 0
    for j in range(1, 13):
        if i + j >= n:
            break
        y = w[i + j]
        # ADD base_reg, base_reg, #imm  (LSL#0)
        if (y & 0x7F800000) == 0x11000000:
            imm12 = (y >> 10) & 0xFFF
            rn = (y >> 5) & 0x1F
            rdd = y & 0x1F
            if rn == base_reg and (y >> 22) & 3 == 0:
                base_add += imm12
                if rdd != base_reg:
                    base_reg = rdd
                continue
        imm = decode_strb_store(y)
        if imm is not None:
            rn = (y >> 5) & 0x1F
            if rn == base_reg and (base_add + imm) in TARGETS:
                hits.append((off, i + j, base_add + imm, 'strb'))
        # STURB Wt,[Xn,#simm9]
        if (y & 0xFFE00C00) == 0x38000000:
            imm9 = (y >> 12) & 0x1FF
            if imm9 >= 1 << 8:
                imm9 -= 1 << 9
            rn = (y >> 5) & 0x1F
            if rn == base_reg and (base_add + imm9) in TARGETS:
                hits.append((off, i + j, base_add + imm9, 'sturb'))

print('候选写入点: %d 处' % len(hits))
for adrp_off, store_off, target, kind in hits:
    print('  adrp@%#08x  %s@%#08x  -> page+%#x' % (adrp_off, kind, store_off, target))
