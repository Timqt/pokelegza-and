# -*- coding: utf-8 -*-
"""把帧快照窗口从「guest_sp+0x10 起 0x70」改成「guest_sp 起 0x90」，
用 x30 的实际落点反推真正的帧底（避免再靠 +0x10 猜）。"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old_n = '#define ZA_SNAP_N 14            /* 14 words = 0x70 字节 = 整个 0x14457c 帧 */'
new_n = ('// 18 words = 0x90 字节：比 0x14457c 的 0x70 帧多留 0x20 余量，\n'
         '// 这样无论「包装函数 prologue 有没有跑」，x29/x30 槽都一定在窗口内，\n'
         '// 可以直接用「x30 == 0x20013ed84」的出现位置反推真实帧底。\n'
         '#define ZA_SNAP_N 18')
assert s.count(old_n) == 1
s = s.replace(old_n, new_n)

old_sp0 = '''    unsigned long sp0 = guest_sp + 0x10;'''
new_sp0 = '''    // 从 guest_sp 原样起算（不加 0x10）：由 dump 里 x30 的位置反推。
    unsigned long sp0 = guest_sp;'''
assert s.count(old_sp0) == 1
s = s.replace(old_sp0, new_sp0)

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('patched horizon')
