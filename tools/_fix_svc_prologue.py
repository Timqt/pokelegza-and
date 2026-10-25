# -*- coding: utf-8 -*-
"""修 patch_svc.py 的 prologue 识别：漏了 `str xN,[sp,#-0x10]!`（N != x0）。

根因（实测）：svc#6 的包装函数 0x17000c 开头是
    17000c:  str  x1, [sp, #-0x10]!     <- 保存 x1，不是 x0
    170010:  svc  #0x6
    170014:  ldr  x2, [sp]
    170018:  str  w1, [x2]
    17001c:  add  sp, sp, #0x10
    170020:  ret

旧代码只认 `str x0,[sp,#-0x10]!`（0xF81F0FE0），于是把它判成 shape=1（无 prologue），
只改写了 svc 那条指令。结果：
  - prologue 照常执行（sp -= 0x10）
  - 门区直接 ret 回 0x1445a8，包装函数的 `add sp,sp,#0x10` / `ret` 永不执行
  - ⇒ 客机 sp 永久少 0x10 ⇒ 之后所有 ldp x29,x30 都从错位的槽取值
  - ⇒ 实测崩点 pc=0 / x30=0

修法：prologue 判定改成掩掉 Rt 位（低 5 位）后比较，
      覆盖 str xN（任意 N）与 stp xN,xM 两种。
"""
import io, re

P = 'tools/patch_svc.py'
s = io.open(P, encoding='utf-8').read()

old_const = """    STR_PRE = 0xF81F0FE0     # str x0,[sp,#-0x10]!
    STP_PRE = 0xA9BF07E0     # stp x0,x1,[sp,#-0x10]!"""
new_const = """    # ⚠ 必须**掩掉 Rt 位**再比较：包装函数保存的不一定是 x0。
    #   实测 0x17000c（svc#6）开头是 `str x1,[sp,#-0x10]!`（0xF81F0FE1），
    #   只比 0xF81F0FE0 会漏判 ⇒ prologue 跑了却被当成没跑 ⇒ sp 永久少 0x10。
    STR_PRE_MASK = 0xFFFFFFE0
    STR_PRE = 0xF81F0FE0     # str xN,[sp,#-0x10]!   (N 任意)
    STP_PRE = 0xA9BF07E0     # stp xN,xM,[sp,#-0x10]! (N=0,M=1 为准，见下)"""
assert s.count(old_const) == 1
s = s.replace(old_const, new_const)

old_loop = """        if off >= 4 and words[off // 4 - 1] == STR_PRE:
            shape = 2
            entry = off - 4
        elif off >= 4 and words[off // 4 - 1] == STP_PRE:
            if off >= 8 and words[off // 4 - 2] == (STR_PRE | 2):
                shape = 4       # svc #47：str x2 + stp x0,x1
                entry = off - 8
            else:
                shape = 3       # stp x0,x1：两个出参
                entry = off - 4"""
new_loop = """        prev = words[off // 4 - 1] if off >= 4 else 0
        if off >= 4 and (prev & STR_PRE_MASK) == STR_PRE:
            shape = 2
            entry = off - 4
            pro_txt = 'str x%d' % (prev & 0x1F)
        elif off >= 4 and prev == STP_PRE:
            if off >= 8 and (words[off // 4 - 2] & STR_PRE_MASK) == STR_PRE:
                shape = 4       # svc #47：str xN + stp x0,x1
                entry = off - 8
            else:
                shape = 3       # stp x0,x1：两个出参
                entry = off - 4
        else:
            pro_txt = '-'"""
assert s.count(old_loop) == 1
s = s.replace(old_loop, new_loop)

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('patch_svc.py prologue detection fixed')
