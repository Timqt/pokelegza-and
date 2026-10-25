# -*- coding: utf-8 -*-
"""在崩溃现场 dump 里找 0x14457c 的 x30 保存槽 [sp0+0x40]，
并列出与它重叠的所有 svc out 指针写区间。

sp0 = 0x14457c 帧内的 sp（= 三条 svc 轨迹里的 sp，0x...e090）
则:
  [sp0+0x40] = x30 槽          (被 ldp x29,x30,[sp,#0x40] 读取)
  [sp0+0x48] = x20 槽
  [sp0+0x50] = x21 槽
  svc#6/#12/#37 的 out 指针:
    0x1445a4 svc#6 : x0 = sp0+0x18  -> 写 MemoryInfo 0x24 字节: sp0+0x18..0x3c
    0x1445c4 svc#12: x0 = sp0+0x18  -> SetMemoryPermission(addr=x0=sp0+0x18, ...)
    0x144604 svc#37: x0 = sp0+0x10  -> 写 8 字节: sp0+0x10..0x18
"""
import sys, re

def main():
    log = sys.argv[1] if len(sys.argv) > 1 else 'work/fatal_now.log'
    txt = open(log, encoding='utf-8', errors='replace').read()

    m = re.search(r'ZaGuest:\s+svc#37 pc=\S+ x0=(\S+) ', txt)
    sp0 = None
    for line in txt.splitlines():
        if 'svc#37' in line and 'sp=' in line:
            sp0 = int(re.search(r'sp=(\S+)', line).group(1), 16)
            break
    if sp0 is None:
        raise SystemExit('no svc#37 line found')

    print('sp0 (0x14457c frame sp) = 0x%x' % sp0)
    print('  x30 slot  = 0x%x' % (sp0 + 0x40))
    print('  x20 slot  = 0x%x' % (sp0 + 0x48))
    print('  x21 slot  = 0x%x' % (sp0 + 0x50))
    print('  svc#6  out (0x24B) = 0x%x .. 0x%x' % (sp0 + 0x18, sp0 + 0x3c))
    print('  svc#37 out (8B)    = 0x%x .. 0x%x' % (sp0 + 0x10, sp0 + 0x18))
    print()

    # 从 "frame-0x40" 那些 dump 行里提取 (addr, words)
    words = {}
    for line in txt.splitlines():
        if not line.startswith('ZaGuest: frame'):
            continue
        parts = line.split()
        addr = int(parts[2], 16)
        for i, w in enumerate(parts[3:]):
            try:
                v = int(w, 16)
            except ValueError:
                continue
            words[addr + i * 8] = v

    def show(a):
        v = words.get(a)
        return '0x%016x' % v if v is not None else '(not in dump)'

    print('--- 关键槽实值 ---')
    for off, name in ((0x10, 'svc#37 out'), (0x18, 'svc#6 MemoryInfo.base'),
                      (0x40, 'x30 (返回地址!)'), (0x48, 'x20'),
                      (0x50, 'x21')):
        print('  sp0+0x%02x %-22s = %s' % (off, name, show(sp0 + off)))

    print()
    print('--- 按地址排序，标出落在 svc out 区间里的槽 ---')
    lo, hi = sp0, sp0 + 0x70
    for a in sorted(words):
        if not (lo <= a < hi):
            continue
        note = ''
        if a == sp0 + 0x40:
            note = '  <<< x30'
        elif a == sp0 + 0x10:
            note = '  <<< svc#37 out'
        elif sp0 + 0x18 <= a < sp0 + 0x3c:
            note = '  <<< svc#6 MemoryInfo'
        print('  +0x%02x = 0x%016x%s' % (a - sp0, words[a], note))

if __name__ == '__main__':
    main()
