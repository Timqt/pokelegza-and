#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 rodata / data 里找崩溃寄存器里那两对 ASCII 字节的来源。

崩溃现场（files/za_fatal.log）:
  x6 = 0x202c42202c41202c   -> 小端字节 ", A, B, "
  x7 = 0x2943202c42202c41   -> 小端字节 "A, B, C)"
两个是**相邻的 8 字节**（偏移 +0 和 +8），所以搜连续 16 字节 ", A, B, A, B, C)"。
同时单独搜 ", A, B" 和 "A, B, C"，报告命中位置与上下文。
"""
import sys, struct

def u64(x):
    return struct.pack('<Q', x)

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'work/nso_32848007'
    pats = []
    # 组合 16 字节
    comb = u64(0x202c42202c41202c) + u64(0x2943202c42202c41)
    pats.append(('REG16  x6|x7  (16B)', comb))
    pats.append(('REG8   x6      (8B)', u64(0x202c42202c41202c)))
    pats.append(('REG8   x7      (8B)', u64(0x2943202c42202c41)))
    # 也直接搜可读片段（可能是未对齐/带前缀的长串）
    pats.append(('ASCII  ", A, B"  ', b', A, B'))
    pats.append(('ASCII  "A, B, C"  ', b'A, B, C'))
    pats.append(('ASCII  "B, C)"    ', b'B, C)'))

    for name in ('rodata.bin', 'data.bin', 'text.bin'):
        path = base + '/' + name
        try:
            blob = open(path, 'rb').read()
        except OSError as e:
            print('skip %s (%s)' % (path, e))
            continue
        print('=== %s  size=0x%x ===' % (path, len(blob)))
        for label, pat in pats:
            hits = []
            start = 0
            while True:
                k = blob.find(pat, start)
                if k < 0:
                    break
                hits.append(k)
                start = k + 1
                if len(hits) >= 12:
                    break
            if not hits:
                print('  %-22s : (none)' % label)
                continue
            print('  %-22s : %d hit(s)' % (label, len(hits)))
            for k in hits[:8]:
                # 打印上下文字符串（取可打印段）
                a = k
                while a > 0 and 32 <= blob[a-1] < 127:
                    a -= 1
                b = k
                while b < len(blob) and 32 <= blob[b] < 127:
                    b += 1
                ctx = blob[a:min(b, a+120)]
                print('       off=0x%06x  ctx="%s"' % (k, ctx.decode('latin-1')))
        print()

if __name__ == '__main__':
    main()
