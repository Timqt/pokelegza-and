#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 main 模块（客机本体）里找崩溃寄存器那两对 UTF-16LE 字节。

崩溃现场:
  x6 = 0x202c42202c41202c  -> UTF-16LE ", A, B, "
  x7 = 0x2943202c42202c41  -> UTF-16LE "A, B, C)"
  frame-0x100: 0x5f004400540053 = "SD_"   0x5a00300031005f = "_10Z"  (UTF-16LE)

⇒ 这批寄存器持有的是 main 模块里**某段 UTF-16 文本**的载荷，
  说明崩溃点所在的代码路径在处理 main 的数据（很可能是名称/枚举字符串表）。
"""
import sys

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'work/nso'
    import os
    pats = [
        ('u16x8 ", A, B, "', b',\x00 \x00A\x00,\x00 \x00B\x00,\x00 \x00'),
        ('u16x8 "A, B, C)"', b'A\x00,\x00 \x00B\x00,\x00 \x00C\x00)\x00'),
        ('utf16 ", A, B"',   ', A, B'.encode('utf-16-le')),
        ('utf16 "A, B, C"',  'A, B, C'.encode('utf-16-le')),
        ('utf16 "SD_"',      'SD_'.encode('utf-16-le')),
        ('utf16 "_10Z"',     '_10Z'.encode('utf-16-le')),
        ('utf16 "ZA"',       'ZA'.encode('utf-16-le')),
    ]
    for name in os.listdir(base):
        if not name.endswith('.bin'):
            continue
        path = os.path.join(base, name)
        try:
            blob = open(path, 'rb').read()
        except OSError:
            continue
        lines = []
        for label, pat in pats:
            cnt = blob.count(pat)
            if cnt:
                k = blob.find(pat)
                lines.append('  %-20s : %5d hit(s), first=0x%06x' % (label, cnt, k))
        if lines:
            print('=== %s  size=0x%x ===' % (path, len(blob)))
            for l in lines:
                print(l)
            print()

if __name__ == '__main__':
    main()
