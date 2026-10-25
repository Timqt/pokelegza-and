# -*- coding: utf-8 -*-
"""给 svc#38 Break 加更强的取证：打印 info 指向的原始字节 + 附近栈，
并额外打印 GetInfo(id=0) 的返回值（CpuMask），因为 0x148f80 的 bics 校验就依赖它。"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """    case 38: // Break(reason=x0, info=x1, size=x2)"""
idx = s.find(old)
assert idx > 0
# 找这一段里的现有 ZLOGI，替换成更详细的版本
seg_end = s.find('    case 39:', idx)
seg = s[idx:seg_end]
print('--- current case 38 block ---')
print(seg[:1600])
