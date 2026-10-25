# -*- coding: utf-8 -*-
"""把 za_horizon.c 里的 IPC 辅助函数块从 switch 内部挪到函数外部。

函数定义不能出现在 switch 的 case 之间（C 不允许 label 后面跟定义）。
用法: python tools/_move_ipc_helpers.py
"""
import io
import os

P = r'D:\feiniukexinhome\Code\pokeLegza-and\app\native\za_horizon.c'
lines = io.open(P, encoding='utf-8').read().split('\n')

# 1) 找块起点：含 "#define ZA_FAKE_SVC_BASE" 的行往上找到第一行 "// ═"
idx_def = None
for i, l in enumerate(lines):
    if '#define ZA_FAKE_SVC_BASE' in l:
        idx_def = i
        break
assert idx_def is not None, 'anchor ZA_FAKE_SVC_BASE not found'

start = idx_def
while start > 0 and not lines[start].startswith('// ═'):
    start -= 1

# 2) 找块终点：含 'snprintf(p, 64, "%#lx", a);' 的行之后的第一个 '}' 行
idx_snp = None
for i, l in enumerate(lines):
    if 'snprintf(p, 64, "%#lx", a);' in l:
        idx_snp = i
        break
assert idx_snp is not None, 'anchor snprintf not found'

end = idx_snp
while end < len(lines) and lines[end].strip() != '}':
    end += 1
end += 1   # 含 '}' 行

block = lines[start:end]
print('block lines %d..%d (%d lines)' % (start + 1, end, len(block)))
print('  first: %s' % block[0][:70])
print('  last : %s' % block[-1][:70])

rest = lines[:start] + lines[end:]

# 3) 插到 za_horizon_dispatch 之前
ins = None
for i, l in enumerate(rest):
    if l.startswith('static long za_horizon_dispatch('):
        ins = i
        break
assert ins is not None, 'za_horizon_dispatch not found'
print('insert before line %d: %s' % (ins + 1, rest[ins][:70]))

out = rest[:ins] + block + [''] + rest[ins:]
io.open(P, 'w', encoding='utf-8', newline='').write('\n'.join(out))
print('done, file now %d lines' % len(out))
