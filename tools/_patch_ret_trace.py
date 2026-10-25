# -*- coding: utf-8 -*-
"""把 svc 轨迹的返回值(ret)加进崩溃 dump —— 供一次性的补丁脚本。"""
import io

GUEST = 'app/native/za_guest.c'
API = 'app/native/za_guest_api.h'

old = (
    '        p = za_put_str(p, " sp=");\n'
    '        p = za_put_hex(p, (unsigned long long)za_svc_trace_sp[i]);\n'
    '        p = za_put_str(p, "\\n");'
)
new = (
    '        p = za_put_str(p, " sp=");\n'
    '        p = za_put_hex(p, (unsigned long long)za_svc_trace_sp[i]);\n'
    '        p = za_put_str(p, " ret=");\n'
    '        p = za_put_hex(p, (unsigned long long)za_svc_trace_retv[i]);\n'
    '        p = za_put_str(p, "\\n");'
)

s = io.open(GUEST, encoding='utf-8').read()
n = s.count(old)
print('guest old count =', n)
if n == 1:
    s = s.replace(old, new)
    io.open(GUEST, 'w', encoding='utf-8', newline='').write(s)
    print('guest patched')
elif n != 0:
    raise SystemExit('unexpected count, abort')

h = io.open(API, encoding='utf-8').read()
o2 = 'extern unsigned long za_svc_trace_sp[32];'
n2 = (o2 + '\n'
      'extern unsigned long za_svc_trace_retv[32];\n'
      '// 回填最近一次 svc 的返回值（客机 w0）\n'
      'void za_svc_trace_ret(long r);')
c2 = h.count(o2)
print('api old count =', c2)
if c2 == 1:
    h = h.replace(o2, n2)
    io.open(API, 'w', encoding='utf-8', newline='').write(h)
    print('api patched')
elif c2 != 0:
    raise SystemExit('unexpected api count, abort')
