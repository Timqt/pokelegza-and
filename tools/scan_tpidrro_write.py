# -*- coding: utf-8 -*-
"""扫全 SDK text，找 `mrs xN,TPIDRRO_EL0` 与 `msr TPIDRRO_EL0, xN`。

⚠ 编码勘误（2026-10-25 实测）：
    MRS Xt, TPIDRRO_EL0 = 0xD53BD060 | Rt    （不是 0xD53BD0C0）
    MSR TPIDRRO_EL0, Xt = 0xD51BD060 | Rt
  用错编码会把 123 个真实读点全部扫成 0 —— 之前就是这么误判的。
"""
import struct

BASE = 'work/nso_32848007'
t = open(BASE + '/text.bin', 'rb').read()
n = len(t) // 4
w = struct.unpack_from('<%dI' % n, t, 0)

MRS_TPIDRRO = 0xD53BD060
MSR_TPIDRRO = 0xD51BD060
MASK = 0xFFFFFFE0

mrs_sites, msr_sites = [], []
for i in range(n):
    x = w[i]
    if (x & MASK) == MRS_TPIDRRO:
        mrs_sites.append((i * 4, x & 0x1F))
    elif (x & MASK) == MSR_TPIDRRO:
        msr_sites.append((i * 4, x & 0x1F))

print('MRS xN,TPIDRRO_EL0 : %d' % len(mrs_sites))
print('MSR TPIDRRO_EL0,xN : %d' % len(msr_sites))
for off, rt in msr_sites:
    print('  %#08x  msr TPIDRRO_EL0, x%d' % (off, rt))

# 与补丁表比对：有没有漏点
import re
s = open('app/native/za_tlsro_patch.h', encoding='utf-8', errors='replace').read()
tab = {int(m.group(1), 16) for m in re.finditer(r'\{(0x[0-9a-fA-F]+)u,', s)}
missing = [off for off, _ in mrs_sites if off not in tab]
extra = [off for off in tab if off not in {o for o, _ in mrs_sites}]
print()
print('补丁表 %d 条；MRS 站点 %d 个' % (len(tab), len(mrs_sites)))
print('漏改写: %d %s' % (len(missing), [hex(x) for x in missing[:10]]))
print('表里多余: %d %s' % (len(extra), [hex(x) for x in extra[:10]]))
