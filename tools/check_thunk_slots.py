#!/usr/bin/env python3
"""核对 7946 个跳板槽：我们的 sdk_relocs.bin 有没有覆盖？文件原值是多少？"""
import os, struct, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import sdk_thunk as ST
import scan_thunk_got as TG

IMG = ST.load()
DATA_OFF = 0xB3B000
DATA_SZ = 0x544E0

# 我们的重定位表
data = open(os.path.join(ROOT, "work", "nso_sdk", "sdk_relocs.bin"), "rb").read()
nrel = struct.unpack_from("<I", data, 0)[0]
our_slots = set()
for i in range(nrel):
    slot, kind, symidx, addend = struct.unpack_from("<IIII", data, 4 + i * 16)
    our_slots.add(slot)

# NSO 真实重定位表（带符号）
rel = TG.reloc_map()

ins = TG.disassemble_all()
slots = {}
import re
for a in sorted(ins):
    t = ins[a]
    m = re.match(r"^adrp\s+x(\d+),\s*0x([0-9a-f]+)(\s|$)", t)
    if not m:
        continue
    rd = int(m.group(1)); page = int(m.group(2), 16)
    m1 = re.match(r"^ldr\s+x(\d+),\s*\[x(\d+),\s*#0x([0-9a-f]+)\](\s|$)", ins.get(a + 4, ""))
    if not m1 or int(m1.group(2)) != rd:
        continue
    rt = int(m1.group(1)); off = int(m1.group(3), 16)
    m2 = re.match(r"^add\s+x(\d+),\s*x(\d+),\s*#0x([0-9a-f]+)(\s|$)", ins.get(a + 8, ""))
    if not m2 or int(m2.group(1)) != rd or int(m2.group(2)) != rd or int(m2.group(3), 16) != off:
        continue
    m3 = re.match(r"^br\s+x(\d+)(\s|$)", ins.get(a + 12, ""))
    if not m3 or int(m3.group(1)) != rt:
        continue
    slots.setdefault(page + off, []).append(a)

print("跳板槽 %d 个" % len(slots))
covered = [s for s in slots if s in our_slots]
nso_rel = [s for s in slots if s in rel]
print("  我们的 sdk_relocs.bin 覆盖: %d" % len(covered))
print("  NSO 真实重定位表覆盖    : %d" % len(nso_rel))
print("  两者都没有（文件原值）  : %d" % len([s for s in slots if s not in our_slots and s not in rel]))

# 文件原值统计
zero = 0
in_data = 0
outside = 0
samples = []
for s in slots:
    if DATA_OFF <= s < DATA_OFF + DATA_SZ:
        in_data += 1
        v = struct.unpack_from("<Q", bytes(IMG[s:s + 8]), 0)[0]
        if v == 0:
            zero += 1
            if len(samples) < 12:
                nm = ",".join(x[1] for x in rel.get(s, [])) or "(无重定位)"
                samples.append((s, nm, v))
    else:
        outside += 1
print("\n槽在 .data 段内: %d，其中文件原值=0 的: %d；不在 .data 段内的: %d" % (in_data, zero, outside))
print("原值为 0 的样例:")
for s, nm, v in samples:
    print("   GOT[%#010x] = %#x   应该是 %s" % (s, v, nm))

# NSO 重定位里这些槽的类型
print("\nNSO 重定位表里这些槽的类型分布:")
tc = collections.Counter()
for s in slots:
    for typ, nm, val in rel.get(s, []):
        tc[typ] += 1
print("  ", dict(tc), "（1025=GLOB_DAT 1026=JUMP_SLOT 257=ABS64 1027=RELATIVE）")
