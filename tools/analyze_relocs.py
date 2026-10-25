#!/usr/bin/env python3
"""分析 NSO 重定位表：ABS64 的符号归属、addend 分布、init_array 覆盖情况。

用途：确认「运行时该往槽里写什么」—— 这是客机装载正确性的关键。
"""
import collections
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSV = os.path.join(ROOT, "work", "nso_relocs.tsv")

R_ABS64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1025, 1026, 1027

rows = []
for line in open(TSV, encoding="utf-8"):
    if line.startswith("#") or not line.strip():
        continue
    p = line.rstrip("\n").split("\t")
    rows.append((p[0], int(p[1], 16), int(p[2]), int(p[3]), p[4], int(p[5]), int(p[6], 16)))

print("总重定位 %d" % len(rows))
print("类型分布 %s" % dict(collections.Counter(r[2] for r in rows)))

abs64 = [r for r in rows if r[2] == R_ABS64]
undef = [r for r in abs64 if r[5] == 0]
defd = [r for r in abs64 if r[5] != 0]
print("\nABS64 %d 条：未定义符号 %d，已定义符号 %d" % (len(abs64), len(undef), len(defd)))

print("未定义 ABS64 的 addend 分布：%s"
      % dict(collections.Counter(r[6] for r in undef).most_common(6)))
print("已定义 ABS64 的 addend 分布：%s"
      % dict(collections.Counter(r[6] for r in defd).most_common(6)))

print("\n未定义 ABS64 样例：")
for r in undef[:5]:
    print("   slot=%#x sym=%s addend=%#x" % (r[1], r[4], r[6]))
print("已定义 ABS64 样例：")
for r in defd[:5]:
    print("   slot=%#x sym=%s value=%#x addend=%#x" % (r[1], r[4], r[6], r[6]))

INIT_OFF, INIT_SZ = 0x39E1000, 0x3BC0
in_init = [r for r in abs64 if INIT_OFF <= r[1] < INIT_OFF + INIT_SZ]
print("\ninit_array 区间 [%#x,%#x)：ABS64 命中 %d 条（条目数 %d）"
      % (INIT_OFF, INIT_OFF + INIT_SZ, len(in_init), INIT_SZ // 8))
kinds = collections.Counter((r[5] == 0) for r in in_init)
print("  其中未定义符号 %d，已定义 %d" % (kinds[True], kinds[False]))
for r in in_init[:4]:
    print("   slot=%#x sym=%s shndx=%d" % (r[1], r[4], r[5]))

# 全局：有多少 ABS64 的槽落在 data 段
DATA_OFF, DATA_SIZE = 0x39E1000, 0x39E1C0
print("\nABS64 槽所在段分布：")
seg = collections.Counter()
for r in abs64:
    if r[1] < 0x2FC7250:
        seg["text"] += 1
    elif r[1] < DATA_OFF:
        seg["rodata"] += 1
    elif r[1] < DATA_OFF + DATA_SIZE:
        seg["data"] += 1
    else:
        seg["bss/其它"] += 1
print("  %s" % dict(seg))
