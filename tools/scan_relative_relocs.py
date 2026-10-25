#!/usr/bin/env python3
"""在 NSO 文件里全盘扫描 R_AARCH64_RELATIVE(1027) 重定位记录。

背景：Z-A 的 main NSO 的 .dynamic 里 DT_RELA/DT_JMPREL 合起来只有
257(ABS64)/1025(GLOB_DAT)/1026(JUMP_SLOT) 三种，一条 RELATIVE 都没有。
但 init_array 里存的是模块内偏移（没有重定位覆盖），
说明「模块内指针」的重定位要么在别处，要么根本不在文件里。

扫描办法：r_info 的低 32 位是类型，1027 = 0x403 → 字节模式 03 04 00 00。
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

d = open(NSO, "rb").read()
print("文件: %s（%.1f MB）" % (NSO, len(d) / 1048576))

PAT = b"\x03\x04\x00\x00"   # r_info 低 32 位 = 1027
hits = []
pos = 0
while True:
    i = d.find(PAT, pos)
    if i < 0:
        break
    pos = i + 1
    # r_info 在重定位记录里的偏移是 8（r_offset 占前 8 字节）
    rinfo_off = i - 8
    if rinfo_off < 0 or rinfo_off + 24 > len(d):
        continue
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, rinfo_off)
    sym = r_info >> 32
    if sym != 0:
        continue          # RELATIVE 的符号索引必须是 0
    if r_off == 0 and r_add == 0:
        continue          # 全零填充
    hits.append((rinfo_off, r_off, r_add & 0xFFFFFFFFFFFFFFFF))

print("命中 RELATIVE 形态记录 %d 条" % len(hits))
for off, r_off, r_add in hits[:40]:
    print("   文件偏移 %#x  r_offset=%#x  addend=%#x" % (off, r_off, r_add))

if len(hits) > 1:
    offs = sorted(r_off for _, r_off, _ in hits)
    print("r_offset 范围: %#x .. %#x" % (offs[0], offs[-1]))
    # 是否连续 8 字节步进（典型数组）
    step = offs[1] - offs[0]
    print("首两条 r_offset 间距: %#x（8 表示是紧密数组）" % step)
