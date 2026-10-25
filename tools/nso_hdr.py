#!/usr/bin/env python3
"""dump main NSO 头字段 + 定位 dynstr/dynsym（按头字段，不做全段扫描）。"""
import os, struct, sys
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

d = open(NSO, "rb").read()
print("文件 %d 字节 magic=%r" % (len(d), d[:4]))
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
print("flags=%#x" % flags)
for i, (fo, mo, sz) in enumerate(segs):
    print("  seg%d fileOff=%#x memOff=%#x size=%#x  压缩后=%#x" % (i, fo, mo, sz, csz[i]))

# 头里 0x40..0xA0 全 dump，找 dynstr/dynsym 相关的成对 (offset,size)
print("\n--- 头 0x40..0xA0 ---")
for off in range(0x40, 0xA0, 4):
    v = struct.unpack_from("<I", d, off)[0]
    if v:
        print("  +0x%02X = %d (%#x)" % (off, v, v))

# 解出 rodata 与 data
out = []
for i, (fo, mo, sz) in enumerate(segs):
    raw = d[fo:fo + csz[i]]
    if flags >> i & 1:
        raw = lz4.block.decompress(raw, uncompressed_size=sz)
    out.append(raw)
text, rodata, data = out
print("\n解压后: text=%d rodata=%d data=%d" % (len(text), len(rodata), len(data)))

# 动态符号表（NSO 里放在 rodata）：每条 24 字节 Elf64_Sym
# 头里的 dynsym/dynstr 偏移是**映像内**偏移还是 rodata 内偏移？两种都试。
def try_sym(blob, base, label):
    """在 blob 里找 dynsym：24 字节一条，st_name 指向 blob 内的字符串。"""
    found = []
    for off in range(0, len(blob) - 24, 4):
        name, info, other, shndx = struct.unpack_from("<IBBH", blob, off)
        value, size = struct.unpack_from("<QQ", blob, off + 8)
        if 0 < name < len(blob) and shndx in (0, 0xFFF1) and value < 0x100000000:
            s = blob[name:blob.find(b"\0", name)]
            if s and all(32 <= c < 127 for c in s) and len(s) > 2:
                found.append((off, name, s.decode(), shndx, value))
    if found:
        print("%s: %d 个候选符号，例：" % (label, len(found)))
        for f in found[:12]:
            print("   off=%#x name=%r shndx=%#x value=%#x" % f)
    return found

print("\n--- 试 rodata 作为符号表来源 ---")
try_sym(rodata, 0, "rodata")
print("\n--- 试 data 段 ---")
try_sym(data, 0, "data")
