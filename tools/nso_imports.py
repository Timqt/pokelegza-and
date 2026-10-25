#!/usr/bin/env python3
"""按 NSO 头字段读导入表：dynsym(0x293c8/0x67b0) + dynstr(0x2fb78/0xae8b)。"""
import os, struct, sys, collections
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

d = open(NSO, "rb").read()
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
out = []
for i, (fo, mo, sz) in enumerate(segs):
    raw = d[fo:fo + csz[i]]
    if flags >> i & 1:
        raw = lz4.block.decompress(raw, uncompressed_size=sz)
    out.append(raw)
text, rodata, data = out

DYNSTR_OFF, DYNSTR_SZ = struct.unpack_from("<II", d, 0x90)
DYNSYM_OFF, DYNSYM_SZ = struct.unpack_from("<II", d, 0x98)
print("dynstr off=%#x size=%#x   dynsym off=%#x size=%#x" % (DYNSTR_OFF, DYNSTR_SZ, DYNSYM_OFF, DYNSYM_SZ))

# 两种基准：rodata 起点 / 映像(text) 起点
def sym_region(base_off, base_name):
    if base_off + DYNSYM_SZ > len(rodata) and base_name == "rodata":
        return None
    return base_off

for base_name, base in (("rodata", rodata), ("text", text)):
    if base_name == "rodata" and DYNSYM_OFF + DYNSYM_SZ > len(rodata):
        print("[%s] dynsym 越界，跳过" % base_name)
        continue
    if base_name == "text" and DYNSYM_OFF + DYNSYM_SZ > len(text):
        print("[%s] dynsym 越界，跳过" % base_name)
        continue
    strs = base[DYNSTR_OFF:DYNSTR_OFF + DYNSTR_SZ]
    syms = base[DYNSYM_OFF:DYNSYM_OFF + DYNSYM_SZ]
    n = len(syms) // 24
    print("\n[%s 基准] dynstr %d 字节, dynsym %d 条" % (base_name, len(strs), n))
    ok = 0
    for i in range(n):
        name, info, other, shndx = struct.unpack_from("<IBBH", syms, i * 24)
        value, size = struct.unpack_from("<QQ", syms, i * 24 + 8)
        if name >= len(strs):
            continue
        end = strs.find(b"\0", name)
        s = strs[name:end].decode("utf-8", "replace")
        if not s or not all(32 <= ord(c) < 127 for c in s):
            continue
        ok += 1
        if i < 12:
            print("   [%3d] st_name=%-6d shndx=%#-6x value=%#012x  %s" % (i, name, shndx, value, s))
    print("   合法符号 %d / %d" % (ok, n))
    if ok > 100:
        # 统计：未定义符号（导入）
        undef = []
        for i in range(n):
            name, info, other, shndx = struct.unpack_from("<IBBH", syms, i * 24)
            value, size = struct.unpack_from("<QQ", syms, i * 24 + 8)
            if name >= len(strs):
                continue
            end = strs.find(b"\0", name)
            s = strs[name:end].decode("utf-8", "replace")
            if s and all(32 <= ord(c) < 127 for c in s) and shndx == 0:
                undef.append((i, s, value, info))
        print("   未定义（导入）符号 %d 个" % len(undef))
        for i, s, v, inf in undef[:25]:
            print("      [%3d] info=%#x value=%#x  %s" % (i, inf, v, s))
        # 按前缀分类
        cat = collections.Counter()
        for _, s, _, _ in undef:
            cat[s.split("::")[0].split("(")[0][:24]] += 1
        print("   前缀分布:", cat.most_common(20))
        outp = os.path.join(ROOT, "work", "nso_imports.txt")
        with open(outp, "w", encoding="utf-8") as o:
            for i, s, v, inf in undef:
                o.write("%d\t%#x\t%s\n" % (i, v, s))
        print("   导入清单已写 %s" % outp)
        break
