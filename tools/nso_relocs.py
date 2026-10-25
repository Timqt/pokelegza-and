#!/usr/bin/env python3
"""导出权威的「符号 → GOT 槽」映射（DT_JMPREL / DT_RELA），并列出全部导出符号找入口点。"""
import os, struct, sys
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")
OUT = os.path.join(ROOT, "work", "nso_relocs.tsv")

d = open(NSO, "rb").read()
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
segd = []
for i, (fo, mo, sz) in enumerate(segs):
    raw = d[fo:fo + csz[i]]
    if flags >> i & 1:
        raw = lz4.block.decompress(raw, uncompressed_size=sz)
    segd.append((mo, sz, raw))
(tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = segd
bss = struct.unpack_from("<I", d, 0x3C)[0]
IMG = bytearray(dmo + dsz + bss)
for mo, sz, raw in segd:
    IMG[mo:mo + sz] = raw

def rd(off, n):
    if off < 0 or off + n > len(IMG):
        return None
    return bytes(IMG[off:off + n])

mod0 = struct.unpack_from("<I", bytes(IMG[4:8]), 0)[0]
disp = struct.unpack_from("<i", rd(mod0, 28), 4)[0]
dyn = mod0 + disp
vals = {}
for i in range(512):
    b = rd(dyn + i * 16, 16)
    if b is None:
        break
    tag, val = struct.unpack_from("<qQ", b, 0)
    if tag == 0:
        break
    vals[tag] = val

symtab, strtab, strsz = vals[6], vals[5], vals[10]
rela, relasz = vals.get(7), vals.get(8)
jmprel, pltrelsz = vals.get(23), vals.get(2)
pltgot = vals.get(3)
nsym = (strtab - symtab) // 24
strs = rd(strtab, strsz)

def sym(i):
    b = rd(symtab + i * 24, 24)
    if not b:
        return None
    name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
    value, size = struct.unpack_from("<QQ", b, 8)
    e = strs.find(b"\0", name)
    return (strs[name:e].decode("ascii", "replace"), info & 0xF, (info >> 4) & 3, shndx, value, size)

R_AARCH64 = {257: "GLOB_DAT", 1025: "JUMP_SLOT", 1024: "ABS64", 1026: "RELATIVE"}
rows = []
for off, size, label in ((rela, relasz, "RELA"), (jmprel, pltrelsz, "JMPREL")):
    if not off or not size:
        continue
    for i in range(size // 24):
        b = rd(off + i * 24, 24)
        r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
        si = r_info >> 32
        typ = r_info & 0xFFFFFFFF
        s = sym(si)
        rows.append((label, r_off, typ, si, s[0] if s else "?", s[3] if s else 0,
                     s[4] if s else 0))

print("重定位总数 %d（RELA %d + JMPREL %d）" % (len(rows), relasz // 24, pltrelsz // 24))
print("DT_PLTGOT = %#x" % pltgot)
jt = [r for r in rows if r[0] == "JMPREL"]
print("JMPREL（PLT 桩）%d 条；类型分布 %s" % (len(jt), {R_AARCH64.get(r[2], r[2]): sum(1 for x in jt if x[2] == r[2]) for r in jt}))

with open(OUT, "w", encoding="utf-8", newline="\n") as o:
    o.write("# 表\tGOT槽(映像内)\t类型\t符号索引\t符号名\tshndx\t符号值\n")
    for r in rows:
        o.write("%s\t%#x\t%s\t%d\t%s\t%d\t%#x\n" % (r[0], r[1], R_AARCH64.get(r[2], r[2]), r[3], r[4], r[5], r[6]))
print("已写 %s" % OUT)

print("\n导出符号（找入口点）：")
defs = [sym(i) for i in range(nsym) if sym(i) and sym(i)[3] != 0]
for s in sorted(defs, key=lambda x: x[4]):
    print("   %-58s value=%#012x size=%#x" % (s[0][:58], s[4], s[5]))
