#!/usr/bin/env python3
"""NSO 动态符号表深挖：区分「已定义/未定义」的正确判据，以及 init_array 的链接方式。

要点：NSO 没有节表，st_shndx 恒为 0 —— 判断符号是否「本模块内定义」必须看 st_value，
不能看 shndx（这正是之前把 ABS64 全当未定义符号的根源）。
"""
import os
import struct

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

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
nsym = (strtab - symtab) // 24
strs = rd(strtab, strsz)
syms = []
for i in range(nsym):
    b = rd(symtab + i * 24, 24)
    if not b:
        break
    name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
    value, size = struct.unpack_from("<QQ", b, 8)
    e = strs.find(b"\0", name)
    syms.append((strs[name:e].decode("ascii", "replace"), info & 0xF, (info >> 4) & 3,
                 shndx, value, size))

print("dynsym 共 %d 条" % len(syms))
print("st_shndx 取值分布：%s" % sorted(set(s[3] for s in syms)))
nval = sum(1 for s in syms if s[4] != 0)
print("st_value != 0 的符号：%d 个；st_value == 0 的：%d 个" % (nval, len(syms) - nval))

print("\n名字里带 init_array / fini_array / preinit 的符号：")
for i, s in enumerate(syms):
    n = s[0]
    if "init_array" in n or "fini_array" in n or "preinit" in n:
        print("   [%d] %-40s value=%#x size=%#x bind=%d type=%d shndx=%d"
              % (i, n, s[4], s[5], s[1], s[2], s[3]))

print("\nABS64 用到的几个符号（看 st_value 是否非零）：")
for want in ("__cxa_pure_virtual",
             "_ZTVN10__cxxabiv120__si_class_type_infoE",
             "_ZN2nn5async6detail19TaskCoordinatorBase9DoExecuteERKNS0_17CancellationTokenE",
             "_ZNKSt3__119__shared_weak_count13__get_deleterERKSt9type_info"):
    for i, s in enumerate(syms):
        if s[0] == want:
            print("   [%d] %-64s value=%#x size=%#x bind=%d" % (i, want[:64], s[4], s[5], s[1]))
            break

print("\nGOT 槽 0x3cc44e8 / 0x3cc44f0 的原始内容：")
for off in (0x3CC44E0, 0x3CC44E8, 0x3CC44F0, 0x3CC44F8):
    v = struct.unpack_from("<Q", bytes(rd(off, 8)), 0)[0]
    print("   %#x -> %#018x" % (off, v))

print("\ndynsym 前 8 条：")
for i, s in enumerate(syms[:8]):
    print("   [%d] %-40s value=%#x size=%#x bind=%d type=%d shndx=%d" % (i, s[0][:40], s[4], s[5], s[1], s[2], s[3]))
