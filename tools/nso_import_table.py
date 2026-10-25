#!/usr/bin/env python3
"""生成 NSO 导入表：符号名 ↔ GOT 槽（装载时把解析出的地址写进 GOT 槽）。

NSO 的导入桩在 .text 末尾，每个 16 字节：
    adrp x16, <GOT 页>
    ldr  x17, [x16, #off]     ← 从 GOT 槽读出目标地址
    add  x16, x16, #off
    br   x17                  ← 跳过去
GOT 在 .data 段（装载器唯一可写的段）。桩序 == GOT 槽序 == dynsym 里未定义符号的顺序。
"""
import os, struct, sys, collections
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")
BASE = 0x140000000

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

DYNSTR_OFF, DYNSTR_SZ = struct.unpack_from("<II", d, 0x90)
DYNSYM_OFF, DYNSYM_SZ = struct.unpack_from("<II", d, 0x98)
strs = rodata[DYNSTR_OFF:DYNSTR_OFF + DYNSTR_SZ]
syms = rodata[DYNSYM_OFF:DYNSYM_OFF + DYNSYM_SZ]

def name_at(off):
    if off >= len(strs):
        return None
    e = strs.find(b"\0", off)
    s = strs[off:e]
    if not s or len(s) > 200:
        return None
    try:
        t = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(32 <= ord(c) < 127 for c in t) else None

undef = []
for i in range(len(syms) // 24):
    name, info, other, shndx = struct.unpack_from("<IBBH", syms, i * 24)
    if shndx == 0:
        n = name_at(name)
        if n:
            undef.append((n, info & 0xF, (info >> 4) & 0xF))   # (名字, 类型, 绑定)
by_type = collections.Counter((t, b) for _, t, b in undef)
print("未定义（导入）符号 %d 个，类型/绑定分布:" % len(undef))
for (t, b), c in sorted(by_type.items()):
    print("   type=%d bind=%d -> %d" % (t, b, c))
print("（type: 0=NOTYPE 1=OBJECT 2=FUNC；bind: 0=LOCAL 1=GLOBAL 2=WEAK）")

# ---- 找 .text 末尾的导入桩 ----
n = len(text) // 4
words = struct.unpack_from("<%dI" % n, text, 0)

def adrp_page(off):
    w = words[off // 4]
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    page = (((immhi << 2) | immlo) << 12) + (off & ~0xFFF)
    return page

def ldr_off(off):
    w = words[off // 4]
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return ((w >> 10) & 0xFFF) * 8

stubs = []
i = n - 4
while i >= 0 and len(stubs) < 4000:
    if i + 3 >= n:
        break
    p = adrp_page(i * 4)
    o = ldr_off((i + 1) * 4)
    w2 = words[i + 2]
    w3 = words[i + 3]
    if p is not None and o is not None and (w2 & 0xFFC00000) == 0x91000000 and (w3 & 0xFFFFFC1F) == 0xD61F0000:
        stubs.append((i * 4, p + o))
        i -= 4
        continue
    if stubs and len(stubs) >= 1001:
        break
    i -= 1
stubs.reverse()
print("找到导入桩 %d 个（text 偏移 %#x..%#x）" % (len(stubs), stubs[0][0], stubs[-1][0]))

# GOT 槽应连续
gaps = collections.Counter(b[1] - a[1] for a, b in zip(stubs, stubs[1:]))
print("GOT 槽相邻差值:", gaps.most_common(4))
got0 = stubs[0][1]
print("GOT 首槽（映像内）= %#x  → data 段内偏移 %#x" % (got0, got0 - dmo))
print("GOT 末槽（映像内）= %#x" % stubs[-1][1])

# 符号 ↔ 槽：1001 个未定义符号 ↔ 1001 个 GOT 槽，按 dynsym 顺序一一对应
got_img = stubs[0][1] if stubs else 0
got_data = got_img - dmo
slots = [struct.unpack_from("<Q", data, got_data + k * 8)[0] for k in range(len(undef))]
with_stub = sum(1 for v in slots if v)
print("GOT 槽 %d 个：有桩 %d，无桩 %d" % (len(slots), with_stub, len(slots) - with_stub))

# 映射规则：按 dynsym 顺序，GOT 槽非零的符号依次领用 .text 末尾的桩（槽值为 0 = 该符号没有桩）
# （桩区 917 个、槽非零 917 个，数目吻合；槽里原本存的是统一的占位桩地址 0x2FC38E0）
stub_area = sorted(s[0] for s in stubs)
assigned = []
si = 0
for i, (name, t, b) in enumerate(undef):
    slot = got_data + i * 8
    stub = None
    if slots[i] != 0:
        if si < len(stub_area):
            stub = stub_area[si]; si += 1
        else:
            print("!! 桩不够用：符号 %s" % name)
    assigned.append((name, t, b, slot, stub))

stubbed = sum(1 for a in assigned if a[4] is not None)
print("导入 %d 个：有桩 %d，无桩 %d；桩用掉 %d" % (len(assigned), stubbed, len(assigned) - stubbed, si))

out = os.path.join(ROOT, "work", "nso_import_table.tsv")
with open(out, "w", encoding="utf-8", newline="\n") as o:
    o.write("# 符号名\tGOT槽(data内偏移)\tGOT槽(映像内偏移)\t桩(text内偏移)\t类型\t绑定\n")
    for name, t, b, slot, stub in assigned:
        o.write("%s\t%#x\t%#x\t%s\t%d\t%d\n" % (name, slot, slot + dmo, ("%#x" % stub) if stub is not None else "-", t, b))
print("导入表已写 %s" % out)

# 导入面统计：宿主要实现哪些
import re
def bucket(n):
    if n.startswith("_ZN2nn3hid") or n.startswith("_ZN2nn3fs") or n.startswith("_ZN2nn4time"): return "nn::hid/fs/time"
    if n.startswith("_ZN2nn2os"): return "nn::os"
    if n.startswith("_ZN2nn3err") or n.startswith("_ZN2nn3res"): return "nn::err/res"
    if n.startswith("_ZN2nn3mem"): return "nn::mem"
    if n.startswith("_ZN2nn3svc"): return "nn::svc"
    if n.startswith("_ZN2nn4fs") or n.startswith("_ZN2nn4hid"): return "nn::fs/hid"
    if n.startswith("_ZNSt3__1") or n.startswith("_ZSt") or n.startswith("_ZNSt"): return "libc++"
    if n.startswith("_ZN2nn3wsi") or n.startswith("nvn") or "nvn" in n: return "nvn/wsi"
    if n.startswith("_ZN2nn6crypto") or n.startswith("_ZN2nn4util"): return "nn::crypto/util"
    if n.startswith("_ZN2nn3account") or n.startswith("_ZN2nn5async") or n.startswith("_ZN2nn5prepo") or n.startswith("_ZN2nn4bcat"): return "nn::网络/账号"
    if n.startswith("__") or n.startswith("_Z") or n.startswith("_") and "(" in n: return "C 运行库"
    return "其它"
cnt = collections.Counter(bucket(a[0]) for a in assigned)
print("\n导入面分布：")
for k, v in cnt.most_common():
    print("   %-22s %4d" % (k, v))
print("\n前 10 个导入 (符号 / GOT 槽 / 桩):")
for name, t, b, slot, stub in assigned[:10]:
    print("   %-50s slot=%#x stub=%s" % (name[:50], slot, ("%#x" % stub) if stub else "-"))
