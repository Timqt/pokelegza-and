#!/usr/bin/env python3
"""分析 work/nso_sdk/sdk_reloc.bin：kind 分布 + kind3 槽是否落在跳板表里。"""
import os, struct, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import sdk_thunk as ST

REL = os.path.join(ROOT, "work", "nso_sdk", "sdk_relocs.bin")
data = open(REL, "rb").read()
nrel = struct.unpack_from("<I", data, 0)[0]
print("重定位条数", nrel)

IMG = ST.load()
mod0 = struct.unpack_from("<I", bytes(IMG[4:8]), 0)[0]
disp = struct.unpack_from("<i", bytes(IMG[mod0:mod0 + 28]), 4)[0]
dyn = mod0 + disp
vals = {}
for i in range(512):
    b = bytes(IMG[dyn + i * 16:dyn + i * 16 + 16])
    if len(b) < 16:
        break
    tag, val = struct.unpack_from("<qQ", b, 0)
    if tag == 0:
        break
    vals[tag] = val
symtab, strtab, strsz = vals[6], vals[5], vals[10]
strs = bytes(IMG[strtab:strtab + strsz])


def sym(i):
    b = bytes(IMG[symtab + i * 24:symtab + i * 24 + 24])
    if len(b) < 24:
        return "?"
    name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
    e = strs.find(b"\0", name)
    return strs[name:e].decode("ascii", "replace")


kinds = collections.Counter()
by_kind = collections.defaultdict(list)
for i in range(nrel):
    slot, kind, symidx, addend = struct.unpack_from("<IIII", data, 4 + i * 16)
    kinds[kind] += 1
    if len(by_kind[kind]) < 400000:
        by_kind[kind].append((slot, symidx, addend))

print("kind 分布:", dict(kinds))
for k in sorted(kinds):
    print("\n=== kind %d：%d 条 ===" % (k, kinds[k]))
    lst = by_kind[k]
    if k == 3:
        for slot, symidx, addend in lst[:20]:
            print("   slot=%#010x symidx=%d(%s) addend=%#x" % (slot, symidx, sym(symidx), addend))
    elif k == 0:
        names = collections.Counter(sym(x[1]) for x in lst)
        print("   符号分布(前 20):")
        for nm, c in names.most_common(20):
            print("      %-50s %d" % (nm, c))
    else:
        for slot, symidx, addend in lst[:6]:
            print("   slot=%#010x symidx=%d(%s) addend=%#x" % (slot, symidx, sym(symidx), addend))
