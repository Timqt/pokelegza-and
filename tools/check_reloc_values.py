#!/usr/bin/env python3
"""查跳板槽在我们 sdk_relocs.bin 里的 kind/addend，以及运行时会被填成什么。"""
import os, struct, sys, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import sdk_thunk as ST

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


data = open(os.path.join(ROOT, "work", "nso_sdk", "sdk_relocs.bin"), "rb").read()
nrel = struct.unpack_from("<I", data, 0)[0]
m = {}
for i in range(nrel):
    slot, kind, symidx, addend = struct.unpack_from("<IIII", data, 4 + i * 16)
    m[slot] = (kind, symidx, addend)

# NSO 真实重定位（slot -> (type, 符号名)）
relmap = {}
for off, size in ((vals.get(7), vals.get(8)), (vals.get(23), vals.get(2))):
    if not off or not size:
        continue
    for i in range(size // 24):
        b = bytes(IMG[off + i * 24:off + i * 24 + 24])
        if len(b) < 24:
            break
        r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
        si, typ = r_info >> 32, r_info & 0xFFFFFFFF
        relmap.setdefault(r_off, []).append((typ, sym(si), r_add, si))

want = [0xb76ff8, 0xb77008, 0xb77010, 0xb77018, 0xb770a8, 0xb770b8, 0xb7acf0, 0xb7ad78, 0xb7ad80]
for s in want:
    ours = m.get(s)
    nso = relmap.get(s)
    fv = struct.unpack_from("<Q", bytes(IMG[s:s + 8]), 0)[0]
    print("GOT[%#010x] 文件原值=%#x" % (s, fv))
    print("   我们: kind=%s symidx=%s addend=%s  -> 运行时 = base + addend = %#x" %
          (ours[0], ours[1], hex(ours[2]), 0x200000000 + ours[2]) if ours else "   我们: (没有)")
    if nso:
        for typ, nm, add, si in nso:
            print("   NSO : type=%d sym=%s(add=%#x symidx=%d)" % (typ, nm, add, si))
    else:
        print("   NSO : (没有)")

# 统计：kind 1 且 addend==0 的槽有多少
z = sum(1 for slot, (k, si, ad) in m.items() if k == 1 and ad == 0)
print("\nkind==1 且 addend==0 的槽: %d / %d" % (z, nrel))
# 这些槽里有多少是跳板槽
import scan_thunk_got as TG
ins = TG.disassemble_all()
thunk_slots = set()
for a in sorted(ins):
    t = ins[a]
    mm = re.match(r"^adrp\s+x(\d+),\s*0x([0-9a-f]+)(\s|$)", t)
    if not mm:
        continue
    rd = int(mm.group(1)); page = int(mm.group(2), 16)
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
    thunk_slots.add(page + off)
bad = [s for s in thunk_slots if s in m and m[s][0] == 1 and m[s][2] == 0]
print("跳板槽里 kind==1 且 addend==0 的: %d / %d" % (len(bad), len(thunk_slots)))
for s in bad[:10]:
    nm = ",".join(x[1] for x in relmap.get(s, []))
    print("   GOT[%#010x]  应为 %s" % (s, nm))
