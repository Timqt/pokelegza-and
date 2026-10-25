#!/usr/bin/env python3
"""生成宿主用的 NSO 装载信息（权威版，走 .dynamic / 重定位表）。

流程（依据 SwitchBrew NSO0 规范 + D2R dm/android/native/game_modules.c 的实测做法）：
  image+4 的 u32 = MOD0 头偏移 → MOD0 头 +4 的位移 → .dynamic（Elf64_Dyn 数组）
  → DT_SYMTAB/DT_STRTAB/DT_RELA/DT_JMPREL/DT_PLTGOT/DT_INIT/DT_INIT_ARRAY

重定位语义：
  R_AARCH64_JUMP_SLOT(1025) / GLOB_DAT(257) → 槽里写「解析出的符号地址」
  R_AARCH64_RELATIVE(1027)                   → 槽里写「基址 + addend」

输出：
  app/native/za_imports.h     —— {符号名, GOT 槽映像内偏移}（只列需要宿主解析的）
  app/native/za_guest_info.h  —— 段布局、GOT 基址、入口点、init 地址
  work/nso_relocs.tsv         —— 全部重定位明细
"""
import os, struct, sys
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")

R_ABS64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1025, 1026, 1027

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

def sym(i):
    b = rd(symtab + i * 24, 24)
    if not b:
        return None
    name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
    value, size = struct.unpack_from("<QQ", b, 8)
    e = strs.find(b"\0", name)
    return (strs[name:e].decode("ascii", "replace"), info & 0xF, (info >> 4) & 3, shndx, value, size)

# ---- 收集重定位 ----
# PLT 的 GOT 槽：DT_JMPREL 里的 R_AARCH64_JUMP_SLOT(1026)，r_offset 就是槽地址（连续）
# 直接槽：DT_RELA 里的 R_AARCH64_GLOB_DAT(1025)，点名了符号
plt_slots = []      # [(槽地址, 符号索引)]
direct = {}         # 符号名 -> 槽地址（未定义符号）
rel_rows = []
for tag_key, size_key, label in ((7, 8, "RELA"), (23, 2, "JMPREL")):
    off, size = vals.get(tag_key), vals.get(size_key)
    if not off or not size:
        continue
    for i in range(size // 24):
        b = rd(off + i * 24, 24)
        r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
        si, typ = r_info >> 32, r_info & 0xFFFFFFFF
        s = sym(si)
        name = s[0] if s else "?"
        shndx = s[3] if s else 0
        rel_rows.append((label, r_off, typ, si, name, shndx, r_add & 0xFFFFFFFFFFFFFFFF))
        if typ == R_JUMP_SLOT:
            plt_slots.append((r_off, si))
        elif typ == R_GLOB_DAT and shndx == 0:
            direct[name] = r_off

print("PLT 槽（JUMP_SLOT）%d 个，首槽 %#x；直接槽（GLOB_DAT，未定义符号）%d 个"
      % (len(plt_slots), plt_slots[0][0] if plt_slots else 0, len(direct)))

# ---- 符号 → 槽 的权威映射 ----
# 规则（与 ELF 链接器一致）：
#   走 PLT 的未定义符号，按 dynsym 顺序依次领用 PLT 槽；
#   有直接槽（GLOB_DAT）的未定义符号不占 PLT 槽。
undef_idx = []
for i in range(nsym):
    s = sym(i)
    if s and s[3] == 0:
        undef_idx.append(i)

direct_syms = {sym(i)[0] for i in undef_idx if sym(i)[0] in direct}
print("未定义符号 %d 个；其中有直接槽的 %d 个 → 走 PLT 的 %d 个（PLT 槽 %d 个）"
      % (len(undef_idx), len(direct_syms), len(undef_idx) - len(direct_syms), len(plt_slots)))

host_slots = {}      # 符号名 -> 槽地址
# PLT 槽：JMPREL 的每条 JUMP_SLOT 直接带符号索引 —— 权威对应，无需按顺序推断
for r_off, si in plt_slots:
    s = sym(si)
    if s and s[3] == 0:
        host_slots.setdefault(s[0], r_off)
# 直接槽：GLOB_DAT 点名的未定义符号
for name, r_off in direct.items():
    host_slots.setdefault(name, r_off)

# ABS64 里的未定义符号同样要宿主解析（vtable / typeinfo 槽指向外部模块的符号）。
# 这批符号不在 PLT/GLOB_DAT 里，所以上面两张表看不到它们，必须单独收进来。
abs64_undef = []
for label, r_off, typ, si, name, shndx, addend in rel_rows:
    if typ == R_ABS64 and shndx == 0:
        abs64_undef.append((name, r_off))
for name, r_off in abs64_undef:
    host_slots.setdefault(name, r_off)
print("映射完成：宿主需解析 %d 个符号（PLT %d + 直接 %d + ABS64 %d）"
      % (len(host_slots), len(plt_slots), len(direct), len(abs64_undef)))
missing = [sym(i)[0] for i in undef_idx if sym(i) and sym(i)[0] not in host_slots]
print("无重定位的未定义符号 %d 个（应为未被引用）: %s" % (len(missing), ", ".join(missing[:6])))

with open(os.path.join(ROOT, "work", "nso_relocs.tsv"), "w", encoding="utf-8", newline="\n") as o:
    o.write("# 表\t槽(映像内)\t类型\t符号索引\t符号名\tshndx\taddend\n")
    for r in rel_rows:
        o.write("%s\t%#x\t%d\t%d\t%s\t%d\t%#x\n" % (r[0], r[1], r[2], r[3], r[4], r[5], r[6]))

# ---- 入口点 ----
entry = {}
for i in range(nsym):
    s = sym(i)
    if s and s[3] != 0:
        entry[s[0]] = s[4]
print("入口: nninitStartup=%#x  nnMain=%#x" % (entry.get("nninitStartup", 0), entry.get("nnMain", 0)))

# ---- 生成头文件 ----
hdr = os.path.join(ROOT, "app", "native", "za_imports.h")
with open(hdr, "w", encoding="utf-8", newline="\n") as o:
    o.write("// 自动生成：Z-A main NSO 的导入表（tools/gen_guest_headers.py，别手改）\n")
    o.write("// 依据 .dynamic 的 R_AARCH64_JUMP_SLOT 重定位：槽里写「宿主解析出的符号地址」。\n")
    o.write("// 客机代码的导入桩在 .text 末尾，读的就是这些槽。\n")
    o.write("#ifndef ZA_IMPORTS_H\n#define ZA_IMPORTS_H\n\n")
    o.write("typedef struct { const char *name; unsigned int slot; } za_import_t;\n\n")
    o.write("static const za_import_t za_imports[] = {\n")
    for name in sorted(host_slots):
        o.write('    {"%s", 0x%xu},\n' % (name, host_slots[name]))
    o.write("};\n\n")
    o.write("#define ZA_IMPORT_COUNT %d\n\n" % len(host_slots))
    o.write("#endif\n")
print("已写 %s（%d 条）" % (hdr, len(host_slots)))

info = os.path.join(ROOT, "app", "native", "za_guest_info.h")

# ---- 重定位清单（供 C 装载器用）----
# kind: 0 = 写「宿主解析出的符号地址」，1 = 写「基址 + 符号值 + addend」，
#       2 = 写「基址 + addend」，3 = 写 0（未定义且宿主也无解）
relhdr = os.path.join(ROOT, "app", "native", "za_relocs.h")
host_names = sorted(host_slots)
host_index = {n: i for i, n in enumerate(host_names)}
entries = []
for label, r_off, typ, si, name, shndx, addend in rel_rows:
    if typ in (R_JUMP_SLOT, R_GLOB_DAT, R_ABS64):
        if shndx == 0:
            # 未定义符号 → 宿主解析（dlsym 命中就用，命中不了落到自动桩）
            if name in host_index:
                entries.append((r_off, 0, host_index[name], 0))
            else:
                entries.append((r_off, 3, 0, 0))
        else:
            # 本模块内定义的符号 → 基址 + 符号值 + addend
            s = sym(si)
            val = (s[4] if s else 0) + addend
            entries.append((r_off, 1, 0, val))
    elif typ == R_RELATIVE:
        entries.append((r_off, 2, 0, addend))
with open(relhdr, "w", encoding="utf-8", newline="\n") as o:
    o.write("// 自动生成：Z-A main NSO 的重定位清单（tools/gen_guest_headers.py）\n")
    o.write("// kind: 0=写宿主解析的符号地址（host_index 指向 za_imports.h 的下标）\n")
    o.write("//       1=写「基址 + 符号值」   2=写「基址 + addend」\n")
    o.write("#ifndef ZA_RELOCS_H\n#define ZA_RELOCS_H\n\n")
    o.write("typedef struct { unsigned int slot; unsigned int kind; unsigned int host_index; unsigned long long value; } za_reloc_t;\n\n")
    o.write("static const za_reloc_t za_relocs[] = {\n")
    for e in entries:
        o.write("    {0x%xu, %d, %d, 0x%016xULL},\n" % e)
    o.write("};\n\n")
    o.write("#define ZA_RELOC_COUNT %d\n\n" % len(entries))
    o.write("#endif\n")
print("已写 %s（%d 条重定位）" % (relhdr, len(entries)))

with open(info, "w", encoding="utf-8", newline="\n") as o:
    o.write("// 自动生成：Z-A main NSO 的段布局与入口（tools/gen_guest_headers.py）\n")
    o.write("#ifndef ZA_GUEST_INFO_H\n#define ZA_GUEST_INFO_H\n\n")
    o.write("#define ZA_TEXT_OFF    0x%xu\n" % tmo)
    o.write("#define ZA_TEXT_SIZE   0x%xu\n" % tsz)
    o.write("#define ZA_RODATA_OFF  0x%xu\n" % rmo)
    o.write("#define ZA_RODATA_SIZE 0x%xu\n" % rsz)
    o.write("#define ZA_DATA_OFF    0x%xu\n" % dmo)
    o.write("#define ZA_DATA_SIZE   0x%xu\n" % dsz)
    o.write("#define ZA_BSS_SIZE    0x%xu\n" % bss)
    o.write("#define ZA_IMAGE_SIZE  0x%xu\n" % (dmo + dsz + bss))
    o.write("#define ZA_PLTGOT      0x%xu\n" % vals.get(3, 0))
    o.write("#define ZA_DT_INIT     0x%xu\n" % vals.get(12, 0))
    o.write("#define ZA_DT_INIT_ARRAY 0x%xu\n" % vals.get(25, 0))
    o.write("#define ZA_DT_INIT_ARRAYSZ 0x%xu\n" % vals.get(27, 0))
    o.write("#define ZA_NN_INIT_STARTUP 0x%xu\n" % entry.get("nninitStartup", 0))
    o.write("#define ZA_NN_MAIN        0x%xu\n" % entry.get("nnMain", 0))
    o.write("\n#endif\n")
print("已写 %s" % info)
