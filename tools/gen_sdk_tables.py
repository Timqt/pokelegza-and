#!/usr/bin/env python3
"""生成 SDK NSO 的运行时表（导出符号 + 重定位），做成二进制资产。

为什么做成二进制而不是 C 数组：SDK 有 19,157 个导出符号、19,167 条重定位，
编成 C 数组会让头文件上兆字节、编译极慢。改成二进制资产，运行时用二分查找。

产出：
  work/nso_sdk/sdk_exports.bin  导出符号表（按名字排序，运行时二分）
  work/nso_sdk/sdk_relocs.bin    重定位表

导出符号表格式（每条 8 字节）：
  u32 name_off   —— 名字在 SDK 映像 dynstr（DT_STRTAB）里的偏移
  u32 value      —— 符号值（SDK 映像内偏移）
重定位表格式（每条 16 字节）：
  u32 slot       —— 要写的槽（映像内偏移）
  u32 kind       —— 0=写宿主符号地址  1=写(基址+符号值+addend)  2=写(基址+addend)  3=写0
  u32 sym        —— 符号索引（kind=0 时用；否则为 0）
  u32 addend     —— 加数
  u32 symidx_hi  —— 预留（0）
  u32 pad        —— 预留（0）
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
OUT = os.path.join(ROOT, "work", "nso_sdk")

R_ABS64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1025, 1026, 1027
OUT = os.path.join(ROOT, "work", "nso_sdk")


def build_tables(nso_name, out_dir, prefix):
    """解析一个 NSO，输出导出符号表（+ 重定位表）。返回 (导出数, 重定位数, 需要的宿主符号)。"""
    NSO = os.path.join(ROOT, "work", "base", "exefs2", nso_name)
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
        return (name, strs[name:e].decode("ascii", "replace"), value, shndx)

    # ---- 导出符号（已定义）----
    exports = []
    for i in range(nsym):
        s = sym(i)
        if s and s[3] != 0 and s[1]:
            exports.append((s[1], s[2], s[0]))
    exports.sort(key=lambda x: x[0].encode("ascii", "replace"))
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(out_dir, prefix + "_exports.bin"), "wb") as o:
        o.write(struct.pack("<III", len(exports), strtab, strsz))
        for _, value, name_off in exports:
            o.write(struct.pack("<II", name_off, value))
    print("%s 导出符号 %d 个 -> %s_exports.bin（名字在映像的 dynstr @%#x）" % (prefix, len(exports), prefix, strtab))

    # ---- 重定位 ----
    # kind: 0=宿主符号（按符号名查 SDK 导出表/宿主） 1=基址+符号值+addend 2=基址+addend 3=写0
    rels = []
    for off, size in ((vals.get(7), vals.get(8)), (vals.get(23), vals.get(2))):
        if not off or not size:
            continue
        for i in range(size // 24):
            b = rd(off + i * 24, 24)
            if not b:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            si, typ = r_info >> 32, r_info & 0xFFFFFFFF
            s = sym(si)
            if s is None:
                continue
            name, _, value, shndx = s
            if shndx == 0:
                if typ in (R_JUMP_SLOT, R_GLOB_DAT, R_ABS64):
                    rels.append((r_off, 0, si, r_add & 0xFFFFFFFF))   # 需要解析的符号
                else:
                    rels.append((r_off, 3, 0, 0))
            else:
                if typ in (R_JUMP_SLOT, R_GLOB_DAT, R_ABS64):
                    rels.append((r_off, 1, 0, (value + (r_add & 0xFFFFFFFF)) & 0xFFFFFFFF))
                elif typ == R_RELATIVE:
                    rels.append((r_off, 2, 0, r_add & 0xFFFFFFFF))
                else:
                    rels.append((r_off, 3, 0, 0))
    with open(os.path.join(out_dir, prefix + "_relocs.bin"), "wb") as o:
        o.write(struct.pack("<I", len(rels)))
        for slot, kind, symidx, addend in rels:
            o.write(struct.pack("<IIII", slot, kind, symidx, addend))
    print("%s 重定位 %d 条 -> %s_relocs.bin" % (prefix, len(rels), prefix))
    kinds = {}
    for _, k, _, _ in rels:
        kinds[k] = kinds.get(k, 0) + 1
    print("  kind 分布: %s（0=宿主符号 1=基址+符号值+addend 2=基址+addend 3=写0）" % kinds)

    # SDK 自己的导入（需要宿主解析的）
    need = set()
    for slot, kind, symidx, addend in rels:
        if kind == 0:
            s = sym(symidx)
            if s:
                need.add(s[1])
    print("SDK 需要的宿主符号 %d 个: %s" % (len(need), ", ".join(sorted(need)[:12])))
    with open(os.path.join(out_dir, prefix + "_imports.txt"), "w", encoding="utf-8") as o:
        for n in sorted(need):
            o.write(n + "\n")


def main():
    os.makedirs(OUT, exist_ok=True)
    build_tables("entry_32848007", OUT, "sdk")
    # main 的导出表：SDK 导入的 nnMain / nninitStartup 要从 main 查
    build_tables("entry_0", OUT, "main")


if __name__ == "__main__":
    main()
