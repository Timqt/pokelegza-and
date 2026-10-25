#!/usr/bin/env python3
"""探查 SDK 映像里那 21 个「服务槽」到底是什么。

背景：SDK 的 _init（映像偏移 0x400）从 0xb73898..0xb73938 这 21 个槽读函数指针，
传给 0x62f360。实测 5 个是 NULL ⇒ 客机调用它们时跳到 0 ⇒ pc=0 SIGSEGV。

本脚本：
  1) 还原 SDK 映像（text/rodata/data/bss）
  2) 找重定位表里有没有以这 21 个槽为目标的条目 —— 有的话能直接拿到符号名
  3) 打印这 21 个槽周围的原始值、以及它们在 rodata/data 里的位置
  4) 反汇编 0x62f360 附近，看它拿这批指针做什么
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
GOT0 = 0xB73898
NSLOT = 21


def load_nso(path):
    d = open(path, "rb").read()
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
    return IMG, (tmo, tsz), (rmo, rsz), (dmo, dsz), bss


def dyn_info(IMG):
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
    return vals


def main():
    IMG, (tmo, tsz), (rmo, rsz), (dmo, dsz), bss = load_nso(NSO)
    vals = dyn_info(IMG)
    symtab, strtab, strsz = vals[6], vals[5], vals[10]
    nsym = (strtab - symtab) // 24
    strs = bytes(IMG[strtab:strtab + strsz])

    def sym(i):
        b = bytes(IMG[symtab + i * 24:symtab + i * 24 + 24])
        if len(b) < 24:
            return None
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        value, size = struct.unpack_from("<QQ", b, 8)
        e = strs.find(b"\0", name)
        return (name, strs[name:e].decode("ascii", "replace"), value, shndx)

    print("=== 段布局 ===")
    print("text   %#x..%#x" % (tmo, tmo + tsz))
    print("rodata %#x..%#x" % (rmo, rmo + rsz))
    print("data   %#x..%#x" % (dmo, dmo + dsz))
    print("bss    %#x..%#x" % (dmo + dsz, dmo + dsz + bss))
    print("GOT 表 %#x 落在 %s" % (GOT0, "rodata" if rmo <= GOT0 < rmo + rsz else
                                  ("data" if dmo <= GOT0 < dmo + dsz else "text/其它")))

    # --- 重定位表 ---
    rels = []
    for off, size in ((vals.get(7), vals.get(8)), (vals.get(23), vals.get(2))):
        if not off or not size:
            continue
        for i in range(size // 24):
            b = bytes(IMG[off + i * 24:off + i * 24 + 24])
            if len(b) < 24:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            si, typ = r_info >> 32, r_info & 0xFFFFFFFF
            s = sym(si)
            if s is None:
                continue
            name, _, value, shndx = s
            rels.append((r_off, typ, si, name, value, shndx, r_add))

    print("\n=== 以这 21 个槽为目标的重定位 ===")
    hit = 0
    for r_off, typ, si, name, value, shndx, r_add in rels:
        if GOT0 <= r_off < GOT0 + NSLOT * 8 and (r_off - GOT0) % 8 == 0:
            i = (r_off - GOT0) // 8
            print("  槽%-2d @%#x  type=%d sym=%s  symvalue=%#x shndx=%d addend=%d"
                  % (i, r_off, typ, name, value, shndx, r_add))
            hit += 1
    print("命中 %d 条" % hit)

    print("\n=== 槽的原始值（未重定位前的文件内容） ===")
    for i in range(NSLOT):
        off = GOT0 + i * 8
        v = struct.unpack_from("<Q", bytes(IMG[off:off + 8]), 0)[0]
        print("  槽%-2d @%#x = %#018x" % (i, off, v))

    print("\n=== 槽前后各 8 项（看表的边界） ===")
    for i in range(-8, NSLOT + 8):
        off = GOT0 + i * 8
        v = struct.unpack_from("<Q", bytes(IMG[off:off + 8]), 0)[0]
        mark = " <<<" if 0 <= i < NSLOT else ""
        print("  %+3d @%#x = %#018x%s" % (i, off, v, mark))

    # 找出所有指向「这 21 个槽」的引用（代码里 adrp/ldr 到这个区域）
    print("\n=== 谁引用了 0x%x 这个页 ===" % (GOT0 & ~0xFFF))
    # 扫描 text 里的 ADRP 指令，页基址在 ±4GB 内
    page = GOT0 & ~0xFFF
    hits = []
    for off in range(tmo, tmo + tsz, 4):
        w = struct.unpack_from("<I", bytes(IMG[off:off + 4]), 0)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        target = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
        if abs(target - page) < 0x100000:
            hits.append((off, target))
    print("  ADRP 命中 %d 处（前 40）" % len(hits))
    for off, t in hits[:40]:
        print("    @%#x -> %#x" % (off, t))

    # 0x62f360 的前 64 字节机器码
    print("\n=== 0x62f360 附近机器码 ===")
    for off in range(0x62f360, 0x62f360 + 0x60, 4):
        w = struct.unpack_from("<I", bytes(IMG[off:off + 4]), 0)[0]
        print("  %#x: %08x" % (off, w))


if __name__ == "__main__":
    main()
