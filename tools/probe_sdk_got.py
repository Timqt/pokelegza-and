#!/usr/bin/env python3
"""查 SDK 的 GOT 区 0xb77160 起那批跳板槽到底对应哪些符号。

背景：SDK 的 0x62f360 不是函数，是 PLT 风格跳板表：
    adrp x16, <page> ; ldr x17,[x16,#off] ; add x16,x16,#off ; br x17
每个 16 字节一项，目标地址存在 GOT 的 0xb77160+8*i。

用法：python tools/probe_sdk_got.py [起址] [个数]
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
TEXT_OFF, TEXT_SZ = 0x0, 0x64E230
RODATA_OFF, RODATA_SZ = 0x64F000, 0x4EC000
DATA_OFF, DATA_SZ = 0xB3B000, 0x544E0


def load():
    d = open(NSO, "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    out = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        out.append((mo, sz, raw))
    (tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = out
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    IMG = bytearray(dmo + dsz + bss)
    for mo, sz, raw in out:
        IMG[mo:mo + sz] = raw
    return IMG


def main():
    lo = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xB77160
    n = int(sys.argv[2], 0) if len(sys.argv) > 2 else 24
    IMG = load()
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

    # 重定位：slot -> 符号
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
            s = sym(si)
            if s is None:
                continue
            relmap.setdefault(r_off, []).append((typ, s[1], s[2], s[3], r_add))

    print("=== GOT %#x 起 %d 个槽 ===" % (lo, n))
    for i in range(n):
        off = lo + i * 8
        raw = struct.unpack_from("<Q", bytes(IMG[off:off + 8]), 0)[0]
        rel = relmap.get(off)
        if rel:
            for typ, name, value, shndx, add in rel:
                print("  槽%-2d @%#x 文件值=%#018x  reloc type=%d sym=%s val=%#x shndx=%d add=%d"
                      % (i, off, raw, typ, name, value, shndx, add))
        else:
            print("  槽%-2d @%#x 文件值=%#018x  (无重定位)" % (i, off, raw))

    # 顺带把跳板表扫一遍：找出所有 adrp/ldr/add/br 的 thunk，并列出它们指向的 GOT 槽
    print("\n=== text 里的跳板表扫描（adrp+ldr+add+br 四联） ===")
    thunks = []
    for off in range(0, TEXT_SZ - 16, 4):
        w = struct.unpack_from("<I", bytes(IMG[off:off + 4]), 0)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
        w2 = struct.unpack_from("<I", bytes(IMG[off + 4:off + 8]), 0)[0]
        if (w2 & 0xFFC00000) != 0xF9400000:
            continue
        imm12 = (w2 >> 10) & 0xFFF
        scale = 8 if (w2 & 0xC0000000) == 0xF9400000 else 4
        rn = (w2 >> 5) & 0x1F
        if rn != 16:
            continue
        w3 = struct.unpack_from("<I", bytes(IMG[off + 8:off + 12]), 0)[0]
        if (w3 & 0xFFC00000) != 0x91000000:
            continue
        imm12b = (w3 >> 10) & 0xFFF
        if imm12b != imm12 * scale:
            continue
        w4 = struct.unpack_from("<I", bytes(IMG[off + 12:off + 16]), 0)[0]
        if (w4 & 0xFFFFFC1F) != 0xD61F0000:
            continue
        got = page + imm12 * scale
        thunks.append((off, got))
    print("跳板 %d 个" % len(thunks))
    seen = {}
    for off, got in thunks:
        seen.setdefault(got, []).append(off)
    for got in sorted(seen):
        r = relmap.get(got)
        nm = ""
        if r:
            nm = "  <- " + ", ".join("%s(val=%#x,shndx=%d)" % (x[1], x[2], x[3]) for x in r)
        else:
            nm = "  (无重定位，文件值=%#x)" % struct.unpack_from("<Q", bytes(IMG[got:got + 8]), 0)[0]
        print("  GOT %#x 被 %d 个跳板引用（首个 @%#x）%s" % (got, len(seen[got]), seen[got][0], nm))


if __name__ == "__main__":
    main()
