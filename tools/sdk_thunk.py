#!/usr/bin/env python3
"""把 SDK 里的跳板（thunk）地址解析成它跳转到的符号名。

SDK 的 PLT 风格跳板：adrp x16,<GOT页> ; ldr x17,[x16,#off] ; add x16,x16,#off ; br x17
⇒ 目标是 GOT 槽里的符号。

用法：python tools/sdk_thunk.py 0x632cb0 0x636760 0x55a740 ...
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
TEXT_SZ = 0x64E230


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


def adrp_target(off, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def ldr_off(w):
    """LDR (unsigned imm, 64-bit) 的字节偏移；不是则 None。"""
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return ((w >> 10) & 0xFFF) * 8


def main():
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
            if s:
                relmap.setdefault(r_off, []).append((typ, s[1], s[2], s[3]))

    for arg in sys.argv[1:]:
        a = int(arg, 0)
        w0 = struct.unpack_from("<I", bytes(IMG[a:a + 4]), 0)[0]
        w1 = struct.unpack_from("<I", bytes(IMG[a + 4:a + 8]), 0)[0]
        if (w0 & 0x9F000000) != 0x90000000:
            print("%#x: 不是 adrp" % a)
            continue
        page = adrp_target(a, w0)
        off = ldr_off(w1)
        if off is None:
            print("%#x: 第二条不是 ldr(imm)" % a)
            continue
        got = page + off
        rel = relmap.get(got)
        nm = ", ".join("%s(val=%#x,shndx=%d)" % (x[1], x[2], x[3]) for x in rel) if rel else "(无重定位)"
        print("%#x -> GOT %#x : %s" % (a, got, nm))


if __name__ == "__main__":
    main()
