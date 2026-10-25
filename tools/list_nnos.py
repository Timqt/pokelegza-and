#!/usr/bin/env python3
"""列出 SDK 导出的 `nnos*`（OS 接口）函数，以及每个函数实际用的「注入槽」。

Switch 上这些函数由 OS 实现；SDK NSO 里只是薄包装 —— 真正的实现放在 .data/.bss
的槽里，由 OS 在装载 NSO 时填进去。我们这边得自己填。

用法：python tools/list_nnos.py
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
TEXT_SZ = 0x64E230
DATA_OFF, DATA_SZ = 0xB3B000, 0x544E0
IMG_SIZE = DATA_OFF + DATA_SZ + 0xCEB20


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
    IMG = load()
    W = struct.unpack_from("<%dI" % (len(IMG) // 4), bytes(IMG), 0)
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

    # 导出表
    exports = []
    for i in range(nsym):
        s = sym(i)
        if s and s[3] != 0 and s[1]:
            exports.append((s[1], s[2]))
    nnos = sorted([e for e in exports if e[0].startswith("nnos")], key=lambda x: x[1])
    print("=== 导出的 nnos* 函数 %d 个 ===" % len(nnos))
    for name, val in nnos:
        print("  %-52s @%#x" % (name, val))

    # 每个 nnos 函数体里用到的槽
    print("\n=== 每个 nnos 函数用到的注入槽 ===")
    for name, val in nnos:
        # 从 val 起 0x100 字节内找 adrp/ldr/br 模式
        slots = set()
        pages = {}
        for off in range(val, min(val + 0x120, TEXT_SZ), 4):
            w = W[off // 4]
            if (w & 0x9F000000) == 0x90000000:
                immlo = (w >> 29) & 3
                immhi = (w >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= (1 << 21)
                pages[w & 31] = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
            elif (w & 0xFFC00000) == 0xF9400000:
                rt, rn = w & 31, (w >> 5) & 31
                imm = ((w >> 10) & 0xFFF) * 8
                if rn in pages:
                    a = pages[rn] + imm
                    if DATA_OFF <= a < IMG_SIZE:
                        slots.add(a)
        if slots:
            info = []
            for a in sorted(slots):
                v = struct.unpack_from("<Q", bytes(IMG[a:a + 8]), 0)[0]
                info.append("%#x%s" % (a, "(0)" if v == 0 else "(=%#x)" % v))
            print("  %-52s → %s" % (name, ", ".join(info)))


if __name__ == "__main__":
    main()
