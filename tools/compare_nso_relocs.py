#!/usr/bin/env python3
"""对比多个 NSO 的重定位构成：类型分布、RELATIVE 覆盖区间。

用途：确认「某个 NSO 的重定位表是否被我们解析完整」，
以及「init_array 这类模块内指针该由谁来重定位」。
"""
import collections
import os
import struct
import sys

import lz4.block


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
    return d, IMG, (tmo, tsz, rmo, rsz, dmo, dsz, bss), segs


def analyze(path):
    d, IMG, lay, segs = load_nso(path)
    tmo, tsz, rmo, rsz, dmo, dsz, bss = lay

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

    print("=" * 78)
    print(path)
    print("  段: text %#x+%#x rodata %#x+%#x data %#x+%#x bss %#x" %
          (tmo, tsz, rmo, rsz, dmo, dsz, bss))
    print("  DT_RELA=%#x sz=%#x  DT_JMPREL=%#x sz=%#x  DT_INIT=%#x  DT_INIT_ARRAY=%#x sz=%#x" %
          (vals.get(7, 0), vals.get(8, 0), vals.get(23, 0), vals.get(2, 0),
           vals.get(12, 0), vals.get(25, 0), vals.get(27, 0)))
    print("  NSO 头: modoff=%#x modsize=%#x dynstroff=%#x dynstrsz=%#x dynsymoff=%#x dynsymsz=%#x" %
          (struct.unpack_from("<I", d, 0x88)[0], struct.unpack_from("<I", d, 0x8C)[0],
           struct.unpack_from("<I", d, 0x90)[0], struct.unpack_from("<I", d, 0x94)[0],
           struct.unpack_from("<I", d, 0x98)[0], struct.unpack_from("<I", d, 0x9C)[0]))

    symtab, strtab, strsz = vals[6], vals[5], vals[10]
    strs = rd(strtab, strsz)

    def sym(i):
        b = rd(symtab + i * 24, 24)
        if not b:
            return None
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        value, size = struct.unpack_from("<QQ", b, 8)
        e = strs.find(b"\0", name)
        return (strs[name:e].decode("ascii", "replace"), value, shndx)

    counts = collections.Counter()
    rel_offs = []
    for off, size in ((vals.get(7), vals.get(8)), (vals.get(23), vals.get(2))):
        if not off or not size:
            continue
        for i in range(size // 24):
            b = rd(off + i * 24, 24)
            if not b:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            typ = r_info & 0xFFFFFFFF
            counts[typ] += 1
            if typ == 1027:
                rel_offs.append(r_off)
    print("  重定位类型分布: %s" % dict(counts))
    if rel_offs:
        rel_offs.sort()
        print("  RELATIVE 槽范围: %#x .. %#x（%d 条）" % (rel_offs[0], rel_offs[-1], len(rel_offs)))

    # init_array 的原始值形态
    ia, isz = vals.get(25, 0), vals.get(27, 0)
    if ia and isz:
        n = isz // 8
        vs = [struct.unpack_from("<Q", bytes(rd(ia + i * 8, 8)), 0)[0] for i in range(n)]
        nz = [v for v in vs if v]
        print("  init_array %d 项，非零 %d；取值范围 %#x..%#x" %
              (n, len(nz), min(nz) if nz else 0, max(nz) if nz else 0))
        if nz:
            print("    首项 %#x（小于 image 大小 %#x ⇒ 是模块内偏移）" % (nz[0], len(IMG)))
    return counts


if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            analyze(p)
        else:
            print("找不到: %s" % p)
