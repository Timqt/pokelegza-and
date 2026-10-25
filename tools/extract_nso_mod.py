#!/usr/bin/env python3
"""从任意 NSO 里解出三段（供装载/扫描用）。

用法: python tools/extract_nso_mod.py entry_0 [entry_32848007 ...]
输出: work/nso_<名字>/{text,rodata,data}.bin
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEFS = os.path.join(ROOT, "work", "base", "exefs2")


def extract(name):
    path = os.path.join(EXEFS, name)
    d = open(path, "rb").read()
    magic, ver, res, flags = struct.unpack_from("<4sIII", d, 0)
    if magic != b"NSO0":
        print("%s: 不是 NSO（magic=%r）" % (name, magic))
        return None
    text_off, text_mem, text_size = struct.unpack_from("<III", d, 0x10)
    ro_off, ro_mem, ro_size = struct.unpack_from("<III", d, 0x20)
    data_off, data_mem, data_size = struct.unpack_from("<III", d, 0x30)
    tfs, rfs, dfs = struct.unpack_from("<III", d, 0x60)
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    out = os.path.join(ROOT, "work", "nso_" + name.replace("entry_", ""))
    os.makedirs(out, exist_ok=True)
    print("== %s ==  文件 %d 字节 flags=%#x" % (name, len(d), flags))
    print("   段内存偏移: text=%#x rodata=%#x data=%#x  bss=%#x" %
          (text_mem, ro_mem, data_mem, bss))
    info = {"text_mem": text_mem, "ro_mem": ro_mem, "data_mem": data_mem,
            "bss": bss, "text_size": text_size, "ro_size": ro_size,
            "data_size": data_size}
    for nm, fo, sz, csize, mem in (("text", text_off, text_size, tfs, text_mem),
                                   ("rodata", ro_off, ro_size, rfs, ro_mem),
                                   ("data", data_off, data_size, dfs, data_mem)):
        raw = d[fo:fo + csize]
        dec = lz4.block.decompress(raw, uncompressed_size=sz) if (flags & (1 << (0 if nm == "text" else 1 if nm == "rodata" else 2))) else raw
        open(os.path.join(out, nm + ".bin"), "wb").write(dec)
        print("   %-7s 内存偏移 %#x  解出 %9d 字节" % (nm, mem, len(dec)))
    with open(os.path.join(out, "layout.txt"), "w") as o:
        for k, v in info.items():
            o.write("%s %#x\n" % (k, v))
    return info


if __name__ == "__main__":
    for n in (sys.argv[1:] or ["entry_0", "entry_32848007"]):
        extract(n)
