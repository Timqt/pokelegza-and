#!/usr/bin/env python3
"""从 Z-A 的 main NSO 里抽内嵌着色器（SPH 魔数 0x12345678），并解出各段供扫描。"""

import os
import struct
import sys

import lz4.block

NSO = r"D:\feiniukexinhome\Code\pokeLegza-and\work\base\exefs2\entry_0"
OUT = r"D:\feiniukexinhome\Code\pokeLegza-and\work\nso"
SPH = bytes.fromhex("78563412")
CTL = bytes.fromhex("34127698")


def main():
    d = open(NSO, "rb").read()
    magic, ver, res, flags = struct.unpack_from("<4sIII", d, 0)
    text_off, text_mem, text_size = struct.unpack_from("<III", d, 0x10)
    ro_off, ro_mem, ro_size = struct.unpack_from("<III", d, 0x20)
    data_off, data_mem, data_size = struct.unpack_from("<III", d, 0x30)
    tfs, rfs, dfs = struct.unpack_from("<III", d, 0x60)
    print("main NSO %d 字节 flags=%#x" % (len(d), flags))

    os.makedirs(OUT, exist_ok=True)
    segs = {}
    for i, (nm, fo, sz, csize) in enumerate(
            (("text", text_off, text_size, tfs), ("rodata", ro_off, ro_size, rfs), ("data", data_off, data_size, dfs))):
        raw = d[fo:fo + csize]
        if flags & (1 << i):
            dec = lz4.block.decompress(raw, uncompressed_size=sz)
        else:
            dec = raw
        segs[nm] = dec
        open(os.path.join(OUT, nm + ".bin"), "wb").write(dec)
        sph = 0
        pos = 0
        while True:
            j = dec.find(SPH, pos)
            if j < 0:
                break
            sph += 1
            pos = j + 1
        ctl = dec.count(CTL)
        print("  %-7s 解出 %9d 字节  SPH=%d  控制段=%d" % (nm, len(dec), sph, ctl))

    # 合并成一个大镜像供 bnsh_xlate 扫描（按段顺序拼接，段内偏移保持）
    blob = b"".join(segs[k] for k in ("text", "rodata", "data"))
    out = os.path.join(OUT, "nso_blob.bin")
    open(out, "wb").write(blob)
    print("合并镜像: %s (%d 字节)" % (out, len(blob)))
    print("  SPH 总数: %d  控制段总数: %d" % (blob.count(SPH), blob.count(CTL)))


if __name__ == "__main__":
    main()
