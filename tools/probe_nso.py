#!/usr/bin/env python3
"""解析完整 NSO0（按 switchbrew 的 NsoHeader 布局），解 LZ4 分段，列导入符号、找 NVIDIA 着色器容器。"""
import re
import struct
import sys
from pathlib import Path

import lz4.block

NSO = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\base\exefs2\entry_0")


def main():
    d = NSO.read_bytes()
    print(f"main: {len(d)} 字节 ({len(d)/2**20:.2f} MiB)")
    magic, ver, res, flags = struct.unpack_from("<4sIII", d, 0)
    print(f"magic={magic} flags={flags:#x}  (bit0/1/2=LZ4 压缩, bit7=zbic/zstd)")
    text_off, text_mem, text_size = struct.unpack_from("<III", d, 0x10)
    ro_off, ro_mem, ro_size = struct.unpack_from("<III", d, 0x20)
    data_off, data_mem, data_size = struct.unpack_from("<III", d, 0x30)
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    tfs, rfs, dfs = struct.unpack_from("<III", d, 0x60)
    print(f"text : fileOff={text_off:#x} memOff={text_mem:#x} size={text_size:#x} compressed={tfs:#x}")
    print(f"rodata:fileOff={ro_off:#x} memOff={ro_mem:#x} size={ro_size:#x} compressed={rfs:#x}")
    print(f"data : fileOff={data_off:#x} memOff={data_mem:#x} size={data_size:#x} compressed={dfs:#x}")
    print(f"bss  : {bss:#x}")
    if text_off + tfs > len(d):
        print("!! text 段超出文件末尾 -> 文件被截断")

    segs = []
    for i, (fo, sz, csize) in enumerate(((text_off, text_size, tfs), (ro_off, ro_size, rfs), (data_off, data_size, dfs))):
        if flags & (1 << i):
            raw = d[fo:fo + csize]
            try:
                dec = lz4.block.decompress(raw, uncompressed_size=sz)
            except Exception as e:
                print(f"  seg{i} LZ4 解压失败: {e}")
                dec = raw
        else:
            dec = d[fo:fo + sz]
        segs.append(dec)
        print(f"  seg{i} 解出 {len(dec)} / 期望 {sz}")

    text, rodata, data = segs
    print("\n--- 导入符号（.rodata 可打印串里的 nvn / nn:: / shader）---")
    names = sorted(set(x.decode() for x in re.findall(rb"[A-Za-z_][A-Za-z0-9_:]{5,70}", rodata)))
    key = [n for n in names if re.search(r"nvn|NVN|nn::|shader|Shader|glsl|Glsl|Maxwell|nvidia", n)]
    for n in key[:80]:
        print("   ", n)
    print(f"  .rodata 共 {len(names)} 个候选符号，命中 {len(key)}")
    print(f"  .text 共 {len(text)} 字节；.data 共 {len(data)} 字节")

    print("\n--- 导入表（NSO 里的 .dynsym/.dynstr 区段）---")
    emb_off, emb_size = struct.unpack_from("<II", d, 0x88)
    ds_off, ds_size = struct.unpack_from("<II", d, 0x90)
    dy_off, dy_size = struct.unpack_from("<II", d, 0x98)
    print(f"  embedded={emb_off:#x}+{emb_size:#x}  dynstr={ds_off:#x}+{ds_size:#x}  dynsym={dy_off:#x}+{dy_size:#x}")
    if ds_size and ds_off + ds_size <= len(rodata):
        blob = rodata[ds_off:ds_off + ds_size]
        strs = [s.decode("utf-8", "replace") for s in blob.split(b"\0") if s]
        print(f"  dynstr 里 {len(strs)} 个字符串，前 40 个：")
        for s in strs[:40]:
            print("     ", s)
        nvn = [s for s in strs if "nvn" in s.lower() or "nn::" in s]
        print(f"  其中含 nvn/nn:: 的 {len(nvn)} 个")
        if nvn:
            print("  >>> 确认使用 NVN：")
            for s in nvn[:30]:
                print("      ", s)


if __name__ == "__main__":
    main()
