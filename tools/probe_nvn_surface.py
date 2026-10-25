#!/usr/bin/env python3
"""统计 NSO 的 NVN 导入面，并核对「运行时编译 GLSL」这条线索。"""
import re
import struct
from collections import Counter
from pathlib import Path

import lz4.block

NSO = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\base\exefs2\entry_0")

d = NSO.read_bytes()
flags = struct.unpack_from("<I", d, 0x0C)[0]
text_off, _, text_size = struct.unpack_from("<III", d, 0x10)
ro_off, _, ro_size = struct.unpack_from("<III", d, 0x20)
data_off, _, data_size = struct.unpack_from("<III", d, 0x30)
tfs, rfs, dfs = struct.unpack_from("<III", d, 0x60)
rodata = lz4.block.decompress(d[ro_off:ro_off + rfs], uncompressed_size=ro_size)
text = lz4.block.decompress(d[text_off:text_off + tfs], uncompressed_size=text_size)

ds_off, ds_size = struct.unpack_from("<II", d, 0x90)
strs = [s.decode("utf-8", "replace") for s in rodata[ds_off:ds_off + ds_size].split(b"\0") if s]
nvn = sorted(s for s in strs if s.startswith("nvn"))
print(f"dynstr 共 {len(strs)} 个字符串，其中 nvn* 共 {len(nvn)} 个")
print("\n--- nvn* 按前缀分组 ---")
c = Counter()
for s in nvn:
    m = re.match(r"nvn([A-Za-z]+)", s)
    c[m.group(1) if m else "?"] += 1
for k, v in sorted(c.items(), key=lambda kv: -kv[1])[:40]:
    print(f"  nvn{k:<28} {v}")

print("\n--- 编译相关的符号 ---")
for s in strs:
    if re.search(r"glsl|GLSL|Compiler|compiler|SPIR|spirv", s):
        print("   ", s)

print("\n--- nvnCompiler* 全量 ---")
comp = [s for s in nvn if "ompil" in s]
for s in comp:
    print("   ", s)
print(f"  共 {len(comp)} 个")

print("\n--- .text 里搜 GLSL 源码特征 ---")
for pat, desc in ((b"#version", "GLSL #version"), (b"layout(", "GLSL layout("),
                  (b"void main()", "GLSL main"), (b"uniform ", "GLSL uniform"),
                  (b"#include", "GLSL #include"), (b"gl_FragColor", "GLSL gl_FragColor"),
                  (b"gl_Position", "GLSL gl_Position")):
    n = text.count(pat)
    print(f"  text: {desc:<22} {n}")

print("\n--- .rodata 里搜 GLSL 源码特征 ---")
for pat, desc in ((b"#version", "GLSL #version"), (b"layout(", "GLSL layout("),
                  (b"void main()", "GLSL main"), (b"uniform ", "GLSL uniform"),
                  (b"#include", "GLSL #include")):
    n = rodata.count(pat)
    print(f"  rodata: {desc:<22} {n}")
