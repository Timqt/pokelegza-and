#!/usr/bin/env python3
"""全量运行时着色器表（修正版）。

要点：
1) 内嵌 BNSH 在原容器里的起点不固定（实测 0x10000 / 0x14000 …），
   而 SPIR-V 文件名用的是**容器相对**的代码偏移 —— 配对时要加回 BNSH 起点。
2) BNSH 内记录形态：`{控制段偏移, 代码段偏移, 间距}` 三个相邻 u32，记录稀疏分布。

输出：work/spv_map_all.tsv
"""

import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTAINERS = os.path.join(ROOT, "work", "shaders_all")
BN = os.path.join(ROOT, "work", "bnsh_all")
SPV = os.path.join(ROOT, "work", "spv_all3")
OUT = os.path.join(ROOT, "work", "spv_map_all.tsv")
BNSH = b"BNSH"
CTL = bytes.fromhex("34127698")
SPH = bytes.fromhex("78563412")
CTL_LEN = 0x880


def find_all(data, magic):
    out = []
    p = 0
    while True:
        i = data.find(magic, p)
        if i < 0:
            break
        out.append(i)
        p = i + 1
    return out


def main():
    # 1) SPIR-V 索引：<容器名>_<容器相对代码偏移:X8>_<stage>.spv
    spv_idx = {}
    for root, _, fs in os.walk(SPV):
        for f in fs:
            if not f.endswith(".spv"):
                continue
            parts = f[:-4].rsplit("_", 2)
            if len(parts) != 3:
                continue
            spv_idx[(parts[0], int(parts[1], 16))] = os.path.join(root, f)

    # 2) 每个容器里内嵌 BNSH 的起点
    start_of = {}
    for f in sorted(os.listdir(CONTAINERS)):
        p = os.path.join(CONTAINERS, f)
        if os.path.getsize(p) <= 64:
            continue
        with open(p, "rb") as g:
            head = g.read(4)
        if head == BNSH:
            start_of[f] = 0          # 本身就是 BNSH
            continue
        i = g.find(BNSH) if False else None
        # 需要完整内容才能找 BNSH（文件可能大于 4 字节头）
    # 2b) 完整扫描（只找魔数，快）
    for f in sorted(os.listdir(CONTAINERS)):
        p = os.path.join(CONTAINERS, f)
        if os.path.getsize(p) <= 64:
            continue
        with open(p, "rb") as g:
            data = g.read()
        i = data.find(BNSH)
        if i >= 0:
            start_of[f] = i
    print("容器 %d 个，其中有内嵌 BNSH 的 %d 个" % (len(os.listdir(CONTAINERS)), len(start_of)))

    # 3) 配对 + 挂 SPIR-V
    rows = []
    npairs = nhit = 0
    for f in sorted(os.listdir(BN)):
        bp = os.path.join(BN, f)
        if not os.path.exists(bp):
            continue
        data = open(bp, "rb").read()
        ctls = find_all(data, CTL)
        sphs = find_all(data, SPH)
        if not ctls or not sphs:
            continue
        cset, sset = set(ctls), set(sphs)
        pairs = {}
        for k in sphs:
            pat = struct.pack("<I", k)
            q = 0
            while True:
                b = data.find(pat, q)
                if b < 0 or b + 4 > len(data):
                    break
                q = b + 1
                if b < 8:
                    continue
                c = struct.unpack_from("<I", data, b - 8)[0]
                if c in cset and c not in pairs:
                    pairs[c] = k
        npairs += len(pairs)
        base = f[:-5] if f.endswith(".bnsh") else f
        cname = base + ".bin" if os.path.exists(os.path.join(CONTAINERS, base + ".bin")) else base
        off = start_of.get(cname, 0)
        for c, code in pairs.items():
            h = hashlib.sha256(data[c:c + CTL_LEN]).hexdigest()[:16]
            spv = spv_idx.get((base, code + off))
            if spv:
                nhit += 1
                rows.append((h, os.path.relpath(spv, os.path.join(ROOT, "work")), f, c, code + off))
    with open(OUT, "w", encoding="utf-8") as o:
        o.write("# ctl_sha16\tspv_file\tcontainer\tctl_offset(BNSH相对)\tcode_offset(容器相对)\n")
        for r in rows:
            o.write("\t".join(str(x) for x in r) + "\n")
    print("配对 %d 对，其中挂上 SPIR-V 的 %d 条 -> %s" % (npairs, nhit, OUT))


if __name__ == "__main__":
    main()
