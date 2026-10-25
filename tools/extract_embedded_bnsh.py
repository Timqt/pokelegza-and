#!/usr/bin/env python3
"""从各容器里抠出内嵌的 BNSH 着色器包（偏移 0x10000 对齐），再按 BNSH 的 grsc 表配对
「控制段 ↔ 代码段」，并输出运行时查表所需的 (控制段 sha16, 代码段偏移) 对。

用法：extract_embedded_bnsh.py [容器目录]
输出：work/bnsh_all/*.bnsh, work/ctl_code_pairs_all.tsv
"""

import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "work", "shaders_all")
DST = os.path.join(ROOT, "work", "bnsh_all")
PAIRS = os.path.join(ROOT, "work", "ctl_code_pairs_all.tsv")
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


def pair_file(data):
    """BNSH 容器：grsc 表 = 0x30 步长记录（+0x18 控制段偏移 / +0x20 代码段偏移 / +0x2c 长度 0x880）。
    先用三连签名找候选，再按记录步长走。"""
    ctls = set(find_all(data, CTL))
    sphs = set(find_all(data, SPH))
    if not ctls or not sphs:
        return []
    # 找表基址（快法）：对每个控制段 c，用 find 找所有等于 c 的 u32 槽位 p，
    # 槽位 p 即记录里的 +0x18 字段位置 -> 记录基址 = p - 0x18
    bases = []
    for c in ctls:
        pat = struct.pack("<I", c)
        q = 0
        while True:
            i = data.find(pat, q)
            if i < 0 or i + 0x30 > len(data):
                break
            if i % 4 == 0 and struct.unpack_from("<I", data, i + 8)[0] in sphs:
                bases.append(i - 0x18)
            q = i + 1
    best = []
    for b in bases:
        recs = []
        o = b
        while o + 0x30 <= len(data):
            c = struct.unpack_from("<I", data, o + 0x18)[0]
            k = struct.unpack_from("<I", data, o + 0x20)[0]
            ln = struct.unpack_from("<I", data, o + 0x2C)[0]
            if c not in ctls or k not in sphs or ln != CTL_LEN:
                break
            recs.append((c, k))
            o += 0x30
        if len(recs) > len(best):
            best = recs
    return best


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else SRC
    os.makedirs(DST, exist_ok=True)
    nfiles = 0
    total = 0
    npairs = 0
    full = 0
    with open(PAIRS, "w", encoding="utf-8") as o:
        o.write("# container\tctl_index\tctl_offset\tctl_sha16\tcode_offset\n")
        for f in sorted(os.listdir(src)):
            p = os.path.join(src, f)
            if os.path.getsize(p) <= 64:
                continue
            data = open(p, "rb").read()
            i = data.find(BNSH)
            if i < 0:
                continue
            blob = data[i:]
            name = f[:-4] if f.endswith(".bin") else f
            outp = os.path.join(DST, name + ".bnsh")
            with open(outp, "wb") as g:
                g.write(blob)
            nfiles += 1
            total += len(blob)
            recs = pair_file(blob)
            nctl = len(find_all(blob, CTL))
            if recs and len(recs) == nctl:
                full += 1
            for k, (c, code) in enumerate(recs):
                h = hashlib.sha256(blob[c:c + CTL_LEN]).hexdigest()[:16]
                o.write("%s.bnsh\t%d\t%x\t%s\t%x\n" % (name, k, c, h, code))
                npairs += 1
    print("抠出内嵌 BNSH: %d 个, 合计 %.1f MB" % (nfiles, total / 1048576))
    print("配对: %d 条（其中 %d 个容器控制段 100%% 全覆盖）-> %s" % (npairs, full, PAIRS))


if __name__ == "__main__":
    main()
