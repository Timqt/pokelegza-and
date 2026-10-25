#!/usr/bin/env python3
"""配对「控制段 ↔ 代码段」：用三连签名(控制段魔数 + SPH 魔数 + 0x880)反查，
再按「每个控制段偏移只应出现一次」筛出真正的 grsc 表条目。

输出：work/ctl_code_pairs.tsv  (container, ctl_index, ctl_offset, ctl_sha16, code_offset)
"""

import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "work", "shaders_all")
OUT = os.path.join(ROOT, "work", "ctl_code_pairs.tsv")
CTL = bytes.fromhex("34127698")
SPH = bytes.fromhex("78563412")
CTL_LEN = 0x880


def find_all(data, magic):
    out = []
    pos = 0
    while True:
        i = data.find(magic, pos)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out


def pair_file(path):
    data = open(path, "rb").read()
    ctls = set(find_all(data, CTL))
    sphs = set(find_all(data, SPH))
    if not ctls or not sphs:
        return []
    # 扫所有 4 字节对齐槽，找 (ctl_off, code_off, 0x880) 三连
    cand = {}
    for off in range(0, len(data) - 0x20, 4):
        c = struct.unpack_from("<I", data, off)[0]
        if c not in ctls:
            continue
        k = struct.unpack_from("<I", data, off + 8)[0]
        if k not in sphs:
            continue
        if struct.unpack_from("<I", data, off + 0x14)[0] != CTL_LEN:
            continue
        cand.setdefault(c, set()).add(k)
    pairs = []
    for c in sorted(ctls):
        ks = cand.get(c)
        if ks and len(ks) == 1:
            pairs.append((c, next(iter(ks))))
    return pairs


def main():
    files = sorted(f for f in os.listdir(SRC) if os.path.getsize(os.path.join(SRC, f)) > 64)
    tot = 0
    full = 0
    with open(OUT, "w", encoding="utf-8") as o:
        o.write("# container\tctl_index\tctl_offset\tctl_sha16\tcode_offset\n")
        for f in files:
            p = os.path.join(SRC, f)
            data = open(p, "rb").read()
            nctl = len(find_all(data, CTL))
            pairs = pair_file(p)
            if not pairs:
                continue
            if len(pairs) == nctl:
                full += 1
            for i, (c, k) in enumerate(pairs):
                h = hashlib.sha256(data[c:c + CTL_LEN]).hexdigest()[:16]
                o.write("%s\t%d\t%x\t%s\t%x\n" % (f, i, c, h, k))
                tot += 1
    print("配对 %d 条（容器 %d 个，其中 %d 个控制段全覆盖）-> %s" % (tot, len(files), full, OUT))


if __name__ == "__main__":
    main()
