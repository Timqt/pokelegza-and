#!/usr/bin/env python3
"""给全量着色器容器建「控制段哈希」索引（运行时查表用的 key = sha256(控制段 0x880 字节)[:16]）。

同时把每个容器的 SPH 偏移列表一起写出来，供后续把控制段与代码段配对。
输出：work/ctl_index.tsv
"""

import hashlib
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "work", "shaders_all")
OUT = os.path.join(ROOT, "work", "ctl_index.tsv")
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


def main():
    files = sorted(f for f in os.listdir(SRC) if os.path.getsize(os.path.join(SRC, f)) > 64)
    nctl = nsph = 0
    with open(OUT, "w", encoding="utf-8") as o:
        o.write("# container\tctl_index\tctl_offset\tctl_sha16\tsph_offsets\n")
        for f in files:
            p = os.path.join(SRC, f)
            data = open(p, "rb").read()
            ctls = find_all(data, CTL)
            sphs = find_all(data, SPH)
            if not ctls:
                continue
            for k, c in enumerate(ctls):
                blob = data[c:c + CTL_LEN]
                h = hashlib.sha256(blob).hexdigest()[:16]
                sph_list = ",".join("%x" % s for s in sphs)
                o.write("%s\t%d\t%x\t%s\t%s\n" % (f, k, c, h, sph_list))
                nctl += 1
            nsph += len(sphs)
    print("容器 %d 个，控制段 %d 个（哈希写入 %s），关联 SPH %d 个" % (len(files), nctl, OUT, nsph))


if __name__ == "__main__":
    main()
