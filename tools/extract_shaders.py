#!/usr/bin/env python3
"""把 Z-A 的着色器归档（.bnsh / .trsha）从 ONEPACK 里解出来。

路径：data.trpfs (ONEPACK) -> .trpak (TRPAK) -> 内层文件（Oodle 压缩）
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oodle import decompress  # noqa: E402
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARC = os.path.join(ROOT, "work", "base", "romfs", "arc")
OUT = os.path.join(ROOT, "work", "shaders")
FNV_BASIS = 0xCBF29CE484222645
FNV_PRIME = 1099511628211
MASK = (1 << 64) - 1


def fnv(path):
    """Game Freak 的 FNV-1a：按字符 XOR，偏移基 0xCBF29CE484222645。"""
    h = FNV_BASIS
    for ch in path:
        h ^= ord(ch)
        h = (h * FNV_PRIME) & MASK
    return h


def main():
    want = sys.argv[1:] or [".bnsh.trpak", ".trsha.trpak"]
    tfs = Trpfs(os.path.join(ARC, "data.trpfs"))
    tfd = Trpfd(os.path.join(ARC, "data.trpfd"))
    h2p = {}
    for p in tfd.paths:
        h2p.setdefault(fnv(p), []).append(p)

    os.makedirs(OUT, exist_ok=True)
    hits = 0
    for i in range(tfs.count()):
        path = h2p.get(tfs.hashes[i], ["?"])[0]
        if not any(w in path for w in want):
            continue
        hits += 1
        blob = tfs.read(i)
        fb = FB(blob)
        root = fb.root()
        tabs = fb.vec_table(root, 1)
        base = os.path.join(OUT, os.path.basename(path).replace(".trpak", ""))
        os.makedirs(base, exist_ok=True)
        print("=== %s (%d 字节, %d 个内层文件) ===" % (path, len(blob), len(tabs)))
        for k, t in enumerate(tabs):
            enc = fb.scalar(t, 1, "u8", 255)
            size = fb.scalar(t, 3, "u64", 0)
            d = fb.field(t, 4)
            if d is None:
                continue
            ds, n = fb.vector(d)
            raw = blob[ds:ds + n]
            if enc == 255 or enc == 0xFF:
                out = raw
                tag = "stored"
            else:
                out = decompress(raw, size)
                tag = "oodle"
            magic = out[:4]
            ext = {b"BNSH": ".bnsh", b"VFXB": ".vfxb"}.get(magic, ".bin")
            name = "%03d_%d%s" % (k, size, ext)
            with open(os.path.join(base, name), "wb") as g:
                g.write(out)
            print("   %-18s enc=%-4d comp=%-9d raw=%-9d %s  magic=%r"
                  % (name, enc, n, size, tag, magic))
    print("共命中 %d 个着色器包 -> %s" % (hits, OUT))
    tfs.close()


if __name__ == "__main__":
    main()
