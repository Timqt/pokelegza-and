#!/usr/bin/env python3
"""TRPAK 内层结构探针 + 目录普查。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRPFS = os.path.join(ROOT, "work", "base", "romfs", "arc", "data.trpfs")
TRPFD = os.path.join(ROOT, "work", "base", "romfs", "arc", "data.trpfd")

FNV_SVS = 14695981039346656837
PRIME = 1099511628211
MASK = (1 << 64) - 1


def fnv(path):
    h = FNV_SVS
    for ch in path:
        h ^= ord(ch)
        h = (h * PRIME) & MASK
    return h


def dump_trpak(buf, label):
    fb = FB(buf)
    root = fb.root()
    print("%s: 长度 %d, root@%d" % (label, len(buf), root))
    vt = fb.vtable(root)
    print("  vtable 字段偏移: %s" % vt)
    for idx in range(len(vt)):
        p = fb.field(root, idx)
        if p is None:
            print("  field%d = <缺省>" % idx)
            continue
        # 试着当 uoffset 指向向量
        try:
            start, n = fb.vector(p)
        except Exception:
            print("  field%d @%d 非向量" % (idx, p))
            continue
        print("  field%d @%d -> 向量 count=%d 元素起始=%d" % (idx, p, n, start))
        # 猜元素类型
        if n and start + 8 <= len(buf):
            vals = fb.vec_u64(root, idx)
            if len(vals) == n:
                print("      当 u64 读: %s" % ["%016x" % v for v in vals[:6]])
        if n and start + 4 <= len(buf):
            tabs = fb.vec_table(root, idx)
            if len(tabs) == n:
                print("      当表读: %d 个，首表@%d" % (n, tabs[0]))
                for t in tabs[:3]:
                    fv = fb.vtable(t)
                    print("        表@%d vtable=%s" % (t, fv))
                    for k in range(len(fv)):
                        q = fb.field(t, k)
                        if q is None:
                            continue
                        print("          field%d @%d u8=%d u32=%d u64=%d"
                              % (k, q, fb.u8(q), fb.u32(q), fb.u64(q)))
                    # 若是 File 表，取 data 向量
                    d = fb.field(t, 4)
                    if d is not None:
                        try:
                            ds, dn = fb.vector(d)
                            print("          data 向量 count=%d 起始=%d" % (dn, ds))
                            print("          data 前 64 字节: %s" % buf[ds:ds + 64].hex(" "))
                        except Exception as e:
                            print("          data 读取失败 %s" % e)


def main():
    tfs = Trpfs(TRPFS)
    tfd = Trpfd(TRPFD)
    h2p = {}
    for p in tfd.paths:
        h2p.setdefault(fnv(p), []).append(p)

    # 目录普查
    exts = {}
    keys = ("shader", "glsl", "nvn", "program", "spirv", "sass", "effect", "ptcl", "bnx", "bntx")
    hits = []
    for p in tfd.paths:
        e = os.path.splitext(p)[0].split(".")[-1]
        exts[e] = exts.get(e, 0) + 1
        low = p.lower()
        if any(k in low for k in keys):
            hits.append(p)
    print("=== 路径后缀分布 ===")
    for e, c in sorted(exts.items(), key=lambda x: -x[1]):
        print("  .%-10s %d" % (e, c))
    print("=== 命中着色器/特效关键词的路径 (%d) ===" % len(hits))
    for p in hits[:40]:
        print("  " + p)

    # 第一个块的结构
    for idx in (0, 1, 2):
        blob = tfs.read(idx)
        path = h2p.get(tfs.hashes[idx], ["?"])[0]
        print("\n=== 块 %d: %s (%d 字节) ===" % (idx, path, len(blob)))
        dump_trpak(blob, "块%d" % idx)
    tfs.close()


if __name__ == "__main__":
    main()
