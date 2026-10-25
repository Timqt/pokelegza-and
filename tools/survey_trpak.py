#!/usr/bin/env python3
"""普查 9,892 个 .trpak 块：内层文件数、压缩类型、解压后体积；并按路径名筛着色器相关条目。"""

import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARC = os.path.join(ROOT, "work", "base", "romfs", "arc")
FNV_SVS = 14695981039346656837
PRIME = 1099511628211
MASK = (1 << 64) - 1


def fnv(path):
    h = FNV_SVS
    for ch in path:
        h ^= ord(ch)
        h = (h * PRIME) & MASK
    return h


def main():
    tfs = Trpfs(os.path.join(ARC, "data.trpfs"))
    tfd = Trpfd(os.path.join(ARC, "data.trpfd"))
    h2p = {}
    for p in tfd.paths:
        h2p.setdefault(fnv(p), []).append(p)

    comp_counter = Counter()
    total_files = 0
    total_raw = 0
    total_comp = 0
    per_blob = []
    bad = []
    for i in range(tfs.count()):
        blob = tfs.read(i)
        path = h2p.get(tfs.hashes[i], ["?"])[0]
        try:
            fb = FB(blob)
            root = fb.root()
            tabs = fb.vec_table(root, 1)          # files
            n = len(tabs)
            comps = []
            raw = 0
            for t in tabs:
                ct = fb.scalar(t, 1, "u8", 255)
                ds = fb.scalar(t, 3, "u64", 0)
                comps.append(ct)
                raw += ds
                comp_counter[ct] += 1
            total_files += n
            total_raw += raw
            total_comp += tfs.size_of(i)
            per_blob.append((path, n, raw, tfs.size_of(i), comps))
        except Exception as e:
            bad.append((path, str(e)))

    print("块数=%d 内层文件总数=%d" % (tfs.count(), total_files))
    print("压缩类型分布 (3=Oodle, 255=None): %s" % dict(comp_counter))
    print("压缩总字节=%d  解压后总字节=%d (比例 %.1f%%)" % (total_comp, total_raw, 100.0 * total_raw / max(1, total_comp)))
    if bad:
        print("解析失败 %d 块，例: %s" % (len(bad), bad[:3]))

    print("\n=== 体积最大的 15 个块（按解压后）===")
    for path, n, raw, comp, comps in sorted(per_blob, key=lambda x: -x[2])[:15]:
        print("  raw=%10d comp=%9d files=%-4d %s" % (raw, comp, n, path))

    print("\n=== 路径名里带 shader/glsl/nvn/gpu/spv/vert/frag 关键字 ===")
    kws = ("shader", "glsl", "nvn", "gpu", "spv", "vert", "frag", "shaders")
    hits = [b for b in per_blob if any(k in b[0].lower() for k in kws)]
    print("命中 %d" % len(hits))
    for path, n, raw, comp, comps in hits[:30]:
        print("  raw=%9d files=%-3d %s" % (raw, n, path))

    print("\n=== 含 .bin / .dat / .h / .blua 的块（前 20）===")
    hits2 = [b for b in per_blob if b[0].lower().endswith((".bin.trpak", ".h.trpak", ".blua.trpak", ".dat.trpak"))]
    print("命中 %d" % len(hits2))
    for path, n, raw, comp, comps in sorted(hits2, key=lambda x: -x[2])[:20]:
        print("  raw=%9d files=%-3d %s" % (raw, n, path))

    tfs.close()


if __name__ == "__main__":
    main()
