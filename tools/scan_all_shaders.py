#!/usr/bin/env python3
"""全量扫 9,892 个 .trpak 包，找内嵌着色器（SPH 魔数 0x12345678）。

流程：TRPFS → 块 → TRPAK → 内层文件（Oodle 解压）→ 扫 SPH / 控制段
含 SPH 的文件落盘到 work/shaders_all/（供 bnsh_xlate 批量翻译），并写索引 TSV。
"""

import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oodle import decompress  # noqa: E402
from onepack import FB, Trpfd, Trpfs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARC = os.path.join(ROOT, "work", "base", "romfs", "arc")
OUT = os.path.join(ROOT, "work", "shaders_all")
INDEX = os.path.join(ROOT, "work", "shader_index.tsv")
FNV_BASIS = 0xCBF29CE484222645
FNV_PRIME = 1099511628211
MASK = (1 << 64) - 1
SPH = bytes.fromhex("78563412")
CTL = bytes.fromhex("34127698")


def fnv(path):
    h = FNV_BASIS
    for ch in path:
        h ^= ord(ch)
        h = (h * FNV_PRIME) & MASK
    return h


def main():
    only = None
    max_bytes = 8 << 30      # 落盘总上限（默认 8 GB）
    max_file = 96 << 20      # 单文件上限
    for a in sys.argv[1:]:
        if a.startswith('--only='):
            only = a.split('=', 1)[1]
        elif a.startswith('--max-gb='):
            max_bytes = int(float(a.split('=', 1)[1]) * (1 << 30))
        elif a.startswith('--max-file-mb='):
            max_file = int(float(a.split('=', 1)[1]) * (1 << 20))
    tfs = Trpfs(os.path.join(ARC, "data.trpfs"))
    tfd = Trpfd(os.path.join(ARC, "data.trpfd"))
    h2p = {}
    for p in tfd.paths:
        h2p.setdefault(fnv(p), []).append(p)

    os.makedirs(OUT, exist_ok=True)
    rows = []
    t0 = time.time()
    scanned = 0
    written = 0
    with open(INDEX, "w", encoding="utf-8") as idx:
        idx.write("package\tinner_index\tsize\tsph\tctl\tmagic\tstage_hint\tout\n")
        for i in range(tfs.count()):
            path = h2p.get(tfs.hashes[i], ["?"])[0]
            if only and only not in path:
                continue
            blob = tfs.read(i)
            try:
                fb = FB(blob)
                tabs = fb.vec_table(fb.root(), 1)
            except Exception:
                continue
            for k, t in enumerate(tabs):
                enc = fb.scalar(t, 1, "u8", 255)
                size = fb.scalar(t, 3, "u64", 0)
                d = fb.field(t, 4)
                if d is None:
                    continue
                ds, n = fb.vector(d)
                raw = blob[ds:ds + n]
                if enc == 255:
                    data = raw
                else:
                    try:
                        data = decompress(raw, size)
                    except Exception:
                        continue
                scanned += 1
                sph = data.count(SPH)
                ctl = data.count(CTL)
                if not sph:
                    continue
                if len(data) > max_file:
                    idx.write("%s\t%d\t%d\t%d\t%d\t%s\tSKIP_TOO_BIG\t\n" % (path, k, size, sph, ctl, data[:4].decode('latin1')))
                    continue
                magic = data[:4]
                out = "%s__%03d_%d.bin" % (
                    os.path.basename(path).replace(".trpak", ""), k, size)
                with open(os.path.join(OUT, out), "wb") as g:
                    g.write(data)
                rows.append((path, k, size, sph, ctl, magic))
                written += len(data)
                if written > max_bytes:
                    print("达到落盘上限 %.1f GB，停止" % (written / (1 << 30)), flush=True)
                    idx.flush()
                    print("完成(截断)：包 %d, 内层文件 %d, 含 SPH 的文件 %d, 落盘 %.2f GB, 用时 %.0fs" % (
                        i + 1, scanned, len(rows), written / (1 << 30), time.time() - t0))
                    tfs.close()
                    return
                idx.write("%s\t%d\t%d\t%d\t%d\t%s\t\t%s\n" % (
                    path, k, size, sph, ctl, magic.decode("latin1"), out))
            if (i + 1) % 500 == 0:
                print("  扫到第 %d 包, 内层文件 %d, 命中着色器文件 %d, 落盘 %.2f GB, 用时 %.0fs" % (
                    i + 1, scanned, len(rows), written / (1 << 30), time.time() - t0), flush=True)
    print("完成：包 %d, 内层文件 %d, 含 SPH 的文件 %d, 用时 %.0fs" % (
        tfs.count(), scanned, len(rows), time.time() - t0))
    print("输出目录: %s" % OUT)
    print("索引: %s" % INDEX)
    tfs.close()


if __name__ == "__main__":
    main()
