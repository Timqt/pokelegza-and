"""在着色器容器里搜 GLSL 源码（顶点/场景着色器的唯一可能来源）。

做法：把容器里连续的可打印 ASCII 片段（>= 48 字节）抽出来，找 GLSL 特征串。
"""
import os, re, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "work", "shaders_all")
OUT = os.path.join(ROOT, "work", "glsl_hits.tsv")

MARKERS = [b"#version", b"void main", b"gl_Position", b"layout(", b"uniform ",
           b"in vec", b"out vec", b"#define", b"precision ", b"#pragma",
           "glsl".encode(), b"attribute ", b"varying "]

TEXT = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{48,}")

def main():
    files = sorted(f for f in os.listdir(SRC) if os.path.getsize(os.path.join(SRC, f)) > 64)
    hits = []
    nfiles = 0
    for name in files:
        p = os.path.join(SRC, name)
        data = open(p, "rb").read()
        nfiles += 1
        found = set()
        best = []
        for m in TEXT.finditer(data):
            seg = m.group()
            for mk in MARKERS:
                if mk in seg:
                    found.add(mk.decode())
                    best.append((m.start(), len(seg), seg[:200]))
                    break
        if found:
            hits.append((name, len(data), sorted(found), best))
            print("[HIT] %-70s %10d 字节  标记=%s  片段%d" % (name, len(data), ",".join(sorted(found)), len(best)))
            for off, ln, seg in best[:2]:
                txt = seg.decode("ascii", "replace").replace("\r", " ").replace("\n", " ")
                print("        @0x%X (%d 字节) %s" % (off, ln, txt[:180]))
    with open(OUT, "w", encoding="utf-8") as o:
        for name, sz, marks, segs in hits:
            o.write("%s\t%d\t%s\t%d\n" % (name, sz, ",".join(marks), len(segs)))
    print("\n扫描 %d 个容器，命中 %d 个 -> %s" % (nfiles, len(hits), OUT))

if __name__ == "__main__":
    main()
