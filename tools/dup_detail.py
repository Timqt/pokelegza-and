"""逐条打印重复 key 下每个条目的文件哈希/大小，定位到底哪几条内容不同。"""
import os, hashlib, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN = os.path.join(ROOT, "work", "spv_map_all.tsv")

def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

rows = []
with open(IN, "r", encoding="utf-8", errors="replace") as f:
    f.readline()
    for line in f:
        p = line.rstrip("\r\n").split("\t")
        if len(p) >= 5:
            rows.append(p)

by = collections.defaultdict(list)
for r in rows:
    by[r[0]].append(r)

for k, v in by.items():
    if len(v) < 2:
        continue
    hs = []
    for r in v:
        fp = os.path.join(ROOT, "work", r[1].replace("\\", "/"))
        if os.path.isfile(fp):
            hs.append((sha_file(fp), os.path.getsize(fp), r[1], r[3], r[4]))
        else:
            hs.append(("MISSING", -1, r[1], r[3], r[4]))
    if len({x[0] for x in hs}) > 1:
        print("=== key %s  (%d 条)" % (k, len(v)))
        for h, sz, fn, ctl, code in hs:
            print("   %s  %7d  ctl=%-8s code=%-8s  %s" % (h[:16], sz, ctl, code, fn))
