"""判定重复 key 的 SPIR-V 内容是否真的相同 —— 决定「控制段哈希」能否当唯一 key。"""
import os, sys, hashlib, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN = os.path.join(ROOT, "work", "spv_map_all.tsv")

def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    rows = []
    with open(IN, "r", encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) >= 5:
                rows.append(parts)

    by_key = collections.defaultdict(list)
    for r in rows:
        by_key[r[0]].append(r)

    dup = {k: v for k, v in by_key.items() if len(v) > 1}
    ident = 0
    differ = 0
    samples = []
    content_map = collections.defaultdict(set)
    for k, v in dup.items():
        hs = set()
        for r in v:
            p = os.path.join(ROOT, "work", r[1].replace("\\", "/"))
            hs.add(sha_file(p) if os.path.isfile(p) else "MISSING")
        if len(hs) == 1:
            ident += 1
        else:
            differ += 1
            if len(samples) < 8:
                samples.append((k, [(r[1], r[3], r[4]) for r in v[:4]]))

    # 另外：唯一 key 的条目里，同一个 spv 文件被多少个 key 引用（反向多对一）
    rev = collections.defaultdict(set)
    for k, v in by_key.items():
        for r in v:
            rev[r[1]].add(k)
    multi = sum(1 for f_, ks in rev.items() if len(ks) > 1)

    print("重复 key 总数        : %d" % len(dup))
    print("  其中内容完全相同    : %d" % ident)
    print("  其中内容不同        : %d" % differ)
    print("反向：一个 SPIR-V 被多个 key 引用 : %d" % multi)
    if samples:
        print("\n内容不同的样例:")
        for k, v in samples:
            print("  key=%s" % k)
            for item in v:
                print("     %s  ctl=%s code=%s" % item)

if __name__ == "__main__":
    main()
