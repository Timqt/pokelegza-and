"""阶段修正后的运行时着色器表（重建版）。

与旧版差异：
 1. SPIR-V 语料换成阶段修正后的 spv_all4（文件名带 _Vertex/_Fragment）；
 2. 表里增加 stage 字段（运行时建管线要用）；
 3. 重复 key 用确定性规则裁定，并把真冲突写进 .conflicts.tsv（D2R 同款做法）。

key 口径（沿用 D2R）：sha256(控制段 0x880 字节)[:16]
冲突裁定：同一 key 下多个不同 SPIR-V 时，取（代码段字节, 控制段字节）差异最小者；
          再并列取字节数小者；再并列取 SPIR-V 哈希最小者（完全确定性）。
"""
import os, sys, hashlib, collections, struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPV_DIRS = [os.path.join(ROOT, "work", "spv_all4"), os.path.join(ROOT, "work", "spv_all3")]
BN = os.path.join(ROOT, "work", "bnsh_all")
TSV = os.path.join(ROOT, "work", "spv_map_all.tsv")
OUT = os.path.join(ROOT, "work", "spv_map_final.tsv")
CONF = OUT + ".conflicts.tsv"

CTL_LEN = 0x880


def sha16(b):
    return hashlib.sha256(b).hexdigest()[:16]


def load_spv_index():
    """(容器基名, 容器相对代码偏移) -> (路径, stage)"""
    idx = {}
    for d in SPV_DIRS:
        if not os.path.isdir(d):
            continue
        for root, _, fs in os.walk(d):
            for f in fs:
                if not f.endswith(".spv"):
                    continue
                stem = f[:-4]
                parts = stem.rsplit("_", 2)
                if len(parts) != 3:
                    continue
                try:
                    off = int(parts[1], 16)
                except ValueError:
                    continue
                key = (parts[0], off)
                # spv_all4 优先（阶段修正版）
                if key not in idx or "spv_all4" in d:
                    idx[key] = (os.path.join(root, f), parts[2])
    return idx


def main():
    spv_idx = load_spv_index()
    rows = []
    with open(TSV, "r", encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\r\n").split("\t")
            if len(p) >= 5:
                rows.append(p)

    by_key = collections.defaultdict(list)
    for p in rows:
        by_key[p[0]].append(p)

    out_rows = []
    conflicts = []
    nmiss = 0
    stage_count = collections.Counter()

    for key in sorted(by_key):
        cands = []
        for p in by_key[key]:
            ctl_off = int(p[3])
            code_off = int(p[4])          # 容器相对
            bpath = os.path.join(BN, p[2])
            ctl_bytes = b""
            if os.path.exists(bpath):
                with open(bpath, "rb") as g:
                    g.seek(ctl_off)
                    ctl_bytes = g.read(CTL_LEN)
            hit = spv_idx.get((p[2][:p[2].rfind(".bnsh")] if p[2].endswith(".bnsh") else p[2], code_off))
            if hit is None:
                nmiss += 1
                continue
            spv_path, stage = hit
            cands.append((spv_path, stage, ctl_bytes, p))
        if not cands:
            continue

        # 去重：同 key 下内容相同的只留一份
        uniq = {}
        for c in cands:
            h = sha16(open(c[0], "rb").read())
            uniq.setdefault(h, c)
        items = list(uniq.values())
        if len(items) > 1:
            # 真冲突：按（代码字节差异、字节数、SPIR-V 哈希）确定性裁定
            base = items[0]
            scored = []
            for c in items:
                diff = sum(1 for a, b in zip(base[2], c[2]) if a != b) if len(base[2]) == len(c[2]) else 9999
                sz = os.path.getsize(c[0])
                h = sha16(open(c[0], "rb").read())
                scored.append((diff, sz, h, c))
            scored.sort(key=lambda x: (x[0], x[1], x[2]))
            chosen = scored[0]
            conflicts.append((key, chosen[2], [
                (x[2], x[0], x[1], x[3][0], x[3][1], x[3][3][2])   # 哈希, 差异, 字节数, SPIR-V 路径, stage, 容器
                for x in scored]))
            c = chosen[3]
        else:
            c = items[0]
        stage_count[c[1]] += 1
        out_rows.append((key, c[1], os.path.relpath(c[0], os.path.join(ROOT, "work")), c[3][2], c[3][3], c[3][4]))

    with open(OUT, "w", encoding="utf-8", newline="\n") as o:
        o.write("ctl_sha16\tstage\tspv_file\tcontainer\tctl_offset(BNSH相对)\tcode_offset(容器相对)\n")
        for r in out_rows:
            o.write("\t".join(str(x) for x in r) + "\n")

    with open(CONF, "w", encoding="utf-8", newline="\n") as o:
        o.write("# kind: evidence  同一控制段 key 对应多个不同 SPIR-V 的裁定（差异最小 → 字节数小 → 哈希最小）\n")
        o.write("# 同一 key 下多个 SPIR-V 内容不同 ⇒ 控制段本身不足以唯一标识着色器；运行时需用「控制段 sha16 + 代码前缀 sha16」二级键消歧\n")
        o.write("ctl_sha16\tchosen_spv_sha16\tcandidates(spv_sha16:差异:字节数:stage:容器:文件)\n")
        for key, chosen, cands in conflicts:
            o.write("%s\t%s\t%s\n" % (key, chosen, " ".join(
                "%s:%d:%d:%s:%s:%s" % (h, d, s, st, cont, os.path.basename(f))
                for h, d, s, f, st, cont in cands)))

    print("唯一 key        : %d" % len(out_rows))
    print("阶段分布        : %s" % dict(stage_count))
    print("真冲突          : %d" % len(conflicts))
    print("挂不上 SPIR-V   : %d" % nmiss)
    print("输出            : %s" % OUT)
    print("冲突记录        : %s" % CONF)


if __name__ == "__main__":
    main()
