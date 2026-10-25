"""质检运行时着色器查找表，并产出确定性裁定后的最终表。

输入: work/spv_map_all.tsv  (sha16 \t spv_file \t container \t ctl_off \t code_off)
输出:
  work/spv_map_final.tsv  去重后的最终表（每个 sha16 一行）
  统计打印到 stdout
"""
import os, sys, hashlib, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN = os.path.join(ROOT, "work", "spv_map_all.tsv")
OUT = os.path.join(ROOT, "work", "spv_map_final.tsv")

def main():
    rows = []
    with open(IN, "r", encoding="utf-8", errors="replace") as f:
        header = f.readline()
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            rows.append((parts[0], parts[1], parts[2], parts[3], parts[4]))

    by_key = collections.defaultdict(list)
    for r in rows:
        by_key[r[0]].append(r)

    dup_keys = {k: v for k, v in by_key.items() if len(v) > 1}
    # 统计同一 key 下不同 spv 文件 vs 完全同文件
    diff_file = 0
    same_file = 0
    for k, v in dup_keys.items():
        if len({x[1] for x in v}) > 1:
            diff_file += 1
        else:
            same_file += 1

    # 校验每个 SPIR-V 文件存在 + 魔数
    missing = 0
    badmagic = 0
    total_bytes = 0
    for r in rows:
        p = os.path.join(ROOT, "work", r[1].replace("\\", "/"))
        if not os.path.isfile(p):
            missing += 1
            continue
        try:
            with open(p, "rb") as g:
                head = g.read(4)
                sz = os.path.getsize(p)
            total_bytes += sz
            if head != b"\x03\x02\x23\x07":
                badmagic += 1
        except OSError:
            missing += 1

    # 确定性裁定：同一 key 多条时，取 (容器名, spv 文件名) 字典序最小的一条。
    # 理由：稳定、可复现、与加载顺序无关。
    final = []
    for k in sorted(by_key):
        cand = sorted(by_key[k], key=lambda x: (x[2], x[1]))
        final.append(cand[0])

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("ctl_sha16\tspv_file\tcontainer\tctl_offset(BNSH\u76f8\u5bf9)\tcode_offset(\u5bb9\u5668\u76f8\u5bf9)\n")
        for r in final:
            f.write("\t".join(r) + "\n")

    print("输入总条目            : %d" % len(rows))
    print("唯一 key             : %d" % len(by_key))
    print("重复 key             : %d  (其中 %d 个指向不同 SPIR-V 文件, %d 个完全相同)" % (len(dup_keys), diff_file, same_file))
    print("裁重后最终条目        : %d" % len(final))
    print("SPIR-V 缺失          : %d" % missing)
    print("SPIR-V 魔数异常      : %d" % badmagic)
    print("SPIR-V 合计          : %.1f MB" % (total_bytes / 1048576.0))
    print("最终表已写出          : %s" % OUT)

if __name__ == "__main__":
    main()
