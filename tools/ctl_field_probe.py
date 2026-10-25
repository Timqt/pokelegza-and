"""验证控制段字段语义：+0x18 / +0x20 到底是不是代码长度 / 到下一个控制段的距离。

同时验证：代码段起点是否是 SPH 头（0x12345678）。
"""
import os, struct, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSV = os.path.join(ROOT, "work", "spv_map_all.tsv")
BN = os.path.join(ROOT, "work", "bnsh_all")

CTL = bytes.fromhex("34127698")
SPH = bytes.fromhex("78563412")

def main():
    rows = []
    with open(TSV, "r", encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\r\n").split("\t")
            if len(p) >= 5:
                rows.append(p)

    by_container = collections.defaultdict(list)
    for r in rows:
        by_container[r[2]].append(r)

    # 取前 5 个容器做样本
    for name in list(sorted(by_container))[:5]:
        recs = sorted(by_container[name], key=lambda x: int(x[3]))
        bp = os.path.join(BN, name)
        data = open(bp, "rb").read()
        print("\n=== %s  (%d 对, BNSH %d 字节)" % (name, len(recs), len(data)))
        print("  %-10s %-10s %-8s %-8s %-10s %-10s %s" % ("ctl(BNSH)", "code(容器)", "+0x18", "+0x20", "ctl间距", "code间距", "code处魔数"))
        prev_code = None
        for r in recs:
            c = int(r[3])                      # BNSH 相对控制段偏移
            code_cont = int(r[4])              # 容器相对代码偏移
            if c + 0x24 <= len(data):
                f18 = struct.unpack_from("<I", data, c + 0x18)[0]
                f20 = struct.unpack_from("<I", data, c + 0x20)[0]
            else:
                f18 = f20 = -1
            # BNSH 内的代码偏移：容器相对 - BNSH 起点（用 code_cont - off 反推）
            # 这里直接用「容器相对」差值表示间距即可
            gap = (code_cont - prev_code) if prev_code is not None else -1
            prev_code = code_cont
            magic = ""
            # 找代码段在 BNSH 内的位置：控制段之后最近的 SPH
            j = data.find(SPH, c)
            if 0 <= j < len(data):
                magic = "SPH@%d" % j
            print("  %-10d %-10d %-8d %-8d %-10s %-10d %s" % (c, code_cont, f18, f20, "-", gap, magic))

    # 全局统计：+0x18 与 +0x20 的取值分布
    vals18 = collections.Counter()
    vals20 = collections.Counter()
    n = 0
    for name, recs in by_container.items():
        bp = os.path.join(BN, name)
        if not os.path.exists(bp):
            continue
        data = open(bp, "rb").read()
        for r in recs:
            c = int(r[3])
            if c + 0x24 <= len(data):
                vals18[struct.unpack_from("<I", data, c + 0x18)[0]] += 1
                vals20[struct.unpack_from("<I", data, c + 0x20)[0]] += 1
                n += 1
    print("\n全局：%d 个控制段" % n)
    print("  +0x18 不同取值数 = %d，最常见 5 个 = %s" % (len(vals18), vals18.most_common(5)))
    print("  +0x20 不同取值数 = %d，最常见 5 个 = %s" % (len(vals20), vals20.most_common(5)))

if __name__ == "__main__":
    main()
