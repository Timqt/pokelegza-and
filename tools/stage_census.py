"""按 D2R 实测规则（maxwell_refs.py:sph_stage）统计全语料 SPH 的真实阶段。

规则：代码段前 4 字节 = 0x12345678；阶段 = (u32 @ code+0x30 >> 10) & 0xf，1=vs / 5=ps。
Ryujinx 之前把全部 SPH 报成 Fragment，这里核对两者。
"""
import os, struct, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BN = os.path.join(ROOT, "work", "bnsh_all")
SPH = bytes.fromhex("78563412")

def main():
    dist = collections.Counter()
    per_file = collections.Counter()
    nfiles = 0
    examples = {}
    for name in sorted(os.listdir(BN)):
        p = os.path.join(BN, name)
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        nfiles += 1
        pos = 0
        while True:
            i = data.find(SPH, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 0x34 > len(data):
                continue
            w = struct.unpack_from("<I", data, i + 0x30)[0]
            st = (w >> 10) & 0xF
            dist[st] += 1
            per_file[st] += 1
            if st not in examples:
                examples[st] = (name, i, hex(w))
    print("扫描 BNSH 文件 %d 个" % nfiles)
    print("阶段字段 (code+0x30 >> 10) & 0xf 分布：")
    for k, v in dist.most_common():
        tag = {1: "vs 顶点", 5: "ps 片元"}.get(k, "?")
        print("   值 %2d  %-8s  %6d 个   例：%s @0x%X (word=%s)" % (k, tag, v, examples[k][0][:60], examples[k][1], examples[k][2]))
    print("\n合计 SPH %d 个" % sum(dist.values()))

if __name__ == "__main__":
    main()
