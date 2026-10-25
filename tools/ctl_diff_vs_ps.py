"""并排 diff 顶点/片元着色器的控制段（0x880 字节），定位与贴图槽、输出目标相关的字段。

控制段 = 0x98761234 开头。每 4 字节一格，标出：
  · 两个控制段相同的字段
  · 只在片元段有值的字段（贴图/输出相关）
"""
import os, struct, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BN = os.path.join(ROOT, "work", "bnsh_all")
TSV = os.path.join(ROOT, "work", "spv_map_all.tsv")
CTL = bytes.fromhex("34127698")
SPH = bytes.fromhex("78563412")
CTL_LEN = 0x880

def stage_of(data, off):
    """SPH 在 off 处 → 阶段字在 off+0x30"""
    return (struct.unpack_from("<I", data, off + 0x30)[0] >> 10) & 0xF

def main():
    rows = []
    with open(TSV, "r", encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\r\n").split("\t")
            if len(p) >= 5:
                rows.append(p)

    # 找一个容器里同时有 vs 和 ps 的
    by_container = collections.defaultdict(list)
    for r in rows:
        by_container[r[2]].append(r)

    vs = ps = None
    vname = pname = None
    for name, recs in by_container.items():
        bp = os.path.join(BN, name)
        if not os.path.exists(bp):
            continue
        data = open(bp, "rb").read()
        sphs = []
        pos = 0
        while True:
            j = data.find(SPH, pos)
            if j < 0:
                break
            pos = j + 1
            sphs.append(j)
        if not sphs:
            continue
        vs_l = ps_l = None
        for r in recs:
            c = int(r[3])
            if c + CTL_LEN > len(data):
                continue
            # 记录表：u32@c 出现在位置 p ⇒ 记录基址 p-0x08，代码偏移 = u32@(p+0x08)
            code = None
            p = data.find(struct.pack("<I", c), 0x100)
            while p >= 0:
                if p + 12 <= len(data):
                    cand = struct.unpack_from("<I", data, p + 8)[0]
                    if cand in sphs:
                        code = cand
                        break
                p = data.find(struct.pack("<I", c), p + 1)
            if code is None:
                continue
            st = stage_of(data, code)
            if st == 1 and vs_l is None:
                vs_l = (c, code, data)
            elif st == 5 and ps_l is None:
                ps_l = (c, code, data)
        if vs_l and ps_l:
            vs, ps, vname, pname = vs_l, ps_l, name, name
            break

    if not (vs and ps):
        print("找不到同时含 vs/ps 的样本"); return

    cv = vs[2][vs[0]:vs[0] + CTL_LEN]
    cp = ps[2][ps[0]:ps[0] + CTL_LEN]
    print("容器 %s" % vname)
    print("  vs: 控制段@0x%X 代码@0x%X" % (vs[0], vs[1]))
    print("  ps: 控制段@0x%X 代码@0x%X" % (ps[0], ps[1]))
    print("\n偏移      顶点(16进制)      片元(16进制)     备注")
    for off in range(0, CTL_LEN, 4):
        a = struct.unpack_from("<I", cv, off)[0]
        b = struct.unpack_from("<I", cp, off)[0]
        if a == b == 0:
            continue
        mark = "相同" if a == b else "不同"
        if a == b and a != 0:
            mark = "相同(常量)"
        print("  +0x%03X  0x%08X      0x%08X      %s" % (off, a, b, mark))

if __name__ == "__main__":
    main()
