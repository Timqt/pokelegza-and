"""对比 D2R 的 Switch 着色器包里 vs / ps 的代码段头部，定位 Ryujinx 读阶段的依据。"""
import os, re, struct, sys

D2R = r"D:\feiniukexinhome\Code\d2r-and\pack-workspace\produce\shaders\work\packages"
SPH = bytes.fromhex("78563412")
CTL = bytes.fromhex("34127698")

def records(d):
    r = [m.start() for m in re.finditer(b'BTCDBTCD', d)]
    return [d[x:(r[k + 1] if k + 1 < len(r) else len(d))] for k, x in enumerate(r)]

def dump(prefix, label):
    files = sorted(f for f in os.listdir(D2R) if f.startswith(prefix))
    if not files:
        print(label, "无文件"); return
    f = files[0]
    d = open(os.path.join(D2R, f), "rb").read()
    recs = records(d)
    print("== %s  (%s, %d 条记录)" % (label, f, len(recs)))
    for k, rec in enumerate(recs[:3]):
        i = rec.find(SPH)
        j = rec.find(CTL)
        print("  记录%d len=%d  SPH@%d CTL@%d" % (k, len(rec), i, j))
        if i >= 0:
            hdr = rec[i:i + 0x50]
            print("    代码段头: " + " ".join("%02x" % b for b in hdr[:0x20]))
            print("    +0x20..0x50: " + " ".join("%02x" % b for b in hdr[0x20:0x50]))
            w = struct.unpack_from("<I", rec, i + 0x30)[0]
            print("    code+0x30 字 = 0x%08X  -> bits10..13 = %d  (%s)" % (w, (w >> 10) & 0xF, {1: "vs", 5: "ps"}.get((w >> 10) & 0xF, "?")))

dump("vs_", "顶点")
dump("ps_", "片元")
dump("cs_", "计算")
