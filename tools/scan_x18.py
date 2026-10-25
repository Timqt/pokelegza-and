#!/usr/bin/env python3
"""扫 Z-A 的 main NSO 与 SDK NSO：x18 的用法 + TPIDR 的用法统计。"""
import os, re, struct, sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and"
sys.path.insert(0, ROOT)
try:
    import capstone
    HAVE_CAP = True
except Exception:
    HAVE_CAP = False

def scan(path, name):
    b = open(path, "rb").read()
    n = len(b) // 4
    w = struct.unpack_from("<%dI" % n, b, 0)
    cnt = {"mrs_x18": 0, "msr_x18": 0, "mrs_tpidr": 0, "mrs_tpidrro": 0,
           "msr_tpidr": 0, "use_x18": 0, "cntpct": 0, "svc": 0}
    # 粗略：任何含 x18 的指令字（mov/add/ldr/str 的 Rd/Rn 为 18）
    for i in range(n):
        x = w[i]
        if (x & 0xFFE0001F) == 0xD5300000:      # mrs
            rd = x & 0x1F
            op = (x >> 5) & 0x7FFFF
            if op == 0x5B8:  cnt["mrs_tpidr"] += 1
            if op == 0x5B9:  cnt["mrs_tpidrro"] += 1
            if rd == 18:     cnt["mrs_x18"] += 1
        elif (x & 0xFFE0001F) == 0xD5100000:    # msr
            rn = x & 0x1F
            op = (x >> 5) & 0x7FFFF
            if op == 0x5B8:  cnt["msr_tpidr"] += 1
            if rn == 18:     cnt["msr_x18"] += 1
        elif (x & 0xFFC00000) == 0xD53BE000:
            if (x & 0xFFFFFFE0) == 0xD53BE020: cnt["cntpct"] += 1
        elif (x & 0xFFE0001F) == 0xD4000001: cnt["svc"] += 1
        else:
            # 通用寄存器 18 作为 Rd/Rn
            rd = x & 0x1F
            rn = (x >> 5) & 0x1F
            if rd == 18 or rn == 18: cnt["use_x18"] += 1
    print("%-12s %s" % (name, cnt))

scan(os.path.join(ROOT, "work", "nso_32848007", "text.bin"), "SDK")
for p in ("work/nso/text.bin",):
    fp = os.path.join(ROOT, p.replace("/", os.sep))
    if os.path.exists(fp):
        scan(fp, "main")
