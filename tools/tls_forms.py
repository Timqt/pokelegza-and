#!/usr/bin/env python3
"""统计客机里「mrs TPIDR_EL0」之后第二条指令的形态分布。

目的：搞清楚到底有几种「用 TPIDR」的写法，判断改写器该覆盖哪些。
（实测踩过：只认 ubfm / and 两种掩码形态，漏掉了 `add xN, TPIDR, xM` 这类。）

用法:
    python tools/tls_forms.py work/nso/text.bin
"""
import struct
import sys
from collections import Counter

MRS_TPIDR_EL0 = 0xD53BD040


def desc(w):
    if (w & 0xFFFFFC00) == 0xF273C800:
        return "ubfm (掩 ~0x1FFF)"
    if (w & 0xFFFFFC00) == 0x9273C800:
        return "and  (掩 ~0x1FFF)"
    if (w & 0x7F800000) == 0x11000000:
        return "add/sub (立即数)"
    if (w & 0xFFE0FC00) == 0x8B000000:
        return "add (寄存器)"
    if (w & 0xFFC00000) == 0xF9400000:
        return "ldr (立即数)"
    if (w & 0xFFC00000) == 0xF9000000:
        return "str (立即数)"
    if (w & 0xFFE00C00) == 0x8B000000:
        return "add (寄存器, 变体)"
    if w == 0xD65F03C0:
        return "ret"
    return "其它 %#010x" % w


def main():
    t = open(sys.argv[1], "rb").read()
    c = Counter()
    n = 0
    for i in range(0, len(t) - 8, 4):
        w = struct.unpack_from("<I", t, i)[0]
        if (w & 0xFFFFFFE0) != MRS_TPIDR_EL0:
            continue
        n += 1
        w2 = struct.unpack_from("<I", t, i + 4)[0]
        # 只看下一条是否操作同一个目标寄存器
        rt = w & 0x1F
        src2 = (w2 >> 5) & 0x1F
        dst2 = w2 & 0x1F
        tag = desc(w2)
        if src2 != rt and dst2 != rt:
            tag = "下一条未用 x%d → " % rt + tag
        c[tag] += 1
    print("%s：mrs TPIDR_EL0 共 %d 处，下一条形态分布：" % (sys.argv[1], n))
    for k, v in c.most_common(20):
        print("   %5d  %s" % (v, k))


if __name__ == "__main__":
    main()
