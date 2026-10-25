#!/usr/bin/env python3
"""定位 BNSH 里的 grsc 着色器映射表。

表结构（由小文件反推）：每条记录 0x30 字节，其中
    +0x18 : 控制段偏移（该处是 0x98761234）
    +0x20 : 代码段偏移（该处是 SPH 魔数 0x12345678）
    +0x2c : 控制段长度（0x880）
本脚本用「三个特征同时成立」来定位表基址并校验整张表。
"""

import os
import struct
import sys

SPH = bytes.fromhex("78563412")
CTL = bytes.fromhex("34127698")
STRIDE = 0x30


def find_all(data, magic):
    out = []
    pos = 0
    while True:
        i = data.find(magic, pos)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out


def try_table(data, base):
    """返回 (记录数, [(ctl_off, code_off)]) 或 None。"""
    recs = []
    b = base
    while b + STRIDE <= len(data):
        ctl = struct.unpack_from("<I", data, b + 0x18)[0]
        code = struct.unpack_from("<I", data, b + 0x20)[0]
        clen = struct.unpack_from("<I", data, b + 0x2C)[0]
        if clen != 0x880:
            break
        if ctl + 4 > len(data) or data[ctl:ctl + 4] != CTL:
            break
        if code + 4 > len(data) or data[code:code + 4] != SPH:
            break
        recs.append((ctl, code))
        b += STRIDE
    return recs or None


def find_table(data):
    """全文件搜「控制段偏移 + 代码段偏移 + 0x880」三连签名，定位 grsc 着色器表。"""
    cands = []
    for off in range(0, len(data) - 0x30, 4):
        ctl = struct.unpack_from("<I", data, off)[0]
        code = struct.unpack_from("<I", data, off + 8)[0]
        clen = struct.unpack_from("<I", data, off + 0x14)[0]
        if clen != 0x880:
            continue
        if ctl + 4 > len(data) or data[ctl:ctl + 4] != CTL:
            continue
        if code + 4 > len(data) or data[code:code + 4] != SPH:
            continue
        cands.append(off)
    best = None
    for off in cands:
        recs = try_table(data, off - 0x18)   # 表基址 = 记录起点（记录内 +0x18 才是字段）
        if recs and (best is None or len(recs) > len(best[1])):
            best = (off - 0x18, recs)
    return best


def analyze(path):
    data = open(path, "rb").read()
    sph = find_all(data, SPH)
    ctl = find_all(data, CTL)
    print("=== %s (%d 字节) ===" % (os.path.basename(path), len(data)))
    print("  SPH 魔数 %d 处, 控制段 %d 处" % (len(sph), len(ctl)))
    best = find_table(data)
    if best:
        base, recs = best
        print("  grsc 表基址 0x%x, 记录 %d 条" % (base, len(recs)))
        print("  前 5 条 (控制段, 代码段): %s" % recs[:5])
        tbl_ctl = sorted(r[0] for r in recs)
        print("  表内控制段 == 文件全部控制段: %s" % (tbl_ctl == sorted(ctl)))
        used_sph = set(r[1] for r in recs)
        print("  表内代码段 %d 个, 文件 SPH %d 个, 多出的 SPH(疑似误命中) %d" % (
            len(used_sph), len(sph), len(sph) - len(used_sph)))
    else:
        print("  !! 没找到 grsc 表")
    return best


def main():
    for p in sys.argv[1:]:
        analyze(p)
        print()


if __name__ == "__main__":
    main()
