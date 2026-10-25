#!/usr/bin/env python3
"""交叉核对：所有 `mrs TPIDR* + blr` 点位，是否都被 TLS helper 改写表覆盖。

没被覆盖的那些就是「客机会拿 bionic 的 tp 当数据用」的漏网点，
其中「把 TPIDR 当函数指针 blr」的就是 pc=0 崩点的候选。

用法:
    python tools/audit_tls_blr.py
"""
import os
import re
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_TEXT = os.path.join(ROOT, "work", "nso", "text.bin")
SDK_TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
H_MAIN = os.path.join(ROOT, "app", "native", "za_tls_patch.h")
H_RO = os.path.join(ROOT, "app", "native", "za_tlsro_patch.h")

MRS_TPIDR_EL0 = 0xD53BD040
MRS_TPIDRRO_EL0 = 0xD53BD060


def load_offs(path, name):
    s = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(name + r"\[\]\s*=\s*\{(.*?)\};", s, re.S)
    if not m:
        return set()
    return {int(x, 16) for x in re.findall(r"\{(0x[0-9a-fA-F]+)u,", m.group(1))}


def find_blr_sites(t):
    """返回 [(mrs偏移, 是哪个TPIDR, blr偏移)]。"""
    out = []
    for i in range(0, len(t) - 68, 4):
        w = struct.unpack_from("<I", t, i)[0]
        if (w & 0xFFFFFFE0) == MRS_TPIDR_EL0:
            which, rt = "TPIDR_EL0", w & 0x1F
        elif (w & 0xFFFFFFE0) == MRS_TPIDRRO_EL0:
            which, rt = "TPIDRRO_EL0", w & 0x1F
        else:
            continue
        for k in range(1, 17):
            off = i + k * 4
            wk = struct.unpack_from("<I", t, off)[0]
            if (wk & 0xFFFFFC1F) == 0xD63F0000 and ((wk >> 5) & 0x1F) == rt:
                out.append((i, which, off))
                break
    return out


def main():
    main_p = load_offs(H_MAIN, "za_tls_patches")
    sdk_p = load_offs(H_RO, "za_tlsro_patches")
    print("改写表：main %d 条、SDK %d 条" % (len(main_p), len(sdk_p)))

    for label, path, patch in (("main", MAIN_TEXT, main_p), ("SDK", SDK_TEXT, sdk_p)):
        t = open(path, "rb").read()
        sites = find_blr_sites(t)
        print("\n=== %s：`mrs TPIDR* + blr` 共 %d 处 ===" % (label, len(sites)))
        miss = 0
        for mrs_off, which, blr_off in sites:
            covered = mrs_off in patch
            if not covered:
                miss += 1
                print("   ⚠ %#010x  mrs %s ... %#010x blr  **未改写**"
                      % (mrs_off, which, blr_off))
        if not miss:
            print("   全部已覆盖")
        else:
            print("   未改写 %d 处（上面列出的就是候选崩点）" % miss)


if __name__ == "__main__":
    main()
