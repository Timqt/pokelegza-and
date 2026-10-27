#!/usr/bin/env python3
"""从 main 的 NVN 名字表生成 app/native/za_nvn_names.h（X-macro 清单）。

名字来源：main+0x1775db0 里那条「逐个 nvnDeviceGetProcAddress(dev, 名字)」的
解析例程（一串 adrp+add 指向 rodata 字符串）。清单可以直接从 NSO 里解出来，
也可以用 --dump 落到 work/nvn_names.txt 再看。

用法:
    python tools/gen_nvn_names.py                  # 直接从 work/nso_0 解名字并生成头文件
    python tools/gen_nvn_names.py --dump OUT.txt   # 只把名字清单落盘
    python tools/gen_nvn_names.py IN.txt OUT.h     # 用现成清单生成
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO_TEXT = os.path.join(ROOT, "work", "nso_0", "text.bin")
NSO_RODATA = os.path.join(ROOT, "work", "nso_0", "rodata.bin")
RO_BASE = 0x2FC8000          # rodata 段的装载地址（work/nso_0/layout.txt: ro_mem）
RESOLVER = 0x1775DB0         # 解析例程入口（main+0x1775db0）
DST = os.path.join(ROOT, "app", "native", "za_nvn_names.h")


def _decode_adrp(w, pc):
    immhi = (w >> 5) & 0x7FFFF
    immlo = (w >> 29) & 3
    off = (immhi << 2) | immlo
    if off & (1 << 20):
        off -= 1 << 21
    return (pc & ~0xFFF) + (off << 12)


def extract_names():
    """扫解析例程，取出它请求的全部名字（adrp+add 指向 rodata 的 C 字符串）。"""
    text = open(NSO_TEXT, "rb").read()
    ro = open(NSO_RODATA, "rb").read()
    out = []
    for k in range(0, 5000):
        i = RESOLVER + 4 * k
        w = struct.unpack_from("<I", text, i)[0]
        if (w & 0x9F000000) == 0x90000000:            # adrp
            rd = w & 0x1F
            page = _decode_adrp(w, i)
            w2 = struct.unpack_from("<I", text, i + 4)[0]
            if ((w2 & 0xFFC00000) == 0x91000000          # add xRd, xRd, #imm
                    and ((w2 >> 5) & 0x1F) == rd and (w2 & 0x1F) == rd):
                va = page + ((w2 >> 10) & 0xFFF)
                if RO_BASE <= va < RO_BASE + len(ro):
                    s = ro[va - RO_BASE:va - RO_BASE + 96].split(b"\0")[0]
                    try:
                        s = s.decode()
                    except UnicodeDecodeError:
                        s = ""
                    if len(s) > 3 and all(32 <= ord(c) < 127 for c in s):
                        out.append(s)
        if (w & 0xFC000000) == 0x94000000:            # bl 到例程外 ⇒ 结束
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            if i + imm * 4 < RESOLVER:
                break
    return out


def main():
    args = [a for a in sys.argv[1:]]
    if args and args[0] == "--dump":
        dst = args[1] if len(args) > 1 else os.path.join(ROOT, "work", "nvn_names.txt")
        names = extract_names()
        open(dst, "w", encoding="utf-8", newline="\n").write("\n".join(names) + "\n")
        print("names=%d -> %s" % (len(names), dst))
        return

    if len(args) >= 2:
        src_names = [l.strip() for l in open(args[0], encoding="utf-8") if l.strip()]
        dst = args[1]
    else:
        src_names = extract_names()
        dst = DST

    names, seen = [], set()
    for n in src_names:
        if not n.startswith("nvn") or n in seen:
            continue
        seen.add(n)
        names.append(n)

    out = []
    out.append("// 由 tools/gen_nvn_names.py 从 main 的 NVN 解析例程（main+0x1775db0）生成，勿手改。")
    out.append("// 名字 = main 里那条「逐个 nvnDeviceGetProcAddress(dev, 名字)」请求的全部条目。")
    out.append("#ifndef ZA_NVN_NAMES_H")
    out.append("#define ZA_NVN_NAMES_H")
    out.append("")
    out.append("#define ZA_NVN_ENUM(X) \\")
    for i, n in enumerate(names):
        out.append("    X(%s)%s" % (n, " \\" if i + 1 < len(names) else ""))
    out.append("")
    out.append("#define ZA_NVN_COUNT %d" % len(names))
    out.append("")
    out.append("#endif")
    open(dst, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    print("names=%d -> %s" % (len(names), dst))


if __name__ == "__main__":
    main()
