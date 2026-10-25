#!/usr/bin/env python3
"""从带 -g 的 .so 里提取某个源文件的函数骨架（名字 + 声明行号 + 代码大小）。

源文件被误清空后，靠这个拿到「有哪些函数、各在第几行」，作为重建的精确骨架。

用法:
    python tools/recover_dwarf.py <so> [源文件名关键字]
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DWARFDUMP = os.path.join(
    ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
    "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-dwarfdump.exe")


def main():
    so = sys.argv[1]
    key = sys.argv[2] if len(sys.argv) > 2 else "za_guest.c"
    r = subprocess.run([DWARFDUMP, "--debug-info", so],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    text = r.stdout

    # 按 DW_TAG_subprogram 切块（块内到下一个 DW_TAG_ 前）
    blocks = re.split(r"\n(?=0x[0-9a-f]+: DW_TAG_)", text)
    rows = []
    for b in blocks:
        if "DW_TAG_subprogram" not in b:
            continue
        if key not in b:
            continue
        if "DW_AT_declaration\t(true)" in b or "DW_AT_declaration\t(true)" in b.replace(" ", "\t"):
            continue
        m_name = re.search(r'DW_AT_name\t\("([^"]+)"\)', b)
        m_line = re.search(r"DW_AT_decl_line\t\((\d+)\)", b)
        m_lo = re.search(r"DW_AT_low_pc\t\((0x[0-9a-f]+)\)", b)
        m_hi = re.search(r"DW_AT_high_pc\t\((0x[0-9a-f]+)\)", b)
        if not (m_name and m_line):
            continue
        size = 0
        if m_lo and m_hi:
            size = int(m_hi.group(1), 16) - int(m_lo.group(1), 16)
        rows.append((int(m_line.group(1)), m_name.group(1), size))

    rows.sort()
    print("%s 中 %s 的**已定义**函数：%d 个" % (os.path.basename(so), key, len(rows)))
    print("   行号     代码字节  函数")
    for line, name, size in rows:
        print("  %5d   %7d   %s" % (line, size, name))
    if rows:
        print("\n最大行号 %d ⇒ 原文件至少这么多行" % max(r[0] for r in rows))


if __name__ == "__main__":
    main()
