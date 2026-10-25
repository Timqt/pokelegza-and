#!/usr/bin/env python3
"""从带 -g 的 .so 的 DWARF 行号表里，还原某个源文件用到的**行号集合**。

源文件被误清空后，这能告诉我们：原文件有多少行、哪些行是代码（有地址映射）、
行号的分段边界（= 函数/语句块的位置），作为重建骨架。

用法:
    python tools/recover_lines.py <so> [源文件名关键字]
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
    r = subprocess.run([DWARFDUMP, "--debug-line", so],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    lines = r.stdout.splitlines()

    # 找 "name: "<key>"" 的 file_names 下标。行号表里第 4 列是文件下标。
    # 先收集每个 CU 区块里 key 的 file index
    target_idx = set()
    for i, ln in enumerate(lines):
        m = re.search(r'name: "([^"]+)"', ln)
        if m and key in m.group(1):
            # 往上找 file_names[ N ]:
            for j in range(i - 1, max(i - 6, 0), -1):
                fm = re.search(r"file_names\[\s*(\d+)\]", lines[j])
                if fm:
                    target_idx.add(int(fm.group(1)))
                    break
    print("目标文件在行号表中的下标：", sorted(target_idx) or "未找到")

    used = []
    for ln in lines:
        # 形如：0x00000000000b7a70    794      0      1   ...
        m = re.match(r"\s*(0x[0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)", ln)
        if not m:
            continue
        row = int(m.group(2))
        fidx = int(m.group(4))
        if target_idx and fidx not in target_idx:
            continue
        used.append(row)

    if not used:
        print("没抓到 %s 的行号（可能该 CU 的 file index 不是 %s）" % (key, sorted(target_idx)))
        return
    used.sort()
    print("有代码映射的行号：%d 个不同行，范围 %d .. %d" % (len(set(used)), min(used), max(used)))
    # 连续段（= 语句块）
    segs, start, prev = [], used[0], used[0]
    for x in used[1:]:
        if x > prev + 3:
            segs.append((start, prev))
            start = x
        prev = x
    segs.append((start, prev))
    print("连续代码段 %d 个（每段大致对应一个函数/语句块）：" % len(segs))
    for a, b in segs:
        print("   %5d .. %5d   (%d 行)" % (a, b, b - a + 1))


if __name__ == "__main__":
    main()
