#!/usr/bin/env python3
"""扫描 NSO 的 text 段里的 SVC（Horizon 服务调用）指令。

为什么重要：客机/SDK 用 `svc #n` 调 Horizon 的内核服务（线程、事件、内存、文件…）。
在 Linux/arm64 上 `svc` 就是系统调用 ⇒ 未知号 ⇒ **SIGSYS**，客机直接死。
⇒ 必须把 svc 改写成跳到宿主门（宿主再决定怎么实现这些服务）。

AArch64 编码：SVC #imm16 = 0xD4000001 | (imm16 << 5)
"""
import collections
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CANDIDATES = {
    "entry_0": os.path.join(ROOT, "work", "nso", "text.bin"),
    "entry_32848007": os.path.join(ROOT, "work", "nso_32848007", "text.bin"),
}


def scan(path, tag):
    d = open(path, "rb").read()
    n = len(d) // 4
    words = struct.unpack_from("<%dI" % n, d, 0)
    hits = []
    for i in range(n):
        w = words[i]
        if (w & 0xFFE0001F) == 0xD4000001:
            hits.append((i * 4, (w >> 5) & 0xFFFF))
    print("== %s ==  text %d 字节" % (tag, len(d)))
    print("   SVC 指令 %d 处" % len(hits))
    c = collections.Counter(imm for _, imm in hits)
    print("   服务号分布（前 20）:")
    for imm, k in c.most_common(20):
        print("      svc #%d (0x%x)  ×%d" % (imm, imm, k))
    for off, imm in hits[:10]:
        print("      text+%#x  svc #%d" % (off, imm))
    return hits


if __name__ == "__main__":
    for tag, path in CANDIDATES.items():
        if os.path.exists(path):
            scan(path, tag)
