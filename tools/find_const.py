#!/usr/bin/env python3
"""在 SDK/main 的 text 段里搜 32 位常量（小端），列出命中偏移。

用法：
    python find_const.py <text.bin> <const> [const2 ...]
    python find_const.py <text.bin> 0x4F434653 0x49434653
"""
import struct
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    path = sys.argv[1]
    targets = [int(a, 0) for a in sys.argv[2:]]
    with open(path, "rb") as f:
        data = f.read()
    for t in targets:
        pat = struct.pack("<I", t & 0xFFFFFFFF)
        hits = []
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        print("const %#x -> %d hit(s): %s" % (t, len(hits), " ".join(hex(h) for h in hits[:40])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
