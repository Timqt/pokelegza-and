#!/usr/bin/env python3
"""从 PFS0（ExeFS 段）里按表解出各文件，绕开 hactool 的 16 MiB 截断。"""
import struct
import sys
from pathlib import Path

PFS0 = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\base\exefs.pfs0")
OUT = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\base\exefs2")


def main():
    d = PFS0.read_bytes()
    magic = d[:4]
    cnt, strsz = struct.unpack_from("<II", d, 4)
    print(f"magic={magic} files={cnt} strsize={strsz} total={len(d)}")
    entries = []
    off = 0x10
    for i in range(cnt):
        eo, es, no, ns = struct.unpack_from("<QQII", d, off)
        off += 0x18
        entries.append((eo, es, no, ns))
    strbase = 0x10 + cnt * 0x18
    datbase = strbase + strsz
    OUT.mkdir(parents=True, exist_ok=True)
    for eo, es, no, ns in entries:
        name = d[strbase + no: strbase + no + ns].rstrip(b"\0").decode("utf-8", "replace")
        blob = d[datbase + eo: datbase + eo + es]
        p = OUT / (name or f"entry_{eo}")
        p.write_bytes(blob)
        print(f"  {name!r}: size={es} -> {p.name} ({len(blob)} 字节)")


if __name__ == "__main__":
    main()
