#!/usr/bin/env python3
"""读 NCZ 的明文节表并定位压缩块布局（NCA 头是加密的，节表在 0xC00 之后是明文）。"""
import struct
import sys
from pathlib import Path

NCZ = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.ncz")
TYPES = {0: "ROMFS", 1: "EXEFS", 2: "INI1", 3: "DATA", 4: "DATA2"}


def dump(path):
    with open(path, "rb") as f:
        head = f.read(0x4000)
        print(f"file size = {path.stat().st_size} (0x{path.stat().st_size:X})")
        print("--- section table @0xC00 (plaintext) ---")
        for i in range(4):
            e = head[0xC00 + i * 0x200: 0xC00 + (i + 1) * 0x200]
            off, size, stype = struct.unpack_from("<III", e, 0)
            crypto = struct.unpack_from("<I", e, 0x28)[0]
            hash_type = struct.unpack_from("<H", e, 0x2C)[0]
            print(f"  section {i}: offset=0x{off:X} ({off})  size={size} (0x{size:X})"
                  f"  type={stype}({TYPES.get(stype,'?')})  crypto={crypto} hashType={hash_type}")
        print("--- bytes 0x1400..0x1600 ---")
        for off in range(0x1400, 0x1600, 0x20):
            row = head[off:off + 0x20]
            hx = " ".join(f"{b:02x}" for b in row)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            print(f"  {off:06x}  {hx}  |{asc}|")
        print("--- bytes 0x3F80..0x4100 (NCZ 头尾 -> 数据起点) ---")
        f.seek(0x3F80)
        buf = f.read(0x180)
        for off in range(0, len(buf), 0x20):
            row = buf[off:off + 0x20]
            hx = " ".join(f"{b:02x}" for b in row)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            print(f"  {0x3F80+off:06x}  {hx}  |{asc}|")


if __name__ == "__main__":
    dump(NCZ)
