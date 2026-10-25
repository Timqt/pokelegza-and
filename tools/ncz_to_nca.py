#!/usr/bin/env python3
"""NCZ -> NCA 解码（按 nsz 的 IndependentNczDecompressor 格式）。

用 zstandard + pycryptodome，逐段 AES-128-CTR 复原。
不打印任何密钥材料。
"""
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter
from zstandard import ZstdDecompressor

NCZ = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.ncz")
OUT = NCZ.with_suffix(".nca")

NCA_HEADER_SIZE = 0x4000


def main():
    with open(NCZ, "rb") as f:
        header = f.read(NCA_HEADER_SIZE)
        magic = f.read(8)
        if magic != b"NCZSECTN":
            raise SystemExit("no NCZSECTN")
        count = struct.unpack("<Q", f.read(8))[0]
        sections = []
        for _ in range(count):
            off, size, ctype, _pad = struct.unpack("<QQQQ", f.read(32))
            key = f.read(16)
            ctr = f.read(16)
            sections.append((off, size, ctype, key, ctr))
        pos = f.tell()
        block_magic = f.read(8)
        f.seek(pos)
        if block_magic == b"NCZBLOCK":
            raise SystemExit("NCZBLOCK path not implemented")
        print(f"sections={count} total={sum(s[1] for s in sections)} data@0x{pos+8:X}", flush=True)

        dec = ZstdDecompressor().stream_reader(f)
        with open(OUT, "wb") as out:
            out.write(header)
            written = 0
            for off, size, ctype, key, ctr in sections:
                plain = dec.read(size)
                if len(plain) != size:
                    print(f"  short read at {off}: {len(plain)}/{size}", flush=True)
                if ctype in (3, 4):
                    c = Counter.new(64, prefix=ctr[0:8], initial_value=(off >> 4))
                    aes = AES.new(key, AES.MODE_CTR, counter=c)
                    plain = aes.encrypt(plain)
                out.write(plain)
                written += len(plain)
                if written % (256 * 1024 * 1024) < size:
                    print(f"  {written/2**20:.0f} MiB", flush=True)
    print(f"DONE -> {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
