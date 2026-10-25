#!/usr/bin/env python3
"""校验重建的 NCA，并自己解析节表 + Bekkō(BKTR) 取出 ExeFS 里的 NSO。"""
import hashlib
import struct
import sys
from pathlib import Path

NCA = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.nca")
EXE = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\exefs")
TYPES = {0: "ROMFS", 1: "EXEFS", 2: "INI1", 3: "DATA", 4: "DATA2"}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(8 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def main():
    digest = sha256(NCA)
    print(f"NCA sha256 = {digest}")
    print(f"expected   = 4a70b3ff963bfe412681185cea68bf55")
    print("MATCH" if digest.startswith("4a70b3ff963bfe412681185cea68bf55") else "*** MISMATCH ***")

    with open(NCA, "rb") as f:
        f.seek(0xC00)
        table = f.read(0x800)
        print("--- section table ---")
        for i in range(4):
            e = table[i * 0x200:(i + 1) * 0x200]
            off, size, stype = struct.unpack_from("<III", e, 0)
            crypto = struct.unpack_from("<I", e, 0x28)[0]
            print(f"  section {i}: offset=0x{off:X} size={size} type={stype}({TYPES.get(stype,'?')}) crypto={crypto}")
            if stype == 1:
                f.seek(off)
                data = f.read(size)
                parse_bktr(data, EXE)


def parse_bktr(data, outdir):
    print(f"  ExeFS section: {len(data)} bytes, magic={data[:4]!r}")
    if data[:4] != b"BKTR":
        print("  !! not BKTR")
        return
    version, header_size = struct.unpack_from("<II", data, 4)
    sect_count, sect_off, sect_size, sect_type = struct.unpack_from("<IIII", data, 0x0C)
    file_count, file_ent_off, file_ent_size = struct.unpack_from("<III", data, 0x1C)
    file_name_off, file_name_size, file_data_off = struct.unpack_from("<III", data, 0x28)
    print(f"  BKTR v{version} hdrSize=0x{header_size:X} sections={sect_count} "
          f"files={file_count} entOff=0x{file_ent_off:X} entSize={file_ent_size} "
          f"nameOff=0x{file_name_off:X} dataOff=0x{file_data_off:X}")
    outdir.mkdir(parents=True, exist_ok=True)
    for i in range(file_count):
        e = data[file_ent_off + i * file_ent_size: file_ent_off + (i + 1) * file_ent_size]
        foff, fsize, soff, ssize = struct.unpack_from("<IIII", e, 0)
        name = data[file_name_off + soff: file_name_off + soff + ssize].rstrip(b"\0").decode("utf-8", "replace")
        blob = data[file_data_off + foff: file_data_off + foff + fsize]
        p = outdir / name
        p.write_bytes(blob)
        print(f"    {name}  {fsize} 字节")


if __name__ == "__main__":
    main()
