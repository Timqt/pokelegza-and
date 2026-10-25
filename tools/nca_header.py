#!/usr/bin/env python3
"""解 NCA 头拿节表，再取 ExeFS 里的 NSO。

主密钥从 prod.keys 取；NCA 头用 AES-128-CTR 解（标准 crypto => keyarea key = master_key）。
不回显任何密钥值。
"""
import re
import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter

KEYS = Path(r"D:\feiniukexinhome\Code\d2r-and\switch key\prod.keys")
NCA = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.nca")
OUT = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\exefs")
TYPES = {0: "ROMFS", 1: "EXEFS", 2: "INI1", 3: "DATA", 4: "DATA2"}


def masters():
    txt = KEYS.read_text()
    out = {}
    for k, v in re.findall(r"^\s*(\w+)\s*=\s*([0-9a-fA-F]+)\s*$", txt, re.M):
        if k.startswith("master_key_") and len(v) == 32:
            out[k] = bytes.fromhex(v)
    return out


def try_header(data, key, iv):
    c = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    aes = AES.new(key, AES.MODE_CTR, counter=c)
    return aes.encrypt(data)


def main():
    mk = masters()
    print("master keys available:", sorted(mk))
    with open(NCA, "rb") as f:
        head = f.read(0x4000)

    found = None
    for name in sorted(mk):
        for ivname, iv in (("zero", b"\x00" * 16),):
            dec = try_header(head[:0xC00], mk[name], iv)
            if dec[0xC0:0xC4] == b"NCA3":
                found = (name, ivname, dec)
                print(f"decrypted header with {name} / iv={ivname}")
                break
        if found:
            break
    if not found:
        # 再试：把 0x100..0x140（fixed key signature 区）当 IV 的一部分等变体
        for name in sorted(mk):
            for off in (0x100, 0x140, 0x180, 0x1C0):
                iv = head[off:off + 16]
                dec = try_header(head[:0xC00], mk[name], iv)
                if dec[0xC0:0xC4] == b"NCA3":
                    found = (name, f"hdr@{off:#x}", dec)
                    print(f"decrypted header with {name} / iv=header@{off:#x}")
                    break
            if found:
                break
    if not found:
        print("!! 无法用 prod.keys 的 master_key 解出 NCA 头")
        return

    dec = found[2]
    print("header magic:", dec[0xC0:0xC4])
    hdr_size = struct.unpack_from("<I", dec, 0x140)[0]
    print(f"header size field = {hdr_size:#x}")
    st_off = None
    for cand in (0x1C0, 0xC00):
        t = dec[cand:cand + 0x800]
        offs = [struct.unpack_from("<I", t, i * 0x200)[0] for i in range(4)]
        szs = [struct.unpack_from("<I", t, i * 0x200 + 4)[0] for i in range(4)]
        tys = [struct.unpack_from("<I", t, i * 0x200 + 8)[0] for i in range(4)]
        if all(t_ in TYPES for t_ in tys) and all(s < NCA.stat().st_size for s in szs):
            st_off = cand
            print(f"section table @ {cand:#x}")
            for i in range(4):
                print(f"  section {i}: offset={offs[i]:#x} size={szs[i]} type={tys[i]}({TYPES.get(tys[i],'?')})")
            break
    if st_off is None:
        print("!! 找不到可解析的节表")
        return

    t = dec[st_off:st_off + 0x800]
    for i in range(4):
        off, size, stype = struct.unpack_from("<III", t, i * 0x200)
        if stype != 1:
            continue
        print(f"提取 ExeFS 段 @{off:#x} 大小 {size}")
        with open(NCA, "rb") as f:
            f.seek(off)
            blob = f.read(size)
        parse_bktr(blob, OUT)


def parse_bktr(data, outdir):
    print(f"  ExeFS 段 {len(data)} 字节, magic={data[:4]!r}")
    if data[:4] != b"BKTR":
        print("  !! 不是 BKTR")
        return
    version, header_size = struct.unpack_from("<II", data, 4)
    sect_count, sect_off, sect_size, sect_type = struct.unpack_from("<IIII", data, 0x0C)
    file_count, file_ent_off, file_ent_size = struct.unpack_from("<III", data, 0x1C)
    file_name_off, file_name_size, file_data_off = struct.unpack_from("<III", data, 0x28)
    print(f"  BKTR v{version} hdrSize={header_size:#x} sections={sect_count} files={file_count} "
          f"entOff={file_ent_off:#x} entSize={file_ent_size} nameOff={file_name_off:#x} dataOff={file_data_off:#x}")
    outdir.mkdir(parents=True, exist_ok=True)
    for i in range(file_count):
        e = data[file_ent_off + i * file_ent_size: file_ent_off + (i + 1) * file_ent_size]
        foff, fsize, soff, ssize = struct.unpack_from("<IIII", e, 0)
        name = data[file_name_off + soff: file_name_off + soff + ssize].rstrip(b"\0").decode("utf-8", "replace")
        (outdir / name).write_bytes(data[file_data_off + foff: file_data_off + foff + fsize])
        print(f"    {name}  {fsize} 字节")


if __name__ == "__main__":
    main()
