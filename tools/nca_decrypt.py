#!/usr/bin/env python3
"""按 nsz 的密钥派生链算 key area key，解 NCA 头 -> 节表 -> ExeFS 里的 NSO。"""
import re
import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter

KEYS = Path(r"D:\feiniukexinhome\Code\d2r-and\switch key\prod.keys")
NCA = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\4a70b3ff963bfe412681185cea68bf55.nca")
OUT = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\exefs")
TYPES = {0: "ROMFS", 1: "EXEFS", 2: "INI1", 3: "DATA", 4: "DATA2"}


def ecb_dec(key, data):
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def load_keys():
    txt = KEYS.read_text()
    d = {}
    for k, v in re.findall(r"^\s*(\w+)\s*=\s*([0-9a-fA-F]+)\s*$", txt, re.M):
        d[k] = v
    return d


def generate_kek(src, master_key, kek_seed, key_seed):
    kek = ecb_dec(master_key, kek_seed)
    src_kek = ecb_dec(kek, src)
    return ecb_dec(src_kek, key_seed)


def main():
    k = load_keys()
    need = ["aes_kek_generation_source", "aes_key_generation_source", "titlekek_source",
            "key_area_key_application_source"]
    for n in need:
        print(f"  {n}: {'有' if n in k else '**缺**'}")
    for extra in ("key_area_key_ocean_source", "key_area_key_system_source"):
        if extra not in k:
            print(f"  {extra}: **缺**（不影响 application key area）")

    master_index = 17  # keyGeneration 18 -> master key revision 0x11
    master = bytes.fromhex(k[f"master_key_{master_index:02x}"])
    kek_seed = bytes.fromhex(k["aes_kek_generation_source"])
    key_seed = bytes.fromhex(k["aes_key_generation_source"])
    app_src = bytes.fromhex(k["key_area_key_application_source"])
    kak = generate_kek(app_src, master, kek_seed, key_seed)
    titlekek = ecb_dec(master, bytes.fromhex(k["titlekek_source"]))

    # 票据里的加密 title key -> 解密
    tik = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\ncas\0100f43008c448000000000000000012.tik")
    raw = tik.read_bytes()
    import struct as st
    sig = st.unpack_from("<I", raw)[0]
    lengths = {0x10000: 0x200, 0x10001: 0x100, 0x10002: 0x3C, 0x10003: 0x200, 0x10004: 0x100, 0x10005: 0x3C}
    base = (4 + lengths[sig] + 0x3F) & ~0x3F
    enc_titlekey = raw[base + 0x40: base + 0x50]
    titlekey = ecb_dec(titlekek, enc_titlekey)
    print(f"  票据签名 {sig:#x}; titlekek 解出长度 {len(titlekek)}; titlekey 已解")

    with open(NCA, "rb") as f:
        head = f.read(0x4000)

    def ctr(key, iv):
        c = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(key, AES.MODE_CTR, counter=c).encrypt

    cands = {
        "kak/zero": (kak, b"\x00" * 16),
        "kak^tk/zero": (bytes(a ^ b for a, b in zip(kak, titlekey)), b"\x00" * 16),
        "master/zero": (master, b"\x00" * 16),
        "master^tk/zero": (bytes(a ^ b for a, b in zip(master, titlekey)), b"\x00" * 16),
        "tk/zero": (titlekey, b"\x00" * 16),
    }
    dec = None
    for name, (k_, iv) in cands.items():
        out = ctr(k_, iv)(head)
        if out[0xC0:0xC4] == b"NCA3":
            print(f"  >>> 命中: {name}")
            dec = out
            break
        # 也试 64 位计数器、8 字节前缀
    if dec is None:
        # 64-bit counter with 8-byte prefix variants
        for name, (k_, iv) in cands.items():
            for pref in range(4):
                c = Counter.new(64, prefix=iv[:8], initial_value=0)
                out = AES.new(k_, AES.MODE_CTR, counter=c).encrypt(head)
                if out[0xC0:0xC4] == b"NCA3":
                    print(f"  >>> 命中: {name} / 64bit prefix")
                    dec = out
                    break
            if dec:
                break
    if dec is None:
        print("!! 仍未解出 NCA 头")
        return

    hdr_size = struct.unpack_from("<I", dec, 0x140)[0]
    print(f"  header size field = {hdr_size:#x}")
    for cand in (0x1C0, 0xC00):
        t = dec[cand:cand + 0x800]
        tys = [struct.unpack_from("<I", t, i * 0x200 + 8)[0] for i in range(4)]
        if all(x in TYPES for x in tys):
            print(f"  节表 @ {cand:#x}")
            for i in range(4):
                off, size, st_ = struct.unpack_from("<III", t, i * 0x200)
                print(f"    section {i}: offset={off:#x} size={size} type={st_}({TYPES.get(st_)})")
            for i in range(4):
                off, size, st_ = struct.unpack_from("<III", t, i * 0x200)
                if st_ == 1:
                    with open(NCA, "rb") as f:
                        f.seek(off)
                        blob = f.read(size)
                    parse_bktr(blob, OUT)
            return
    print("!! 节表未找到")


def parse_bktr(data, outdir):
    print(f"  ExeFS 段 {len(data)} 字节, magic={data[:4]!r}")
    if data[:4] != b"BKTR":
        print("  !! 不是 BKTR")
        return
    version, header_size = struct.unpack_from("<II", data, 4)
    file_count, file_ent_off, file_ent_size = struct.unpack_from("<III", data, 0x1C)
    file_name_off, file_name_size, file_data_off = struct.unpack_from("<III", data, 0x28)
    print(f"  BKTR v{version} files={file_count} entOff={file_ent_off:#x} nameOff={file_name_off:#x} dataOff={file_data_off:#x}")
    outdir.mkdir(parents=True, exist_ok=True)
    for i in range(file_count):
        e = data[file_ent_off + i * file_ent_size: file_ent_off + (i + 1) * file_ent_size]
        foff, fsize, soff, ssize = struct.unpack_from("<IIII", e, 0)
        name = data[file_name_off + soff: file_name_off + soff + ssize].rstrip(b"\0").decode("utf-8", "replace")
        (outdir / name).write_bytes(data[file_data_off + foff: file_data_off + foff + fsize])
        print(f"    {name}  {fsize} 字节")


if __name__ == "__main__":
    main()
