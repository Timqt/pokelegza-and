#!/usr/bin/env python3
"""看 NSO 的 embedded 段（文件 0xA18468/0x3C0）与 .data 开头，找导入桩/GOT 的落点。"""
import os, struct, sys
import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_0")
BASE = 0x140000000

d = open(NSO, "rb").read()
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
segd = []
for i, (fo, mo, sz) in enumerate(segs):
    raw = d[fo:fo + csz[i]]
    if flags >> i & 1:
        raw = lz4.block.decompress(raw, uncompressed_size=sz)
    segd.append((mo, sz, raw))
(tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = segd

def hd(b, base, n=0x100):
    out = []
    for i in range(0, min(n, len(b)), 16):
        c = b[i:i + 16]
        out.append("%08x  %-*s |%s|" % (base + i, 48, " ".join("%02x" % x for x in c),
                    "".join(chr(x) if 32 <= x < 127 else "." for x in c)))
    return "\n".join(out)

emb_off, emb_sz = struct.unpack_from("<II", d, 0x88)
print("=== embedded 段：文件 %#x +%#x ===" % (emb_off, emb_sz))
print(hd(d[emb_off:emb_off + emb_sz], emb_off, 0x200))

print("\n=== .data 段开头（映像内 %#x）===" % dmo)
print(hd(data, dmo, 0x180))

print("\n=== .rodata 段开头（映像内 %#x）===" % rmo)
print(hd(rodata, rmo, 0x100))
