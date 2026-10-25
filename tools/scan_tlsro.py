#!/usr/bin/env python3
"""扫 SDK / main 映像里所有 `mrs Xt, TPIDRRO_EL0`（以及 TPIDR_EL0）并给出后续访问的偏移。

为什么要处理 TPIDRRO_EL0：
  客机里有一处 `mrs x8, TPIDRRO_EL0 ; ldr x8,[x8,#0x1f8]` 直接读只读 TLS 寄存器。
  安卓/bionic **从不设置 TPIDRRO_EL0**（它一直是 0）⇒ 读到空指针 ⇒ pc 崩。
  之前只改写了 TPIDR_EL0 的 617 个 helper，漏了这一路。
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO_DIR = os.path.join(ROOT, "work", "base", "exefs2")
MRS_TPIDR = 0xD53BD040
MRS_TPIDRRO = 0xD53BD060


def load(name):
    d = open(os.path.join(NSO_DIR, name), "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    out = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        out.append((mo, sz, raw))
    (tmo, tsz, text), (rmo, rsz, rodata), (dmo, dsz, data) = out
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    IMG = bytearray(dmo + dsz + bss)
    for mo, sz, raw in out:
        IMG[mo:mo + sz] = raw
    return IMG


def ldr_imm(w):
    """LDR (unsigned imm) 的字节偏移；不是 LDR 则返回 None。"""
    if (w & 0x3B000000) != 0x39000000:
        return None
    size = (w >> 30) & 3
    return ((w >> 10) & 0xFFF) << size


def scan(name, nso):
    IMG = load(nso)
    text_end = 0x64E230 if nso == "entry_32848007" else 0x2FC7250
    counts = {}
    hits = []
    for off in range(0, min(text_end, len(IMG) - 8), 4):
        w = struct.unpack_from("<I", bytes(IMG[off:off + 4]), 0)[0]
        if (w & 0xFFFFFFE0) != MRS_TPIDRRO:
            continue
        rt = w & 31
        nxt = struct.unpack_from("<I", bytes(IMG[off + 4:off + 8]), 0)[0]
        offv = ldr_imm(nxt)
        rn = (nxt >> 5) & 31
        hits.append((off, rt, offv, rn))
        counts[offv] = counts.get(offv, 0) + 1
    print("=== %s (%s) ===" % (nso, name))
    print("  `mrs Xt,TPIDRRO_EL0` 共 %d 处" % len(hits))
    for k in sorted(counts, key=lambda x: (x is None, x)):
        print("    后续 LDR 偏移 %s : %d 处" % ("None" if k is None else hex(k), counts[k]))
    for off, rt, offv, rn in hits[:40]:
        tag = "OK(读的是自己)" if rn == rt else "读别的寄存器!"
        print("    @%#x  x%d  后续 ldr [x%d,#%s]  %s" %
              (off, rt, rn, "?" if offv is None else hex(offv), tag))
    if len(hits) > 40:
        print("    ... 共 %d 处" % len(hits))
    return hits


def main():
    scan("SDK", "entry_32848007")
    print()
    scan("main", "entry_0")


if __name__ == "__main__":
    main()
