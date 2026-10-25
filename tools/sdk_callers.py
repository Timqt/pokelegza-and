#!/usr/bin/env python3
"""在 SDK text 里找调用某个偏移的所有 `bl` 调用点，并把调用点前后反汇编出来。

用法：python tools/sdk_callers.py 0x146040
"""
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import lz4.block

NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
OBJDUMP = os.path.join(ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
                       "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objdump.exe")
TEXT_SZ = 0x64E230


def load():
    d = open(NSO, "rb").read()
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


def wrap_elf(text, vaddr):
    shstr = b"\0.shstrtab\0.text\0"
    ehsize, phentsize = 64, 56
    phoff = ehsize
    dataoff = (phoff + phentsize + 15) & ~15
    shstr_off = dataoff + len(text)
    shoff = (shstr_off + len(shstr) + 15) & ~15
    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    e += struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, vaddr, phoff, shoff, 0,
                     ehsize, phentsize, 56, 64, 3, 2)
    e += struct.pack("<IIQQQQQQ", 1, 5, dataoff, vaddr, vaddr, len(text), len(text), 0x1000)
    e += b"\0" * (dataoff - len(e))
    e += text
    e += shstr
    e += b"\0" * (shoff - len(e))
    e += bytes(64)
    e += struct.pack("<IIQQQQIIQQ", 1, 1, 6, vaddr, dataoff, len(text), 0, 0, 8, 0)
    e += struct.pack("<IIQQQQIIQQ", 2, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(e)


def disasm(IMG, addr, length):
    piece = bytes(IMG[addr:addr + length])
    elf = wrap_elf(piece, addr)
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(elf)
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    out = []
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("Disassembly") or s.startswith("/") or "ELF" in s or s.startswith("<"):
            continue
        out.append(s)
    return out


def main():
    target = int(sys.argv[1], 0)
    IMG = load()
    hits = []
    for off in range(0, TEXT_SZ, 4):
        w = struct.unpack_from("<I", bytes(IMG[off:off + 4]), 0)[0]
        if (w & 0xFC000000) == 0x94000000:          # BL
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            if off + (imm << 2) == target:
                hits.append(off)
        elif (w & 0xFC000000) == 0x14000000:        # B（尾调用）
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            if off + (imm << 2) == target:
                hits.append(off)
    print("调用 %s 的位置: %s" % (hex(target), ", ".join(hex(h) for h in hits) or "无"))
    for h in hits:
        print("\n=== 调用点 @%#x ===" % h)
        for l in disasm(IMG, max(0, h - 0x30), 0x60):
            print("   " + l)


if __name__ == "__main__":
    main()
