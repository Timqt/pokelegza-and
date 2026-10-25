#!/usr/bin/env python3
"""把 SDK 那 21 个槽的值逐个"认脸"：文本槽反汇编，数据槽转储内容。"""
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
GOT0 = 0xB73898
NSLOT = 21
TEXT = (0x0, 0x64E230)
RODATA = (0x64F000, 0x4EC000)
DATA = (0xB3B000, 0x544E0)


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
    ehsize, phentsize, shentsize = 64, 56, 64
    phoff = ehsize
    dataoff = (phoff + phentsize + 15) & ~15
    shstr_off = dataoff + len(text)
    shoff = (shstr_off + len(shstr) + 15) & ~15
    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    e += struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, vaddr, phoff, shoff, 0,
                     ehsize, phentsize, 56, shentsize, 3, 2)
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
    for lo, sz in (TEXT, RODATA, DATA):
        if lo <= addr < lo + sz:
            piece = bytes(IMG[addr:addr + length])
            break
    else:
        return "(不在任何段)"
    elf = wrap_elf(piece, addr)
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(elf)
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    lines = []
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("Disassembly") or s.startswith("/") or "ELF" in s:
            continue
        if s.startswith("<"):
            continue
        lines.append(s)
    return lines


def main():
    IMG = load()
    vals = []
    for i in range(NSLOT):
        off = GOT0 + i * 8
        vals.append(struct.unpack_from("<Q", bytes(IMG[off:off + 8]), 0)[0])

    # 参数顺序：x0..x7 = 槽10,11,12,13,14,15,17,18；栈 = 槽20,19,9,16,8,7,6,5,4,3,2,1,0
    argmap = [10, 11, 12, 13, 14, 15, 17, 18, 20, 19, 9, 16, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    print("=== 参数 ↔ 槽 对应 ===")
    for ai, si in enumerate(argmap):
        v = vals[si]
        print("  arg%-2d = 槽%-2d = %#018x%s" % (ai, si, v, "   <== NULL" if v == 0 else ""))

    print("\n=== 非零槽的内容 ===")
    seen = set()
    for i, v in enumerate(vals):
        if v == 0 or v in seen:
            continue
        seen.add(v)
        print("\n--- 槽%d -> %#x ---" % (i, v))
        if TEXT[0] <= v < TEXT[1]:
            for l in disasm(IMG, v, 0x40):
                print("   " + l)
        elif RODATA[0] <= v < RODATA[1]:
            b = bytes(IMG[v:v + 64])
            print("   rodata: %s" % " ".join("%02x" % c for c in b[:48]))
            print("   ascii: %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in b[:48]))
        elif DATA[0] <= v < DATA[1]:
            b = bytes(IMG[v:v + 64])
            print("   data  : %s" % " ".join("%02x" % c for c in b[:48]))
            print("   ascii: %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in b[:48]))
            print("   qword : %s" % " ".join("%#x" % struct.unpack_from("<Q", b, j)[0] for j in range(0, 48, 8)))
        else:
            print("   (小整数/其它: %d)" % v)

    # 数据槽附近的其它内容
    print("\n=== 0xb73630 附近 ===")
    for off in range(0xb73600, 0xb73660, 8):
        q = struct.unpack_from("<Q", bytes(IMG[off:off + 8]), 0)[0]
        print("  %#x = %#018x" % (off, q))
    print("\n=== 0xb868c0 附近 ===")
    for off in range(0xb868a0, 0xb868f0, 8):
        q = struct.unpack_from("<Q", bytes(IMG[off:off + 8]), 0)[0]
        print("  %#x = %#018x" % (off, q))


if __name__ == "__main__":
    main()
