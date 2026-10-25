#!/usr/bin/env python3
"""在给定的裸 text 里找所有 `bl <目标>` 的调用点（并顺带打印调用点前后的机器码）。

用法:
    python tools/find_bl.py <text.bin> <目标地址> [上下文指令数]
例:
    python tools/find_bl.py work/nso_32848007/text.bin 0x145d54
"""
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(
    ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
    "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objdump.exe")


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


def disasm(blob, off, size):
    chunk = blob[off:off + size]
    if not chunk:
        return []
    elf = wrap_elf(chunk, off)
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
    path = sys.argv[1]
    target = int(sys.argv[2], 0)
    ctx = int(sys.argv[3], 0) if len(sys.argv) > 3 else 24
    blob = open(path, "rb").read()
    n = len(blob) // 4
    words = struct.unpack_from("<%dI" % n, blob, 0)
    hits = []
    for i in range(n):
        w = words[i]
        if (w & 0xFC000000) == 0x94000000:          # BL imm26
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            dst = (i * 4) + (imm << 2)
            if dst == target:
                hits.append(i * 4)
    print("目标 %#x 的调用点：%d 处" % (target, len(hits)))
    for h in hits:
        print("  调用点 %#x" % h)
        for line in disasm(blob, max(0, h - ctx * 4), ctx * 4 + 8):
            print("    " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
