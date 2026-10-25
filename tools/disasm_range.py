#!/usr/bin/env python3
"""反汇编一段字节范围（裸 aarch64，包成临时 ELF 后交给 llvm-objdump）。

用法:
    python tools/disasm_range.py <文件> <起始偏移> [字节数]

例:
    python tools/disasm_range.py work/nso_32848007/text.bin 0x145a00 0x120
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


def main():
    path = sys.argv[1]
    off = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x100
    blob = open(path, "rb").read()
    chunk = blob[off:off + size]
    if not chunk:
        print("范围超出文件", file=sys.stderr)
        return 1
    elf = wrap_elf(chunk, off)
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(elf)
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("Disassembly") or s.startswith("/") or "ELF" in s or s.startswith("<"):
            continue
        print(s)
    if r.stderr.strip():
        print(r.stderr.strip(), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
