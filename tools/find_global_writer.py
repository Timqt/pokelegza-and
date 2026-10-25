# -*- coding: utf-8 -*-
"""找 SDK 里对某个全局变量（模块内偏移）的写入点。

在每条 `adrp xD, <目标页>` 之后模拟一小段寄存器跟踪，
识别 `add xM,xD,#off` + `str [xM]` / `str [xD,#off]` / `stp [xM]` 两种写法。

用法:
    python tools/find_global_writer.py 0xbac9f0
"""
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
OBJDUMP = os.path.join(
    ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
    "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objdump.exe")

t = open(TEXT, "rb").read()
n = len(t) // 4
w = struct.unpack_from("<%dI" % n, t, 0)

target = int(sys.argv[1], 0)
page = target & ~0xFFF
off = target & 0xFFF
print("target %#x  page %#x  off %#x" % (target, page, off))


def adrp_target(pc, word):
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


hits = []
for i in range(n):
    wi = w[i]
    if (wi & 0x9F000000) != 0x90000000:
        continue
    if adrp_target(i * 4, wi) != page:
        continue
    base = wi & 0x1F
    # regs[reg] = 该寄存器当前指向的地址（只跟踪从 adrp 派生的）
    regs = {base: page}
    for k in range(1, 40):
        j = i + k
        if j >= n:
            break
        ww = w[j]
        # ADD (immediate) 64/32 位：add xD, xN, #imm
        if (ww & 0xFF800000) == 0x91000000 or (ww & 0xFF800000) == 0x11000000:
            rd = ww & 0x1F
            rn = (ww >> 5) & 0x1F
            imm = (ww >> 10) & 0xFFF
            if rn in regs:
                regs[rd] = regs[rn] + imm
            else:
                regs.pop(rd, None)
            continue
        # MOV (register) 64 位
        if (ww & 0xFF800000) == 0xAA000000:
            rd = ww & 0x1F
            rm = (ww >> 16) & 0x1F
            if rm in regs:
                regs[rd] = regs[rm]
            else:
                regs.pop(rd, None)
            continue
        # STR (immediate, unsigned offset) / STRB
        if (ww & 0xFFC00000) == 0xF9000000 or (ww & 0xFFC00000) == 0x39000000:
            rn = (ww >> 5) & 0x1F
            imm = (ww >> 10) & 0xFFF
            if rn in regs and regs[rn] + imm == target:
                hits.append((i * 4, j * 4))
        # STP (immediate) 64 位：stp xA, xB, [xN, #imm]
        if (ww & 0xFFC00000) == 0xA9000000:
            rn = (ww >> 5) & 0x1F
            imm = (ww >> 15) & 0x7FFF
            if imm & 0x8000:
                imm -= 0x10000
            if rn in regs and regs[rn] + imm == target:
                hits.append((i * 4, j * 4))
        # STR (immediate, pre/post-index) 变体
        if (ww & 0xFFC00000) == 0xF8000000 or (ww & 0xFFC00000) == 0xB8000000:
            rn = (ww >> 5) & 0x1F
            imm = (ww >> 12) & 0x1FF
            if (ww >> 21) & 1:      # imm9
                imm = (ww >> 12) & 0x1FF
                if imm & 0x100:
                    imm -= 0x200
            else:
                imm = ((ww >> 10) & 0xFFF)
            if rn in regs and regs[rn] + imm == target:
                hits.append((i * 4, j * 4))

uniq = sorted(set(hits))
print("命中 %d 处" % len(uniq))


def wrap_elf(text, vaddr):
    shstr = b"\0.shstrtab\0.text\0"
    ehsize, phentsize = 64, 56
    phoff = ehsize
    dataoff = (phoff + phentsize + 15) & ~15
    shstr_off = dataoff + len(text)
    shoff = (shstr_off + len(shstr) + 15) & ~15
    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    e += struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, 0x140000000, phoff, shoff, 0,
                     ehsize, phentsize, 56, 64, 3, 2)
    e += struct.pack("<IIQQQQQQ", 1, 5, dataoff, 0x140000000, 0x140000000,
                     len(text), len(text), 0x1000)
    e += b"\0" * (dataoff - len(e))
    e += text
    e += shstr
    e += b"\0" * (shoff - len(e))
    e += bytes(64)
    e += struct.pack("<IIQQQQIIQQ", 1, 1, 6, shstr_off, dataoff, len(text), 0, 0, 8, 0)
    e += struct.pack("<IIQQQQIIQQ", 2, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(e)


for adrp_at, store_at in uniq:
    lo = max(0, adrp_at - 0x10)
    hi = min(len(t), store_at + 0x10)
    chunk = t[lo:hi]
    elf = wrap_elf(chunk, lo)
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(elf)
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    print("\n=== 写 %s @ text+%#x（adrp @%#x）===" % (hex(target), store_at, adrp_at))
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("Disassembly") or s.startswith("/") or "ELF" in s or s.startswith("<"):
            continue
        print("   " + s)
