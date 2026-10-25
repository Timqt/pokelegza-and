#!/usr/bin/env python3
"""用 llvm-objdump 反汇编整个 Z-A SDK/main text，统计：
   mrs cntpct / cntvct / tpidr_el0 / tpidrro_el0，以及 x18 的读写。
（d2r 的 patch_nso.py 用的就是同一类统计；d2r 记录 SDK 里有 33 处 mrs cntpct。）
"""
import os, re, subprocess, sys, tempfile

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and"
OBJDUMP = os.path.join(ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
                       "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objdump.exe")


def wrap_elf(text, vaddr):
    import struct
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


def scan(path, name):
    blob = open(path, "rb").read()
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(wrap_elf(blob, 0))
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    c = {"cntpct": 0, "cntvct": 0, "tpidr_el0": 0, "tpidrro_el0": 0,
         "svc": 0, "x18_rd": 0, "x18_rn": 0}
    samples = []
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(.*)$", line)
        if not m:
            continue
        off, ins = int(m.group(1), 16), m.group(2).strip()
        IL = ins.lower()          # llvm-objdump 打印系统寄存器名是**大写**（TPIDRRO_EL0）
        if IL.startswith("mrs"):
            for k, ck in (("cntpct_el0", "cntpct"), ("cntvct_el0", "cntvct"),
                          ("tpidrro_el0", "tpidrro_el0"), ("tpidr_el0", "tpidr_el0")):
                if k in IL:
                    c[ck] += 1
                    if len(samples) < 12 and ck in ("cntpct", "cntvct"):
                        samples.append("%#x %s" % (off, ins))
        elif IL.startswith("msr"):
            for k, ck in (("cntpct_el0", "cntpct"), ("cntvct_el0", "cntvct"),
                          ("tpidrro_el0", "tpidrro_el0"), ("tpidr_el0", "tpidr_el0")):
                if k in IL:
                    c[ck] += 1
        elif IL.startswith("svc"):
            c["svc"] += 1
        # x18 作为数据寄存器
        if not ins.startswith(("b.", "b ", "cbz", "cbnz", "tbz", "tbnz")):
            ops = ins.split("\t")
            if len(ops) >= 2:
                o = ops[-1]
                if re.search(r"\b(x18|w18)\b", o):
                    c["x18_rd"] += 1
                if re.search(r"\[(x18|w18)", o):
                    c["x18_rn"] += 1
    print("%-6s %s" % (name, c))
    for s in samples:
        print("        ", s)


scan(os.path.join(ROOT, "work", "nso_32848007", "text.bin"), "SDK")
p = os.path.join(ROOT, "work", "nso", "text.bin")
if os.path.exists(p):
    scan(p, "main")
