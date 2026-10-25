#!/usr/bin/env python3
"""把 NSO 的一个段包成最小 ELF64，然后交给 llvm-objdump 反汇编。

为什么需要它：llvm-objdump 不吃裸二进制（GNU objdump 的 -b binary 它没有），
所以现场造一个「只有 1 个 PT_LOAD + 1 个 .text 节」的 ELF 出来。

用法：
    python tools/nso_disasm.py sdk 0x400 0x100
    python tools/nso_disasm.py main 0x19E8950 0x80

段名：sdk = entry_32848007，main = entry_0
"""
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NDK = os.path.join(ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c")
OBJDUMP = os.path.join(NDK, "toolchains", "llvm", "prebuilt", "windows-x86_64",
                       "bin", "llvm-objdump.exe")

SEGMENTS = {
    "sdk": ("entry_32848007", [(0x0, "text"), (0x64F000, "rodata"), (0xB3B000, "data")]),
    "main": ("entry_0", None),
}


def load_nso(path):
    import lz4.block
    d = open(path, "rb").read()
    flags = struct.unpack_from("<I", d, 0x0C)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x16 if False else 0x10 + i * 0x10)
            for i in range(3)]
    csz = struct.unpack_from("<III", d, 0x60)
    out = []
    for i, (fo, mo, sz) in enumerate(segs):
        raw = d[fo:fo + csz[i]]
        if flags >> i & 1:
            raw = lz4.block.decompress(raw, uncompressed_size=sz)
        out.append((mo, sz, raw))
    return out


def wrap_elf(text, vaddr):
    """把一段代码包成 ELF64 LE aarch64，.text 节在 vaddr。"""
    shstr = b"\0.shstrtab\0.text\0"
    ehsize, phentsize, shentsize = 64, 56, 64
    phoff = ehsize
    dataoff = phoff + phentsize
    # 让 .text 的文件偏移 = dataoff（对齐 16）
    dataoff = (dataoff + 15) & ~15
    shstr_off = dataoff + len(text)
    shoff = (shstr_off + len(shstr) + 15) & ~15

    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    e += struct.pack("<HHIQQQIHHHHHH",
                     2,          # e_type = ET_EXEC
                     0xB7,       # e_machine = EM_AARCH64
                     1,          # e_version
                     vaddr,      # e_entry
                     phoff, shoff,
                     0,          # e_flags
                     ehsize, phentsize, 56, shentsize, 3, 2)
    # program header
    e += struct.pack("<IIQQQQQQ", 1, 5, dataoff, vaddr, vaddr, len(text), len(text), 0x1000)
    # .shstrtab
    e += b"\0" * (dataoff - len(e))
    e += text
    e += shstr
    e += b"\0" * (shoff - len(e))
    # section headers: [0]=NULL, [1]=.text, [2]=.shstrtab
    e += bytes(64)
    e += struct.pack("<IIQQQQIIQQ", 1, 1, 6, vaddr, dataoff, len(text), 0, 0, 8, 0)
    e += struct.pack("<IIQQQQIIQQ", 2, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(e)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    which = sys.argv[1]
    addr = int(sys.argv[2], 0)
    length = int(sys.argv[3], 0)

    nso_name, _ = SEGMENTS[which]
    path = os.path.join(ROOT, "work", "base", "exefs2", nso_name)
    segs = load_nso(path)
    text_off, text_sz, text = segs[0]

    # 取包含目标地址的段
    blob = None
    for mo, sz, raw in segs:
        if mo <= addr < mo + sz:
            blob = raw
            vaddr = mo
            break
    if blob is None:
        print("地址 %#x 不在任何段里" % addr)
        return 1

    lo = addr - vaddr
    piece = blob[lo:lo + length]
    # 让 objdump 打印的地址跟映像偏移一致：用「段起始 vaddr」当 .text 的 vaddr，
    # 但我们的 piece 从 lo 开始 ⇒ 改用「以 addr 为新基址」再手工标注原始偏移。
    elf = wrap_elf(piece, addr)
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(elf)
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        out = r.stdout
    finally:
        os.unlink(tmp)

    print("=== %s @%#x  (%d 字节) ===" % (which, addr, length))
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("Disassembly") or s.startswith("/") or "ELF" in s:
            continue
        if ":" in s and s.split(":")[0].strip().startswith(("0", "1", "2", "3", "4", "5",
                                                            "6", "7", "8", "9", "a", "b",
                                                            "c", "d", "e", "f")):
            print(s)
        elif s.startswith("<"):
            print(s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
