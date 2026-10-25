#!/usr/bin/env python3
""" dump NSO 的 ELF 程序头 —— 重点是 PT_TLS（客机 TLS 的初始镜像）。"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO_DIR = os.path.join(ROOT, "work", "base", "exefs2")

PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB",
      6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
      0x6474e552: "GNU_RELRO", 0x70000001: "ARM_EXIDX"}


def main():
    for name in ("entry_32848007", "entry_0"):
        path = os.path.join(NSO_DIR, name)
        d = open(path, "rb").read()
        # NSO 头之后还有 API info 等，ELF 头要自己找
        eh = d.find(b"\x7fELF")
        assert eh > 0 and d[0:4] == b"NSO0", (eh, d[0:4])
        phoff = struct.unpack_from("<Q", d, eh + 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", d, eh + 0x36)
        print("=== %s  (ELF@%#x phoff=%#x phnum=%d) ===" % (name, eh, phoff, phnum))
        for i in range(phnum):
            o = phoff + i * phentsize
            p_type, p_flags = struct.unpack_from("<II", d, o)
            p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", d, o + 8)
            tn = PT.get(p_type, hex(p_type))
            print("  [%2d] %-12s flags=%d off=%#012x vaddr=%#012x filesz=%#x memsz=%#x align=%#x"
                  % (i, tn, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align))
            if p_type == 7:
                print("       ⇒ PT_TLS：初始化镜像 vaddr=%#x 大小=%#x（+ %d 字节零填充），对齐=%#x"
                      % (p_vaddr, p_filesz, p_memsz - p_filesz, p_align))
        print()


if __name__ == "__main__":
    main()
