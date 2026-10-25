#!/usr/bin/env python3
"""dump NSO 的头部、API info 与 runtime module。

NSO 头布局（0x80 字节）：
  0x00 magic "NSO0" / 0x04 version / 0x0C flags
  0x10 3×{u32 file_off, u32 mem_off, u32 size}     段头
  0x40 3×{u32 file_off, u32 size}                   段数据
  0x70 3×u32 compressed_size
  0x7C reserved
API info（0x80..0x180）：
  0x80 u32 runtime_module_offset
  0x84 u32 runtime_module_size
  0x88 u32 runtime_flags
  0x8C u32 sdk_version
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO_DIR = os.path.join(ROOT, "work", "base", "exefs2")


def main():
    for name in ("entry_32848007", "entry_0"):
        p = os.path.join(NSO_DIR, name)
        d = open(p, "rb").read()
        print("=== %s (%d 字节) ===" % (name, len(d)))
        print("  magic=%r version=%#x flags=%#x" % (d[0:4], struct.unpack_from("<I", d, 4)[0],
                                                     struct.unpack_from("<I", d, 0x0C)[0]))
        for i in range(3):
            fo, mo, sz = struct.unpack_from("<III", d, 0x10 + i * 0x10)
            do, ds = struct.unpack_from("<II", d, 0x40 + i * 8)
            cs = struct.unpack_from("<I", d, 0x70 + i * 4)[0]
            print("  段%d: 头(off=%#x mem=%#x size=%#x) 数据(file=%#x size=%#x) 压缩=%#x"
                  % (i, fo, mo, sz, do, ds, cs))
        rm_off, rm_size, rm_flags, sdk_ver = struct.unpack_from("<IIII", d, 0x80)
        print("  API info: runtime_module off=%#x size=%#x flags=%#x sdk_version=%#x"
              % (rm_off, rm_size, rm_flags, sdk_ver))
        # 0x90 起是模块名等
        blob = d[0x90:0x180]
        printable = bytes(c if 32 <= c < 127 else 0x2E for c in blob)
        print("  API info 0x90..0x180: %s" % printable.decode("ascii", "replace"))
        if rm_off and rm_size and rm_off + rm_size <= len(d):
            print("  runtime module 前 128 字节:")
            b = d[rm_off:rm_off + 128]
            print("   ", " ".join("%02x" % c for c in b[:64]))
            print("   ", " ".join("%02x" % c for c in b[64:128]))
            print("  runtime module 可打印: %s" %
                  bytes(c if 32 <= c < 127 else 0x2E for c in b[:256]).decode("ascii", "replace"))
        print()


if __name__ == "__main__":
    main()
