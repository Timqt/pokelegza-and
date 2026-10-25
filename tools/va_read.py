# -*- coding: utf-8 -*-
"""按 SDK 客机的真实段布局读虚拟地址内容。

真实布局（来自 app/native/za_guest_info.h + 实测日志）：
    text    : 0x000000 .. 0x64e230   (text.bin,  0x64e230 字节)
    rodata  : 0x64f000 .. 0xb3b000   (rodata.bin, 0x4ec000 字节)
    data    : 0xb3b000 .. 0xb8f4e0   (data.bin,  0x544e0 字节)
    bss     : 0xb8f4e0 .. 0xc5e000   (无文件)
    ro TLS  : 0xf00000 ..
"""
import sys

BASE = 'work/nso_32848007'
SEGS = [
    ('text.bin', 0x0, 0x64e230, 0x64e230),
    ('rodata.bin', 0x64f000, 0x4ec000, 0x4ec000),
    ('data.bin', 0xb3b000, 0x544e0, 0x544e0),
]


def find_segment(v):
    for name, start, size, flen in SEGS:
        if start <= v < start + size:
            return name, v - start, flen
    return None, None, None


def main():
    v = int(sys.argv[1], 16)
    ln = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x60
    name, off, flen = find_segment(v)
    if not name:
        print('%#x 不在 text/rodata/data（bss / ro-TLS / gate 区，无文件内容）' % v)
        return
    if off >= flen:
        print('%#x -> %s + %#x 超出文件长度 %#x' % (v, name, off, flen))
        return
    blob = open('%s/%s' % (BASE, name), 'rb').read()
    chunk = blob[off:off + ln]
    print('%#x -> %s + %#x' % (v, name, off))
    print('hex  :', chunk.hex())
    print('ascii:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk))
    first = chunk.split(b'\x00')[0]
    if first:
        print('cstr :', repr(first))


if __name__ == '__main__':
    main()
