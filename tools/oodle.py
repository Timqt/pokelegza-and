#!/usr/bin/env python3
"""Oodle 解压封装（ctypes 调用 RAD oo2core）。

oo2core_2_9_14_win64.dll 取自 Crauzer/OodleSharp 仓库（RAD 官方 Oodle 的 Windows x64 库）。
"""

import ctypes
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DLL_PATH = os.path.join(ROOT, "work", "oodle", "oo2core_2_9_14_win64.dll")

_dll = None


def _load():
    global _dll
    if _dll is None:
        _dll = ctypes.CDLL(DLL_PATH)
        f = _dll.OodleLZ_Decompress
        f.restype = ctypes.c_int
        f.argtypes = [
            ctypes.c_void_p,    # src
            ctypes.c_longlong,  # src_len
            ctypes.c_void_p,    # dst
            ctypes.c_longlong,  # dst_len
            ctypes.c_uint,      # a
            ctypes.c_uint,      # b
            ctypes.c_ulonglong, # c
            ctypes.c_uint,      # d
            ctypes.c_uint,      # e
            ctypes.c_uint,      # f
            ctypes.c_uint,      # g
            ctypes.c_uint,      # h
            ctypes.c_uint,      # i
            ctypes.c_int,       # threadModule
        ]
    return _dll


def decompress(src: bytes, dst_len: int = 0) -> bytes:
    """解压一段 Oodle 数据。dst_len=0 时按 oo2core 的上界公式估。"""
    dll = _load()
    src_buf = ctypes.create_string_buffer(src, len(src))
    if not dst_len:
        # oo2core: bound = srcSize + 272 + ceil(srcSize/0x40000)*0x40000
        dst_len = len(src) + 272 + ((len(src) + 0x3FFFF) // 0x40000) * 0x40000
    dst_buf = ctypes.create_string_buffer(dst_len)
    fn = _dll.OodleLZ_Decompress
    r = fn(src_buf, len(src), dst_buf, dst_len,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 3)
    if r <= 0:
        raise RuntimeError("OodleLZ_Decompress 返回 %d（期望 %d）" % (r, dst_len))
    return dst_buf.raw[:r]


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: python tools\\oodle.py <压缩文件> [输出文件]")
        sys.exit(1)
    data = open(sys.argv[1], "rb").read()
    out = decompress(data)
    if len(sys.argv) > 2:
        open(sys.argv[2], "wb").write(out)
    print("解压成功: %d -> %d 字节, 头: %s" % (len(data), len(out), out[:32]))
